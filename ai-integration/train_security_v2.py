
import json
import joblib
import pandas as pd
import numpy as np

from pathlib import Path

from sklearn.model_selection import GroupShuffleSplit
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import (
    OneHotEncoder,
    StandardScaler,
    LabelEncoder
)
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)

from sklearn.utils.class_weight import compute_sample_weight

from sklearn.ensemble import (
    RandomForestClassifier,
    GradientBoostingClassifier
)
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression

from xgboost import XGBClassifier


# =====================================================
# 1. CONFIGURATION
# =====================================================

SEED = 42

DATA_FILE = Path("datasets/security_events.csv")
MODEL_DIR = Path("models/security_v2")
RESULT_DIR = Path("results/security_v2")

MODEL_DIR.mkdir(parents=True, exist_ok=True)
RESULT_DIR.mkdir(parents=True, exist_ok=True)


# =====================================================
# 2. FEATURE DEFINITIONS
# =====================================================

NUMERIC_FEATURES = [
    "source_port",
    "destination_port",
    "bytes_sent",
    "bytes_received",
    "duration_seconds",
    "failed_login_count",
    "connection_count",
    "unique_destination_count",
    "cpu_percent",
    "memory_percent",
    "process_count"
]

CATEGORICAL_FEATURES = [
    "protocol",
    "auth_result",
    "username",
    "privilege_level"
]

FEATURES = NUMERIC_FEATURES + CATEGORICAL_FEATURES

TARGET = "label"
GROUP = "campaign_id"


# =====================================================
# 3. LOAD AND VALIDATE DATASET
# =====================================================

def load_dataset():

    if not DATA_FILE.exists():
        raise FileNotFoundError(
            f"Dataset not found: {DATA_FILE}"
        )

    df = pd.read_csv(DATA_FILE)

    required = FEATURES + [TARGET, GROUP]

    missing = [
        col for col in required
        if col not in df.columns
    ]

    if missing:
        raise ValueError(
            f"Missing columns: {missing}"
        )

    if df[required].isnull().any().any():
        raise ValueError(
            "Missing values found in required columns."
        )

    if df[TARGET].nunique() < 2:
        raise ValueError("At least two classes are required.")

    print("Dataset loaded successfully.")
    print("Records:", len(df))
    print("Campaigns:", df[GROUP].nunique())

    print("\nClass distribution:")
    print(df[TARGET].value_counts())

    return df


# =====================================================
# 4. CAMPAIGN-AWARE TRAIN/TEST SPLIT
# =====================================================

def split_dataset(df):

    X = df[FEATURES]
    y = df[TARGET]
    groups = df[GROUP]

    splitter = GroupShuffleSplit(
        n_splits=1,
        test_size=0.20,
        random_state=SEED
    )

    train_idx, test_idx = next(
        splitter.split(X, y, groups)
    )

    X_train = X.iloc[train_idx]
    X_test = X.iloc[test_idx]

    y_train = y.iloc[train_idx]
    y_test = y.iloc[test_idx]

    train_groups = set(groups.iloc[train_idx])
    test_groups = set(groups.iloc[test_idx])

    assert train_groups.isdisjoint(test_groups)

    if set(y_train) != set(y_test):
        raise ValueError(
            "A class is missing from train or test split. "
            "Review the campaign split before training."
        )

    print("\nCampaign-aware split completed.")
    print("Training records:", len(X_train))
    print("Testing records:", len(X_test))
    print("Training campaigns:", len(train_groups))
    print("Testing campaigns:", len(test_groups))

    print("\nTraining class distribution:")
    print(y_train.value_counts())

    print("\nTesting class distribution:")
    print(y_test.value_counts())

    return X_train, X_test, y_train, y_test


# =====================================================
# 5. PREPROCESSING PIPELINE
# =====================================================

def create_preprocessor():

    numeric_pipeline = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler", StandardScaler())
    ])

    categorical_pipeline = Pipeline([
        (
            "imputer",
            SimpleImputer(strategy="most_frequent")
        ),
        (
            "encoder",
            OneHotEncoder(handle_unknown="ignore")
        )
    ])

    preprocessor = ColumnTransformer([
        (
            "numeric",
            numeric_pipeline,
            NUMERIC_FEATURES
        ),
        (
            "categorical",
            categorical_pipeline,
            CATEGORICAL_FEATURES
        )
    ])

    return preprocessor


# =====================================================
# 6. DEFINE FIVE ML MODELS
# =====================================================

def create_models(number_of_classes):

    models = {

        "Random Forest": RandomForestClassifier(
            n_estimators=200,
            class_weight="balanced",
            random_state=SEED,
            n_jobs=-1
        ),

        "XGBoost": XGBClassifier(
            n_estimators=150,
            max_depth=5,
            learning_rate=0.1,
            objective="multi:softprob",
            num_class=number_of_classes,
            eval_metric="mlogloss",
            random_state=SEED,
            n_jobs=-1
        ),

        "SVM": SVC(
            kernel="rbf",
            C=1.0,
            class_weight="balanced",
            random_state=SEED
        ),

        "Logistic Regression": LogisticRegression(
            max_iter=2000,
            class_weight="balanced",
            random_state=SEED
        ),

        "Gradient Boosting": GradientBoostingClassifier(
            n_estimators=150,
            learning_rate=0.1,
            max_depth=3,
            random_state=SEED
        )
    }

    return models


# =====================================================
# 7. TRAIN AND EVALUATE MODELS
# =====================================================

def train_models(
    X_train,
    X_test,
    y_train,
    y_test
):

    label_encoder = LabelEncoder()

    y_train_encoded = label_encoder.fit_transform(y_train)
    y_test_encoded = label_encoder.transform(y_test)

    class_names = label_encoder.classes_.tolist()

    models = create_models(len(class_names))

    sample_weights = compute_sample_weight(
        class_weight="balanced",
        y=y_train_encoded
    )

    results = []
    reports = {}
    matrices = {}
    predictions = {}

    for name, classifier in models.items():

        print("\n" + "=" * 55)
        print("Training:", name)
        print("=" * 55)

        pipeline = Pipeline([
            ("preprocessor", create_preprocessor()),
            ("classifier", classifier)
        ])

        pipeline.fit(
            X_train,
            y_train_encoded,
            classifier__sample_weight=sample_weights
        )

        predicted = pipeline.predict(X_test)

        accuracy = accuracy_score(
            y_test_encoded,
            predicted
        )

        precision = precision_score(
            y_test_encoded,
            predicted,
            average="macro",
            zero_division=0
        )

        recall = recall_score(
            y_test_encoded,
            predicted,
            average="macro",
            zero_division=0
        )

        f1 = f1_score(
            y_test_encoded,
            predicted,
            average="macro",
            zero_division=0
        )

        report = classification_report(
            y_test_encoded,
            predicted,
            labels=np.arange(len(class_names)),
            target_names=class_names,
            output_dict=True,
            zero_division=0
        )

        matrix = confusion_matrix(
            y_test_encoded,
            predicted,
            labels=np.arange(len(class_names))
        )

        results.append({
            "model": name,
            "accuracy": accuracy,
            "precision_macro": precision,
            "recall_macro": recall,
            "f1_macro": f1
        })

        reports[name] = report

        matrices[name] = {
            "labels": class_names,
            "matrix": matrix.tolist()
        }

        predictions[name] = predicted.tolist()

        safe_name = name.lower().replace(" ", "_")

        model_path = MODEL_DIR / f"{safe_name}.pkl"

        joblib.dump(pipeline, model_path)

        print("Accuracy:", round(accuracy, 4))
        print("Macro Precision:", round(precision, 4))
        print("Macro Recall:", round(recall, 4))
        print("Macro F1:", round(f1, 4))
        print("Saved:", model_path)

    return (
        results,
        reports,
        matrices,
        predictions,
        label_encoder,
        y_test_encoded
    )


# =====================================================
# 8. SAVE EVALUATION RESULTS
# =====================================================

def save_results(
    results,
    reports,
    matrices,
    predictions,
    label_encoder,
    y_test_encoded
):

    comparison = pd.DataFrame(results)

    comparison.to_csv(
        RESULT_DIR / "model_comparison.csv",
        index=False
    )

    with open(
        RESULT_DIR / "classification_reports.json",
        "w"
    ) as file:
        json.dump(reports, file, indent=4)

    with open(
        RESULT_DIR / "confusion_matrices.json",
        "w"
    ) as file:
        json.dump(matrices, file, indent=4)

    with open(
        RESULT_DIR / "label_classes.json",
        "w"
    ) as file:
        json.dump(
            label_encoder.classes_.tolist(),
            file,
            indent=4
        )

    prediction_data = pd.DataFrame({
        "actual": label_encoder.inverse_transform(
            y_test_encoded
        )
    })

    for name, values in predictions.items():

        prediction_data[
            name.lower().replace(" ", "_")
        ] = label_encoder.inverse_transform(
            np.array(values, dtype=int)
        )

    prediction_data.to_csv(
        RESULT_DIR / "test_predictions.csv",
        index=False
    )

    summary = {
        "dataset": str(DATA_FILE),
        "total_records": 10000,
        "feature_count": len(FEATURES),
        "features": FEATURES,
        "target": TARGET,
        "group_column": GROUP,
        "split_method": "GroupShuffleSplit",
        "test_size": 0.20,
        "random_state": SEED,
        "class_names": label_encoder.classes_.tolist(),
        "models": results,
        "note": (
            "Synthetic dataset evaluation. "
            "Results must not be interpreted as "
            "real-world detection performance."
        )
    }

    with open(
        RESULT_DIR / "evaluation_summary.json",
        "w"
    ) as file:
        json.dump(summary, file, indent=4)

    print("\nAll evaluation results saved.")
    print("Results folder:", RESULT_DIR)


# =====================================================
# 9. MAIN FUNCTION
# =====================================================

def main():

    df = load_dataset()

    X_train, X_test, y_train, y_test = split_dataset(df)

    (
        results,
        reports,
        matrices,
        predictions,
        label_encoder,
        y_test_encoded
    ) = train_models(
        X_train,
        X_test,
        y_train,
        y_test
    )

    save_results(
        results,
        reports,
        matrices,
        predictions,
        label_encoder,
        y_test_encoded
    )

    print("\n" + "=" * 55)
    print("FIVE-MODEL EVALUATION COMPLETED")
    print("=" * 55)

    print(
        pd.DataFrame(results).to_string(index=False)
    )


if __name__ == "__main__":
    main()
