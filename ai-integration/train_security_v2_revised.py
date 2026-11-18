
import json
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler, OneHotEncoder, LabelEncoder
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.utils.class_weight import compute_sample_weight

from xgboost import XGBClassifier

warnings.filterwarnings("ignore")

# --------------------------------------------------
# 1. PATHS
# --------------------------------------------------

DATA_FILE = Path("datasets/security_events_v2.csv")
MODEL_DIR = Path("models/security_v2_revised")
RESULT_DIR = Path("results/security_v2_revised")

MODEL_DIR.mkdir(parents=True, exist_ok=True)
RESULT_DIR.mkdir(parents=True, exist_ok=True)

RANDOM_STATE = 42
TEST_SIZE = 0.20

# --------------------------------------------------
# 2. FEATURES
# --------------------------------------------------

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
    "process_count",
]

CATEGORICAL_FEATURES = [
    "protocol",
    "auth_result",
    "username",
    "privilege_level",
]

FEATURES = NUMERIC_FEATURES + CATEGORICAL_FEATURES
TARGET = "label"
GROUP = "campaign_id"

# --------------------------------------------------
# 3. LOAD AND VALIDATE DATA
# --------------------------------------------------

print("=" * 65)
print("SIEM LITE - REVISED FIVE-MODEL EVALUATION")
print("=" * 65)

if not DATA_FILE.exists():
    raise FileNotFoundError(f"Dataset not found: {DATA_FILE}")

df = pd.read_csv(DATA_FILE)

required_columns = FEATURES + [TARGET, GROUP]
missing_columns = [c for c in required_columns if c not in df.columns]

if missing_columns:
    raise ValueError(f"Missing required columns: {missing_columns}")

if df[required_columns].isnull().any().any():
    raise ValueError("Missing values found in required columns.")

if df[GROUP].nunique() < 2:
    raise ValueError("Not enough campaigns for group splitting.")

if df.groupby(GROUP)[TARGET].nunique().max() > 1:
    raise ValueError("A campaign contains multiple target labels.")

print(f"\nDataset: {DATA_FILE}")
print(f"Total records: {len(df)}")
print(f"Unique campaigns: {df[GROUP].nunique()}")
print("\nClass distribution:")
print(df[TARGET].value_counts().to_string())

X = df[FEATURES].copy()
y_text = df[TARGET].astype(str)
groups = df[GROUP].copy()

# --------------------------------------------------
# 4. CAMPAIGN-AWARE TRAIN/TEST SPLIT
# --------------------------------------------------

splitter = GroupShuffleSplit(
    n_splits=1,
    test_size=TEST_SIZE,
    random_state=RANDOM_STATE,
)

train_idx, test_idx = next(splitter.split(X, y_text, groups))

X_train = X.iloc[train_idx].copy()
X_test = X.iloc[test_idx].copy()

y_train_text = y_text.iloc[train_idx]
y_test_text = y_text.iloc[test_idx]

train_groups = set(groups.iloc[train_idx])
test_groups = set(groups.iloc[test_idx])

if train_groups.intersection(test_groups):
    raise RuntimeError("Campaign leakage detected!")

if set(y_train_text.unique()) != set(y_test_text.unique()):
    raise ValueError("Train/test class distributions do not contain the same classes.")

label_encoder = LabelEncoder()
y_train = label_encoder.fit_transform(y_train_text)
y_test = label_encoder.transform(y_test_text)

class_names = label_encoder.classes_.tolist()
num_classes = len(class_names)

print("\nCampaign-aware split completed.")
print(f"Training records: {len(X_train)}")
print(f"Testing records: {len(X_test)}")
print(f"Training campaigns: {len(train_groups)}")
print(f"Testing campaigns: {len(test_groups)}")
print("Campaign overlap: 0")

# --------------------------------------------------
# 5. PREPROCESSING
# --------------------------------------------------

numeric_transformer = Pipeline(
    steps=[
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler", StandardScaler()),
    ]
)

categorical_transformer = Pipeline(
    steps=[
        ("imputer", SimpleImputer(strategy="most_frequent")),
        ("encoder", OneHotEncoder(handle_unknown="ignore")),
    ]
)

preprocessor = ColumnTransformer(
    transformers=[
        ("numeric", numeric_transformer, NUMERIC_FEATURES),
        ("categorical", categorical_transformer, CATEGORICAL_FEATURES),
    ]
)

# Sample weights calculated from training labels only.
sample_weights = compute_sample_weight(
    class_weight="balanced",
    y=y_train,
)

# --------------------------------------------------
# 6. DEFINE FIVE MODELS
# --------------------------------------------------

models = {
    "random_forest": RandomForestClassifier(
        n_estimators=200,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    ),

    "xgboost": XGBClassifier(
        n_estimators=150,
        max_depth=5,
        learning_rate=0.1,
        objective="multi:softprob",
        num_class=num_classes,
        eval_metric="mlogloss",
        random_state=RANDOM_STATE,
        n_jobs=-1,
        verbosity=0,
    ),

    "svm": SVC(
        kernel="rbf",
        C=1.0,
        probability=True,
        random_state=RANDOM_STATE,
    ),

    "logistic_regression": LogisticRegression(
        max_iter=2000,
        random_state=RANDOM_STATE,
    ),

    "gradient_boosting": GradientBoostingClassifier(
        n_estimators=100,
        learning_rate=0.1,
        max_depth=3,
        random_state=RANDOM_STATE,
    ),
}

# --------------------------------------------------
# 7. TRAIN AND EVALUATE
# --------------------------------------------------

comparison_rows = []
classification_reports = {}
confusion_matrices = {}
all_predictions = []

for model_name, classifier in models.items():

    print("\n" + "-" * 65)
    print(f"Training: {model_name}")
    print("-" * 65)

    pipeline = Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            ("classifier", classifier),
        ]
    )

    pipeline.fit(
        X_train,
        y_train,
        classifier__sample_weight=sample_weights,
    )

    predictions = pipeline.predict(X_test)

    accuracy = accuracy_score(y_test, predictions)
    precision = precision_score(
        y_test, predictions, average="macro", zero_division=0
    )
    recall = recall_score(
        y_test, predictions, average="macro", zero_division=0
    )
    f1 = f1_score(
        y_test, predictions, average="macro", zero_division=0
    )

    report = classification_report(
        y_test,
        predictions,
        labels=np.arange(num_classes),
        target_names=class_names,
        output_dict=True,
        zero_division=0,
    )

    matrix = confusion_matrix(
        y_test,
        predictions,
        labels=np.arange(num_classes),
    )

    comparison_rows.append({
        "model": model_name,
        "accuracy": accuracy,
        "macro_precision": precision,
        "macro_recall": recall,
        "macro_f1": f1,
    })

    classification_reports[model_name] = report
    confusion_matrices[model_name] = matrix.tolist()

    for actual, predicted in zip(y_test_text, label_encoder.inverse_transform(predictions)):
        all_predictions.append({
            "model": model_name,
            "actual_label": actual,
            "predicted_label": predicted,
            "correct": actual == predicted,
        })

    model_path = MODEL_DIR / f"{model_name}.pkl"
    joblib.dump(pipeline, model_path)

    print(f"Accuracy:        {accuracy:.4f}")
    print(f"Macro Precision: {precision:.4f}")
    print(f"Macro Recall:    {recall:.4f}")
    print(f"Macro F1-score:  {f1:.4f}")
    print(f"Saved model: {model_path}")

# --------------------------------------------------
# 8. SAVE RESULTS
# --------------------------------------------------

comparison_df = pd.DataFrame(comparison_rows)
comparison_df = comparison_df.sort_values(
    by="macro_f1",
    ascending=False,
)

comparison_df.to_csv(
    RESULT_DIR / "model_comparison.csv",
    index=False,
)

with open(RESULT_DIR / "classification_reports.json", "w") as f:
    json.dump(classification_reports, f, indent=4)

with open(RESULT_DIR / "confusion_matrices.json", "w") as f:
    json.dump(confusion_matrices, f, indent=4)

with open(RESULT_DIR / "label_classes.json", "w") as f:
    json.dump(class_names, f, indent=4)

pd.DataFrame(all_predictions).to_csv(
    RESULT_DIR / "test_predictions.csv",
    index=False,
)

summary = {
    "dataset": str(DATA_FILE),
    "dataset_type": "synthetic",
    "total_records": int(len(df)),
    "total_campaigns": int(df[GROUP].nunique()),
    "training_records": int(len(X_train)),
    "testing_records": int(len(X_test)),
    "training_campaigns": int(len(train_groups)),
    "testing_campaigns": int(len(test_groups)),
    "campaign_overlap": 0,
    "random_state": RANDOM_STATE,
    "test_size": TEST_SIZE,
    "features": FEATURES,
    "classes": class_names,
    "best_model_by_macro_f1": str(comparison_df.iloc[0]["model"]),
    "metrics": comparison_rows,
    "evaluation_note": (
        "Results are from a synthetic dataset and should not be "
        "interpreted as real-world cybersecurity performance."
    ),
}

with open(RESULT_DIR / "evaluation_summary.json", "w") as f:
    json.dump(summary, f, indent=4)

# --------------------------------------------------
# 9. FINAL SUMMARY
# --------------------------------------------------

print("\n" + "=" * 65)
print("REVISED MODEL COMPARISON")
print("=" * 65)

print(comparison_df.to_string(index=False))

print("\nAll revised models trained successfully.")
print(f"Models saved in: {MODEL_DIR}")
print(f"Results saved in: {RESULT_DIR}")
print("\nIMPORTANT: These are synthetic dataset evaluation results.")
