
#!/usr/bin/env python3
"""SIEM Lite: Leakage-safe comparison of five ML classifiers."""

import os
import sys
import json
import logging
import pickle
from collections import Counter

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.ensemble import (
    RandomForestClassifier,
    GradientBoostingClassifier
)
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import Pipeline

from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay
)

from xgboost import XGBClassifier

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "ai-integration"))

from integrator import AIIntegrator


# --------------------------------------------------
# 1. PROJECT CONFIGURATION
# --------------------------------------------------

RANDOM_STATE = 42
NUM_SAMPLES = 2000
TEST_SIZE = 0.20

OUTPUT_DIR = os.path.join(PROJECT_ROOT, "results")
MODEL_DIR = os.path.join(PROJECT_ROOT, "models")

os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(MODEL_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger(__name__)


# --------------------------------------------------
# 2. BUILD FIVE MACHINE LEARNING MODELS
# --------------------------------------------------

def build_models():
    """Create five classifiers with training-only scaling."""

    return {

        "Random Forest": Pipeline([
            ("scaler", StandardScaler()),
            ("model", RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=RANDOM_STATE,
                n_jobs=-1
            ))
        ]),

        "XGBoost": Pipeline([
            ("scaler", StandardScaler()),
            ("model", XGBClassifier(
                n_estimators=100,
                max_depth=4,
                learning_rate=0.1,
                random_state=RANDOM_STATE,
                eval_metric="mlogloss",
                n_jobs=-1
            ))
        ]),

        "SVM": Pipeline([
            ("scaler", StandardScaler()),
            ("model", SVC(
                kernel="rbf",
                probability=True,
                random_state=RANDOM_STATE
            ))
        ]),

        "Logistic Regression": Pipeline([
            ("scaler", StandardScaler()),
            ("model", LogisticRegression(
                max_iter=2000,
                random_state=RANDOM_STATE
            ))
        ]),

        "Gradient Boosting": Pipeline([
            ("scaler", StandardScaler()),
            ("model", GradientBoostingClassifier(
                n_estimators=100,
                learning_rate=0.1,
                max_depth=3,
                random_state=RANDOM_STATE
            ))
        ])

    }


# --------------------------------------------------
# 3. SAVE JSON RESULTS
# --------------------------------------------------

def save_json(data, path):
    """Save JSON with NumPy-compatible values."""

    def convert(value):

        if isinstance(value, np.integer):
            return int(value)

        if isinstance(value, np.floating):
            return float(value)

        if isinstance(value, np.ndarray):
            return value.tolist()

        return str(value)

    with open(path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4, default=convert)


# --------------------------------------------------
# 4. GENERATE COMPARISON CHARTS
# --------------------------------------------------

def generate_comparison_charts(results_df, all_matrices, class_names):
    """Generate model comparison and confusion matrix charts."""

    # Chart 1: Accuracy comparison

    plt.figure(figsize=(10, 6))

    plt.bar(
        results_df["Model"],
        results_df["Accuracy"]
    )

    plt.title("Accuracy Comparison of Five ML Classifiers")
    plt.xlabel("Machine Learning Models")
    plt.ylabel("Accuracy")
    plt.ylim(0, 1.05)
    plt.xticks(rotation=20, ha="right")
    plt.tight_layout()

    plt.savefig(
        os.path.join(OUTPUT_DIR, "accuracy_comparison.png"),
        dpi=300
    )

    plt.close()

    # Chart 2: Macro Precision, Recall and F1

    results_df.plot(
        x="Model",
        y=[
            "Macro Precision",
            "Macro Recall",
            "Macro F1"
        ],
        kind="bar",
        figsize=(12, 6)
    )

    plt.title("Macro Performance Comparison")
    plt.xlabel("Machine Learning Models")
    plt.ylabel("Score")
    plt.ylim(0, 1.05)
    plt.xticks(rotation=20, ha="right")
    plt.tight_layout()

    plt.savefig(
        os.path.join(OUTPUT_DIR, "macro_metrics_comparison.png"),
        dpi=300
    )

    plt.close()

    # Charts 3-7: Confusion matrix for each classifier

    for model_name, matrix in all_matrices.items():

        display = ConfusionMatrixDisplay(
            confusion_matrix=np.array(matrix),
            display_labels=class_names
        )

        fig, ax = plt.subplots(figsize=(7, 6))

        display.plot(
            ax=ax,
            cmap="Blues",
            values_format="d",
            colorbar=False
        )

        ax.set_title(f"Confusion Matrix - {model_name}")

        plt.tight_layout()

        safe_name = model_name.lower().replace(" ", "_")

        plt.savefig(
            os.path.join(
                OUTPUT_DIR,
                f"confusion_matrix_{safe_name}.png"
            ),
            dpi=300
        )

        plt.close()

    logger.info("All comparison charts generated successfully.")


# --------------------------------------------------
# 5. MAIN TRAINING AND EVALUATION FUNCTION
# --------------------------------------------------

def main():

    print("\nSIEM LITE - FIVE CLASSIFIER EVALUATION")
    print("=" * 55)

    # STEP 1: Generate synthetic dataset

    logger.info(
        "Generating %s synthetic records...",
        NUM_SAMPLES
    )

    integrator = AIIntegrator(model_dir=MODEL_DIR)

    data, labels = integrator.generate_training_data(
        num_samples=NUM_SAMPLES
    )

    labels = np.asarray(labels)

    label_encoder = LabelEncoder()

    y = label_encoder.fit_transform(labels)

    class_names = label_encoder.classes_.tolist()

    class_ids = np.arange(len(class_names))

    if len(data) != NUM_SAMPLES or len(labels) != NUM_SAMPLES:
        raise ValueError(
            "Dataset does not contain exactly 2,000 records."
        )

    if data.isnull().any().any():
        raise ValueError(
            "Dataset contains missing values. Inspect before training."
        )

    print("\nDataset shape:", data.shape)

    print(
        "Class distribution:",
        dict(Counter(labels))
    )

    
    # STEP 2: Extract features

    X = np.asarray(
        integrator.prepare_features(data),
        dtype=float
    )

    if X.ndim != 2 or len(X) != len(y):
        raise ValueError(
            "Feature matrix dimensions do not match the labels."
        )

    if not np.isfinite(X).all():
        raise ValueError(
            "Feature matrix contains NaN or infinite values."
        )

    feature_names = [
        "status_code",
        "hour",
        "path_length",
        "method_get",
        "method_post",
        "method_put",
        "method_delete",
        "method_other",
        "user_agent_length",
        "query_present",
        "sqli_score",
        "xss_score",
        "traversal_score",
        "scanner_score"
    ]

    if len(feature_names) != X.shape[1]:
        raise ValueError(
            "Feature names do not match the extracted feature count."
        )

    # STEP 3: Create groups from identical feature patterns

    groups, unique_group_ids = pd.factorize(
        pd.Series(
            [tuple(row) for row in X],
            dtype=object
        )
    )

    print("\nUNIQUE FEATURE GROUPS")
    print("-" * 40)

    print("Total records:", len(X))

    print(
        "Unique feature patterns:",
        len(unique_group_ids)
    )

    print(
        "Duplicate records:",
        len(X) - len(unique_group_ids)
    )


    # STEP 4: Create stratified group splitter

    splitter = StratifiedGroupKFold(
        n_splits=5,
        shuffle=True,
        random_state=RANDOM_STATE
    )

    # Examine all folds and select the best split

    best_split = None
    best_score = float("inf")

    total_class_counts = np.bincount(
        y,
        minlength=len(class_names)
    )

    overall_class_distribution = (
        total_class_counts / len(y)
    )

    for candidate_train_idx, candidate_test_idx in splitter.split(
        X,
        y,
        groups=groups
    ):

        # Every class must appear in both sets

        if (
            set(np.unique(y[candidate_train_idx])) != set(class_ids)
            or set(np.unique(y[candidate_test_idx])) != set(class_ids)
        ):
            continue

        actual_test_size = (
            len(candidate_test_idx) / len(y)
        )

        test_class_counts = np.bincount(
            y[candidate_test_idx],
            minlength=len(class_names)
        )

        test_class_distribution = (
            test_class_counts / len(candidate_test_idx)
        )

        size_error = abs(
            actual_test_size - TEST_SIZE
        )

        distribution_error = np.mean(
            np.abs(
                test_class_distribution -
                overall_class_distribution
            )
        )

        score = size_error + distribution_error

        if score < best_score:

            best_score = score

            best_split = (
                candidate_train_idx,
                candidate_test_idx
            )

    if best_split is None:
        raise ValueError(
            "Could not create a grouped train-test split containing "
            "every class in both sets. Inspect the dataset."
        )

    train_idx, test_idx = best_split

    X_train = X[train_idx]
    X_test = X[test_idx]

    y_train = y[train_idx]
    y_test = y[test_idx]

    # STEP 5: Display split information

    print("\nGROUP-AWARE DATA SPLIT")
    print("-" * 40)

    print("Training records:", len(X_train))
    print("Testing records :", len(X_test))

    print(
        "Actual training percentage:",
        round(len(X_train) / len(X) * 100, 2)
    )

    print(
        "Actual testing percentage:",
        round(len(X_test) / len(X) * 100, 2)
    )

    print(
        "Training classes:",
        dict(Counter(y_train))
    )

    print(
        "Testing classes:",
        dict(Counter(y_test))
    )

    # STEP 6: Verify duplicate-pattern leakage

    train_patterns = {
        tuple(row) for row in X_train
    }

    test_patterns = {
        tuple(row) for row in X_test
    }

    overlap = train_patterns.intersection(
        test_patterns
    )

    overlap_report = {
        "training_records": len(X_train),
        "testing_records": len(X_test),
        "training_unique_patterns": len(train_patterns),
        "testing_unique_patterns": len(test_patterns),
        "shared_feature_patterns": len(overlap),
        "duplicate_pattern_leakage_prevented": len(overlap) == 0
    }

    save_json(
        overlap_report,
        os.path.join(
            OUTPUT_DIR,
            "duplicate_pattern_check.json"
        )
    )

    print("\nDUPLICATE-PATTERN VERIFICATION")
    print(overlap_report)

    if len(overlap) != 0:
        raise RuntimeError(
            "Duplicate feature patterns crossed the train-test split."
        )

    # STEP 7: Train and evaluate five models

    models = build_models()

    results = []

    predictions = pd.DataFrame({
        "test_record_index": test_idx,
        "actual_label": label_encoder.inverse_transform(y_test)
    })

    all_reports = {}

    all_matrices = {}

    for name, model in models.items():

        print("\n" + "=" * 55)
        print("MODEL:", name)
        print("=" * 55)

        # Fit preprocessing and model on training records only

        model.fit(X_train, y_train)

        # Predict every held-out test record

        y_pred = model.predict(X_test)

        accuracy = accuracy_score(
            y_test,
            y_pred
        )

        precision, recall, f1, support = (
            precision_recall_fscore_support(
                y_test,
                y_pred,
                labels=class_ids,
                zero_division=0
            )
        )

        macro_p, macro_r, macro_f1, _ = (
            precision_recall_fscore_support(
                y_test,
                y_pred,
                average="macro",
                zero_division=0
            )
        )

        weighted_p, weighted_r, weighted_f1, _ = (
            precision_recall_fscore_support(
                y_test,
                y_pred,
                average="weighted",
                zero_division=0
            )
        )

        matrix = confusion_matrix(
            y_test,
            y_pred,
            labels=class_ids
        )

        report = classification_report(
            y_test,
            y_pred,
            labels=class_ids,
            target_names=class_names,
            output_dict=True,
            zero_division=0
        )

        results.append({

            "Model": name,

            "Accuracy": accuracy,

            "Macro Precision": macro_p,

            "Macro Recall": macro_r,

            "Macro F1": macro_f1,

            "Weighted Precision": weighted_p,

            "Weighted Recall": weighted_r,

            "Weighted F1": weighted_f1

        })

        all_reports[name] = report

        all_matrices[name] = matrix.tolist()

        predictions[
            name + "_prediction"
        ] = label_encoder.inverse_transform(y_pred)

        print(f"Accuracy          : {accuracy:.4f}")
        print(f"Macro Precision   : {macro_p:.4f}")
        print(f"Macro Recall      : {macro_r:.4f}")
        print(f"Macro F1-score    : {macro_f1:.4f}")
        print(f"Weighted F1-score : {weighted_f1:.4f}")

        print("\nPer-class report:")

        print(
            classification_report(
                y_test,
                y_pred,
                labels=class_ids,
                target_names=class_names,
                zero_division=0
            )
        )

        print("Confusion matrix:")
        print(matrix)

        if accuracy == 1.0:

            logger.warning(
                "%s achieved 100%% accuracy. Investigate data "
                "simplicity, duplicates and feature-label relationships "
                "before making any generalisation claim.",
                name
            )

    # STEP 8: Save evaluation results

    results_df = pd.DataFrame(results)

    results_df = results_df.sort_values(
        by="Macro F1",
        ascending=False
    )

    results_df.to_csv(
        os.path.join(
            OUTPUT_DIR,
            "model_comparison.csv"
        ),
        index=False
    )

    predictions.to_csv(
        os.path.join(
            OUTPUT_DIR,
            "all_test_predictions.csv"
        ),
        index=False
    )

    save_json(
        all_reports,
        os.path.join(
            OUTPUT_DIR,
            "classification_reports.json"
        )
    )

    save_json(
        all_matrices,
        os.path.join(
            OUTPUT_DIR,
            "confusion_matrices.json"
        )
    )

    save_json(
        {
            "dataset_records": len(data),
            "training_records": len(X_train),
            "testing_records": len(X_test),
            "random_state": RANDOM_STATE,
            "requested_test_size": TEST_SIZE,
            "actual_test_size": len(X_test) / len(X),
            "class_names": class_names,
            "feature_names": feature_names,
            "duplicate_check": overlap_report,
            "models": results
        },
        os.path.join(
            OUTPUT_DIR,
            "evaluation_summary.json"
        )
    )

    # STEP 9: Generate comparison charts

    generate_comparison_charts(
        results_df,
        all_matrices,
        class_names
    )

    print("\nFINAL MODEL COMPARISON")
    print("=" * 70)

    print(
        results_df.to_string(index=False)
    )

    
    # STEP 10: Save all five training-fitted model pipelines

    print("\nSAVING FIVE TRAINED MODELS")
    print("=" * 55)

    os.makedirs(MODEL_DIR, exist_ok=True)

    model_files = {
        "Random Forest": "random_forest.pkl",
        "XGBoost": "xgboost.pkl",
        "SVM": "svm.pkl",
        "Logistic Regression": "logistic_regression.pkl",
        "Gradient Boosting": "gradient_boosting.pkl"
    }

    saved_model_paths = {}

    for name, model in models.items():

        if name not in model_files:
            raise ValueError(
                f"Unexpected model name: {name}"
            )

        filename = model_files[name]

        model_path = os.path.join(
            MODEL_DIR,
            filename
        )

        temporary_path = model_path + ".tmp"

        try:
            with open(temporary_path, "wb") as file:
                pickle.dump(model, file)

            os.replace(temporary_path, model_path)

        finally:
            if os.path.exists(temporary_path):
                os.remove(temporary_path)

        saved_model_paths[name] = model_path

        print(f"{name}: {model_path}")

    # STEP 11: Train anomaly detector using training records only

    logger.info(
        "Training anomaly detector on %s training records...",
        len(train_idx)
    )

    anomaly_training_data = (
        data.iloc[train_idx].reset_index(drop=True)
    )

    anomaly_training_success = integrator.train_anomaly_detector(
        anomaly_training_data
    )

    if not anomaly_training_success:
        raise RuntimeError(
            "Anomaly detector training failed."
        )

    # STEP 12: Save evaluation and model metadata

    save_json(
        {
            "saved_models": {
                name: os.path.basename(path)
                for name, path in saved_model_paths.items()
            },
            "model_selection": (
                "No deployment winner selected using held-out test results."
            ),
            "evaluation_method": (
                "All five pipelines were fitted on the same training "
                "records and evaluated on the same held-out test records."
            ),
            "anomaly_detector_training_records": len(train_idx),
            "feature_names": feature_names,
            "class_names": class_names,
            "random_state": RANDOM_STATE
        },
        os.path.join(
            OUTPUT_DIR,
            "model_artifacts_summary.json"
        )
    )

    # Do not overwrite the legacy threat_classifier.pkl or
    # siem_lite_best_classifier.pkl files here.
    # The five newly trained pipelines are saved independently.

    # STEP 13: Final completion report

    print("\nCOMPLETED")
    print("=" * 55)

    print("Total records     :", len(data))
    print("Training records  :", len(X_train))
    print("Testing records   :", len(X_test))
    print("Features per record:", X.shape[1])
    print("Models saved      :", len(saved_model_paths))
    print("Results folder    :", OUTPUT_DIR)
    print("Model folder      :", MODEL_DIR)

    print(
        "\nAll five models were evaluated on the same "
        "held-out test records."
    )

    print(
        "All five saved pipelines were fitted on training "
        "records only. No test-based winner was selected."
    )


# --------------------------------------------------
# 6. PROGRAM ENTRY POINT
# --------------------------------------------------

if __name__ == "__main__":
    main()
