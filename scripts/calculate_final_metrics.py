
import csv
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix
)

file_path = "results/security_v2/test_predictions.csv"

with open(file_path, encoding="utf-8-sig") as file:
    rows = list(csv.DictReader(file))

actual = [row["actual"] for row in rows]

models = [
    "random_forest",
    "xgboost",
    "svm",
    "logistic_regression",
    "gradient_boosting"
]

binary_actual = [label != "normal" for label in actual]

print("FINAL FIVE-MODEL EVALUATION")
print("Total test records:", len(rows))

for model in models:
    predicted = [row[model] for row in rows]
    binary_predicted = [
        label != "normal" for label in predicted
    ]

    tn, fp, fn, tp = confusion_matrix(
        binary_actual,
        binary_predicted,
        labels=[False, True]
    ).ravel()

    threat_recall = (
        tp / (tp + fn) * 100
        if (tp + fn) else 0
    )

    print("\nMODEL:", model.upper())
    print("Accuracy:", round(
        accuracy_score(actual, predicted) * 100, 2
    ), "%")
    print("Macro Precision:", round(
        precision_score(
            actual, predicted,
            average="macro", zero_division=0
        ) * 100, 2
    ), "%")
    print("Macro Recall:", round(
        recall_score(
            actual, predicted,
            average="macro", zero_division=0
        ) * 100, 2
    ), "%")
    print("Macro F1:", round(
        f1_score(
            actual, predicted,
            average="macro", zero_division=0
        ) * 100, 2
    ), "%")
    print("Threat Recall:", round(threat_recall, 2), "%")
    print("Threat Confusion Matrix:", tn, fp, fn, tp)
