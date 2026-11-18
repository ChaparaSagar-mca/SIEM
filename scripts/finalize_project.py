
import os
import sys
import json
import csv
import sqlite3
import importlib.util
from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).resolve().parent.parent
os.chdir(ROOT)

MODELS = [
    "random_forest",
    "xgboost",
    "svm",
    "logistic_regression",
    "gradient_boosting"
]

REPORT = []
def log(message):
    print(message)
    REPORT.append(message)

def read_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None

log("=" * 65)
log("SIEM LITE - FINAL PROJECT VERIFICATION")
log(datetime.now().strftime("Date: %Y-%m-%d %H:%M:%S"))
log("=" * 65)

# 1. Verify five trained models.
log("\n1. TRAINED MODEL VERIFICATION")
model_dir = ROOT / "models" / "security_v2"
model_status = {}

for name in MODELS:
    path = model_dir / f"{name}.pkl"
    exists = path.is_file() and path.stat().st_size > 0
    model_status[name] = exists
    log(f"[{'PASS' if exists else 'FAIL'}] {name}: {path}")

# 2. Verify actual evaluation files.
log("\n2. MODEL EVALUATION FILES")
evaluation_files = [
    ROOT / "results/security_v2/model_comparison.csv",
    ROOT / "results/security_v2/evaluation_summary.json",
    ROOT / "results/security_v2/confusion_matrices.json",
    ROOT / "results/security_v2/classification_reports.json",
    ROOT / "results/security_v2/test_predictions.csv"
]

for path in evaluation_files:
    log(f"[{'PASS' if path.is_file() else 'FAIL'}] {path}")

comparison = ROOT / "results/security_v2/model_comparison.csv"
if comparison.is_file():
    log("\nMODEL COMPARISON DATA:")
    with comparison.open(encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        log("Columns: " + str(reader.fieldnames))
        for row in reader:
            log(str(row))

# 3. Check whether test predictions contain labelled outcomes.
log("\n3. LABELLED TEST DATA VALIDATION")
prediction_file = ROOT / "results/security_v2/test_predictions.csv"
labelled_data_verified = False

if prediction_file.is_file():
    with prediction_file.open(encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        columns = reader.fieldnames or []
        rows = list(reader)

    log("Prediction columns: " + str(columns))
    log(f"Prediction rows: {len(rows)}")

    normalized = {c.lower().strip(): c for c in columns}
    true_candidates = [
        "y_true", "true_label", "actual", "actual_label",
        "true", "ground_truth", "label"
    ]
    pred_candidates = [
        "y_pred", "predicted_label", "prediction",
        "predicted", "pred_label"
    ]

    true_col = next(
        (normalized[x] for x in true_candidates if x in normalized),
        None
    )
    pred_col = next(
        (normalized[x] for x in pred_candidates if x in normalized),
        None
    )

    if true_col and pred_col and rows:
        actual = [r[true_col] for r in rows]
        predicted = [r[pred_col] for r in rows]

        if all(x != "" for x in actual + predicted):
            try:
                from sklearn.metrics import (
                    accuracy_score, precision_score,
                    recall_score, f1_score,
                    classification_report
                )

                log("[PASS] Actual and predicted labels are available.")
                log(f"Accuracy: {accuracy_score(actual, predicted):.4f}")
                log(
                    "Macro precision: "
                    f"{precision_score(actual, predicted, average='macro', zero_division=0):.4f}"
                )
                log(
                    "Macro recall: "
                    f"{recall_score(actual, predicted, average='macro', zero_division=0):.4f}"
                )
                log(
                    "Macro F1: "
                    f"{f1_score(actual, predicted, average='macro', zero_division=0):.4f}"
                )
                labelled_data_verified = True
            except Exception as e:
                log(f"[WARNING] Could not calculate metrics: {e}")
    else:
        log("[WARNING] Recognized actual/predicted label columns were not found.")
else:
    log("[WARNING] Test predictions file is missing.")

if not labelled_data_verified:
    log("[NOT VERIFIED] Detection accuracy cannot be independently calculated from recognized labelled columns.")

# 4. Read production database without modifying it.
log("\n4. PRODUCTION DATABASE VERIFICATION")
db_path = ROOT / "siem_data.db"
db_metrics = {}

if db_path.is_file():
    try:
        conn = sqlite3.connect(
            f"{db_path.resolve().as_uri()}?mode=ro",
            uri=True
        )
        tables = {
            row[0] for row in
            conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }

        for table in ["logs", "alerts", "processing_results"]:
            if table in tables:
                count = conn.execute(
                    f'SELECT COUNT(*) FROM "{table}"'
                ).fetchone()[0]
                db_metrics[table] = count
                log(f"[PASS] {table}: {count} records")

        if "processing_results" in tables:
            result = conn.execute("""
                SELECT
                    COUNT(*),
                    SUM(CASE WHEN status='success' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END)
                FROM processing_results
            """).fetchone()

            total, success, failed = result
            total = total or 0
            success = success or 0
            failed = failed or 0
            rate = success / total * 100 if total else 0

            db_metrics["attempts"] = total
            db_metrics["successful"] = success
            db_metrics["failed"] = failed
            db_metrics["success_rate"] = round(rate, 2)

            log(f"Processing attempts: {total}")
            log(f"Successful: {success}")
            log(f"Failed: {failed}")
            log(f"Actual processing success rate: {rate:.2f}%")

        conn.close()
    except Exception as e:
        log(f"[FAIL] Database audit: {e}")
else:
    log("[FAIL] Production database not found.")

# 5. Verify dashboard API using an isolated Flask test client.
log("\n5. DASHBOARD API VERIFICATION")
dashboard_data = None

try:
    analyzer_path = ROOT / "server" / "analyzer.py"
    spec = importlib.util.spec_from_file_location(
        "siem_final_audit_analyzer", analyzer_path
    )
    analyzer = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = analyzer
    spec.loader.exec_module(analyzer)

    with analyzer.app.test_client() as client:
        for route in [
            "/health",
            "/api/dashboard",
            "/api/alerts",
            "/api/logs",
            "/api/ml-predictions"
        ]:
            response = client.get(route)
            log(
                f"[{'PASS' if response.status_code == 200 else 'FAIL'}] "
                f"{route}: HTTP {response.status_code}"
            )

            if route == "/api/dashboard" and response.status_code == 200:
                dashboard_data = response.get_json() or {}

    if dashboard_data:
        logs = dashboard_data.get("logs", {})
        threats = dashboard_data.get("threats", {})

        log(f"Dashboard logs processed: {logs.get('processed')}")
        log(f"Dashboard success rate: {logs.get('success_rate')}%")
        log(
            "Dashboard predicted threat events: "
            f"{threats.get('predicted_threat_events')}"
        )

        if db_metrics.get("attempts", 0) > 0:
            matches = (
                logs.get("processed") == db_metrics.get("successful")
                and logs.get("success_rate") == db_metrics.get("success_rate")
            )
            log(
                f"[{'PASS' if matches else 'CHECK'}] "
                "Dashboard processing values compared with database."
            )

        if "detection_rate" in threats:
            log("[WARNING] Do not present prediction share as validated detection accuracy.")
except Exception as e:
    log(f"[WARNING] Dashboard API verification could not complete: {e}")

# 6. Generate final documentation and screenshot checklist.
docs = ROOT / "docs"
docs.mkdir(exist_ok=True)

report_path = docs / "final_verification_report.md"
report_path.write_text(
    "# SIEM Lite - Final Verification Report\n\n"
    + "\n".join(REPORT)
    + "\n\n## Verification limitations\n"
    "- A successful API test does not prove the browser UI layout visually.\n"
    "- Detection accuracy requires valid labelled actual and predicted outcomes.\n"
    "- Processing success rate and ML detection accuracy are different metrics.\n",
    encoding="utf-8"
)

checklist_path = docs / "final_screenshot_checklist.md"
checklist_path.write_text("""# Final SIEM Lite Screenshot Checklist

Capture these screenshots from the running project:

1. Main SIEM dashboard showing actual database-backed values.
2. Alerts page showing generated security alerts.
3. Logs page showing processed log records.
4. ML predictions page.
5. Five-model comparison table with actual evaluation metrics.
6. Confusion matrix for Random Forest.
7. Confusion matrix for XGBoost.
8. Confusion matrix for SVM.
9. Confusion matrix for Logistic Regression.
10. Confusion matrix for Gradient Boosting.
11. Dataset overview and class distribution.
12. Final verification report.

Do not edit, fabricate, or alter screenshots or evaluation results.
""", encoding="utf-8")

log("\n6. GENERATED DOCUMENTATION")
log(f"[PASS] {report_path.relative_to(ROOT)}")
log(f"[PASS] {checklist_path.relative_to(ROOT)}")

log("\n" + "=" * 65)
log("FINALIZATION AUDIT COMPLETED")
log("Review warnings and limitations before claiming final submission readiness.")
log("=" * 65)

print("\nFull report saved to:", report_path)
print("Screenshot checklist saved to:", checklist_path)



