# SIEM Lite - Final Verification Report

=================================================================
SIEM LITE - FINAL PROJECT VERIFICATION
Date: 2026-11-18 12:08:33
=================================================================

1. TRAINED MODEL VERIFICATION
[PASS] random_forest: D:\SIEM-Projects\siem-lite-project\models\security_v2\random_forest.pkl
[PASS] xgboost: D:\SIEM-Projects\siem-lite-project\models\security_v2\xgboost.pkl
[PASS] svm: D:\SIEM-Projects\siem-lite-project\models\security_v2\svm.pkl
[PASS] logistic_regression: D:\SIEM-Projects\siem-lite-project\models\security_v2\logistic_regression.pkl
[PASS] gradient_boosting: D:\SIEM-Projects\siem-lite-project\models\security_v2\gradient_boosting.pkl

2. MODEL EVALUATION FILES
[PASS] D:\SIEM-Projects\siem-lite-project\results\security_v2\model_comparison.csv
[PASS] D:\SIEM-Projects\siem-lite-project\results\security_v2\evaluation_summary.json
[PASS] D:\SIEM-Projects\siem-lite-project\results\security_v2\confusion_matrices.json
[PASS] D:\SIEM-Projects\siem-lite-project\results\security_v2\classification_reports.json
[PASS] D:\SIEM-Projects\siem-lite-project\results\security_v2\test_predictions.csv

MODEL COMPARISON DATA:
Columns: ['model', 'accuracy', 'precision_macro', 'recall_macro', 'f1_macro']
{'model': 'Random Forest', 'accuracy': '0.9355', 'precision_macro': '0.9499259579865349', 'recall_macro': '0.9345428453136718', 'f1_macro': '0.9408884439951107'}
{'model': 'XGBoost', 'accuracy': '0.9385', 'precision_macro': '0.9515451893225176', 'recall_macro': '0.9372172965796723', 'f1_macro': '0.9435659347097901'}
{'model': 'SVM', 'accuracy': '0.9', 'precision_macro': '0.909195493033637', 'recall_macro': '0.9119008592067878', 'f1_macro': '0.9102336387302133'}
{'model': 'Logistic Regression', 'accuracy': '0.895', 'precision_macro': '0.9026446253698647', 'recall_macro': '0.9008674232279429', 'f1_macro': '0.9014785999538764'}
{'model': 'Gradient Boosting', 'accuracy': '0.938', 'precision_macro': '0.9498293172499156', 'recall_macro': '0.9379747832608407', 'f1_macro': '0.9432488176322879'}

3. LABELLED TEST DATA VALIDATION
Prediction columns: ['actual', 'random_forest', 'xgboost', 'svm', 'logistic_regression', 'gradient_boosting']
Prediction rows: 2000
[WARNING] Recognized actual/predicted label columns were not found.
[NOT VERIFIED] Detection accuracy cannot be independently calculated from recognized labelled columns.

4. PRODUCTION DATABASE VERIFICATION
[PASS] logs: 33 records
[PASS] alerts: 27 records
[PASS] processing_results: 16 records
Processing attempts: 16
Successful: 15
Failed: 1
Actual processing success rate: 93.75%

5. DASHBOARD API VERIFICATION
[PASS] /health: HTTP 200
[PASS] /api/dashboard: HTTP 200
[PASS] /api/alerts: HTTP 200
[PASS] /api/logs: HTTP 200
[PASS] /api/ml-predictions: HTTP 200
Dashboard logs processed: 15
Dashboard success rate: 93.75%
Dashboard predicted threat events: 7
[PASS] Dashboard processing values compared with database.

## Verification limitations
- A successful API test does not prove the browser UI layout visually.
- Detection accuracy requires valid labelled actual and predicted outcomes.
- Processing success rate and ML detection accuracy are different metrics.
