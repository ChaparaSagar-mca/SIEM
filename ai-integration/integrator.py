import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import pickle
import os
import logging
from datetime import datetime
import json

logger = logging.getLogger(__name__)


class AIIntegrator:
    def __init__(self, model_dir=None):
        """Initialize AI integrator with machine learning models."""

        # Get the project root directory
        project_root = os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))
        )

        # Set the default model directory
        if model_dir is None:
            model_dir = os.path.join(project_root, "models")

        self.model_dir = os.path.abspath(model_dir)

                # Initialize legacy models
        self.anomaly_detector = None
        self.threat_classifier = None

        # Initialize five comparison models
        self.comparison_models = {}

        # Class names used by the comparison models
        self.comparison_class_names = []
        # Initialize scalers and encoder
        self.anomaly_scaler = StandardScaler()
        self.classifier_scaler = StandardScaler()
        self.label_encoder = LabelEncoder()

        self.is_trained = False

        # Create model directory if it does not exist
        os.makedirs(self.model_dir, exist_ok=True)

                # Load existing and comparison models
        self.load_models()
        self.load_comparison_models()
    def predict_with_comparison_models(self, log_data):
        """Predict HTTP log classes using all five comparison models."""

        if not self.comparison_models:
            logger.warning("No comparison models are loaded.")
            return {}

        try:
            features = self.prepare_features(log_data)

            predictions = {}

            for model_name, model in self.comparison_models.items():
                predicted_ids = model.predict(features)

                predicted_classes = [
                    self.comparison_class_names[int(class_id)]
                    for class_id in predicted_ids
                ]

                predictions[model_name] = predicted_classes

            return predictions

        except Exception as e:
            logger.exception("Comparison model prediction failed: %s", e)
            return {}

    
    
    def prepare_features(self, log_data):
        """Extract a consistent numerical feature matrix from HTTP logs."""

        if isinstance(log_data, pd.DataFrame):
            records = log_data.to_dict(orient="records")
        elif isinstance(log_data, dict):
            records = [log_data]
        else:
            raise TypeError(
                "log_data must be a pandas DataFrame or dictionary."
            )

        return np.asarray(
            [self._extract_single_features(record) for record in records],
            dtype=float
        )

    def _extract_single_features(self, log_entry):
        """Extract 14 label-independent HTTP security features."""

        import re
        from urllib.parse import unquote, urlsplit

        # Read HTTP request information
        path = str(log_entry.get("path", "/"))
        method = str(log_entry.get("method", "GET")).upper()
        user_agent = str(log_entry.get("user_agent", ""))

        # 1. HTTP status code
        try:
            status_code = int(
                log_entry.get("status_code", log_entry.get("status", 200))
            )
        except (ValueError, TypeError):
            status_code = 200

        # 2. Hour: Apache timestamp, ISO timestamp, or HH:MM
        timestamp = str(log_entry.get("timestamp", ""))
        hour = 12

        try:
            cleaned = timestamp.strip().strip("[]")

            try:
                hour = datetime.strptime(
                    cleaned, "%d/%b/%Y:%H:%M:%S %z"
                ).hour
            except ValueError:
                try:
                    hour = datetime.fromisoformat(
                        cleaned.replace("Z", "+00:00")
                    ).hour
                except ValueError:
                    match = re.search(r"\b(\d{1,2}):\d{2}\b", cleaned)
                    if match:
                        hour = int(match.group(1))

            if not 0 <= hour <= 23:
                hour = 12

        except (ValueError, TypeError):
            hour = 12

        # Parse and decode the request target
        try:
            parsed = urlsplit(path)
            decoded_path = unquote(path).lower()
            decoded_target = unquote(
                parsed.path + "?" + parsed.query
            ).lower()
        except ValueError:
            decoded_path = path.lower()
            decoded_target = decoded_path

        query_present = int("?" in path and bool(path.split("?", 1)[1]))

        # 3. Request path length
        path_length = len(path)

        # 4-8. HTTP method indicators
        method_features = [
            int(method == "GET"),
            int(method == "POST"),
            int(method == "PUT"),
            int(method == "DELETE"),
            int(method not in {"GET", "POST", "PUT", "DELETE"})
        ]

        # 9. User-agent length
        user_agent_length = len(user_agent)

        # 10. Query-string indicator
        # 11. SQL injection indicators
        sqli_patterns = [
            r"\bunion\s+(all\s+)?select\b",
            r"\bselect\b.+\bfrom\b",
            r"\bor\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
            r"(--|%2d%2d|/\*|\*/)",
            r"\bsleep\s*\(",
            r"\bdrop\s+table\b"
        ]

        sqli_score = sum(
            bool(re.search(pattern, decoded_target, re.IGNORECASE))
            for pattern in sqli_patterns
        )

        # 12. Cross-site scripting indicators
        xss_patterns = [
            r"<\s*script\b",
            r"javascript\s*:",
            r"onerror\s*=",
            r"onload\s*=",
            r"<\s*iframe\b",
            r"document\.cookie"
        ]

        xss_score = sum(
            bool(re.search(pattern, decoded_target, re.IGNORECASE))
            for pattern in xss_patterns
        )

        # 13. Path traversal indicators
        traversal_score = sum([
            int("../" in decoded_path),
            int("..\\" in decoded_path),
            int("%2e%2e" in path.lower()),
            int("/etc/passwd" in decoded_path),
            int("/windows/win.ini" in decoded_path)
        ])

        # 14. Suspicious scanning indicators
        scanner_patterns = [
            "/wp-admin",
            "/wp-login.php",
            "/.env",
            "/phpmyadmin",
            "/xmlrpc.php",
            "/.git",
            "/server-status",
            "/admin"
        ]

        scanner_score = sum(
            pattern in decoded_path
            for pattern in scanner_patterns
        )

        return [
            status_code,
            hour,
            path_length,
            *method_features,
            user_agent_length,
            query_present,
            sqli_score,
            xss_score,
            traversal_score,
            scanner_score
        ]



    
    def train_anomaly_detector(self, training_data):
        """Train anomaly detection model."""
        try:
            features = self.prepare_features(training_data)
            
            # Scale features for anomaly detection
            features_scaled = self.anomaly_scaler.fit_transform(features)
            
            # Train Isolation Forest
            self.anomaly_detector = IsolationForest(
                contamination=0.1,  # Expect 10% anomalies
                random_state=42,
                n_estimators=100
            )
            
            self.anomaly_detector.fit(features_scaled)
            
            logger.info(f"Trained anomaly detector on {len(features)} samples")
            return True
            
        except Exception as e:
            logger.error(f"Error training anomaly detector: {e}")
            return False
    
    def train_threat_classifier(self, training_data, labels):
        """Train threat classification model."""
        try:
            features = self.prepare_features(training_data)
            
            # Scale features for threat classification
            features_scaled = self.classifier_scaler.fit_transform(features)
            
            # Encode labels
            labels_encoded = self.label_encoder.fit_transform(labels)
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                features_scaled, labels_encoded, test_size=0.2, random_state=42
            )
            
            # Train Random Forest classifier
            self.threat_classifier = RandomForestClassifier(
                n_estimators=100,
                random_state=42,
                max_depth=10
            )
            
            self.threat_classifier.fit(X_train, y_train)
            
            # Evaluate model
            y_pred = self.threat_classifier.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            
            logger.info(f"Trained threat classifier with {accuracy:.2f} accuracy")
            logger.info(f"Training samples: {len(X_train)}, Test samples: {len(X_test)}")
            
            self.is_trained = True
            return True
            
        except Exception as e:
            logger.error(f"Error training threat classifier: {e}")
            return False
    
    def detect_anomalies(self, log_data):
        """Detect anomalies in log data."""
        if self.anomaly_detector is None:
            return []
        
        try:
            features = self.prepare_features(log_data)
            features_scaled = self.anomaly_scaler.transform(features)
            
            predictions = self.anomaly_detector.predict(features_scaled)
            anomaly_scores = self.anomaly_detector.score_samples(features_scaled)
            
            anomalies = []
            if isinstance(log_data, pd.DataFrame):
                for i, (_, row) in enumerate(log_data.iterrows()):
                    if predictions[i] == -1:  # Anomaly detected
                        anomalies.append({
                            'log_entry': row.to_dict(),
                            'anomaly_score': float(anomaly_scores[i]),
                            'severity': 'high' if anomaly_scores[i] < -0.5 else 'medium'
                        })
            else:
                if predictions[0] == -1:
                    anomalies.append({
                        'log_entry': log_data,
                        'anomaly_score': float(anomaly_scores[0]),
                        'severity': 'high' if anomaly_scores[0] < -0.5 else 'medium'
                    })
            
            return anomalies
            
        except Exception as e:
            logger.error(f"Error detecting anomalies: {e}")
            return []
    
    
    def classify_threat(self, log_data):
        """Classify threat type using either a pipeline or legacy model."""
        if self.threat_classifier is None or not self.is_trained:
            return None

        try:
            features = self.prepare_features(log_data)

            # New deployment model: preprocessing is inside the pipeline.
            if hasattr(self.threat_classifier, "named_steps"):
                prediction = self.threat_classifier.predict(features)[0]
                probabilities = self.threat_classifier.predict_proba(features)[0]

            # Backward compatibility with the original classifier.
            else:
                features_scaled = self.classifier_scaler.transform(features)
                prediction = self.threat_classifier.predict(features_scaled)[0]
                probabilities = self.threat_classifier.predict_proba(
                    features_scaled
                )[0]

            threat_type = self.label_encoder.inverse_transform(
                [int(prediction)]
            )[0]

            confidence = float(np.max(probabilities))

            return {
                "threat_type": str(threat_type),
                "confidence": confidence,
                "all_probabilities": {
                    str(label): float(probability)
                    for label, probability in zip(
                        self.label_encoder.classes_,
                        probabilities
                    )
                }
            }

        except Exception as e:
            logger.error(f"Error classifying threat: {e}")
            return None

    
    
    def analyze_log_entry(self, log_entry):
        """Comprehensive analysis of a log entry."""
        results = {
            'timestamp': datetime.now().isoformat(),
            'log_entry': log_entry,
            'anomaly_detected': False,
            'threat_classification': None,
            'risk_score': 0.0,
            'recommendations': []
        }

        # Anomaly detection
        anomalies = self.detect_anomalies(log_entry)
        if anomalies:
            results['anomaly_detected'] = True
            results['anomaly_score'] = anomalies[0]['anomaly_score']
            results['risk_score'] += 0.5

        # Threat classification
        threat_result = self.classify_threat(log_entry)
        if threat_result:
            results['threat_classification'] = threat_result

            threat_type = threat_result.get('threat_type')
            confidence = threat_result.get('confidence', 0)

            if threat_type in ['suspicious', 'malicious'] and confidence > 0.7:
                results['risk_score'] += 0.3

        # Rule-based analysis
        rule_score = self._apply_rules(log_entry)
        results['risk_score'] += rule_score

        # Keep risk score between 0 and 1
        results['risk_score'] = min(
            max(results['risk_score'], 0.0), 1.0
        )

        # Generate recommendations
        results['recommendations'] = self._generate_recommendations(results)

        return results

    def _apply_rules(self, log_entry):
        """Apply rule-based threat detection."""
        score = 0.0

        status_code = str(log_entry.get('status_code', 200))
        path = log_entry.get('path', '').lower()
        method = log_entry.get('method', 'GET').upper()

        # High-risk patterns
        if status_code in ['401', '403']:
            score += 0.3

        if any(pattern in path for pattern in [
            '/admin', '/wp-admin', '/../', 'etc/passwd'
        ]):
            score += 0.4

        if any(pattern in path for pattern in [
            'script', 'select', 'union', 'drop', 'insert'
        ]):
            score += 0.5

        if method in ['PUT', 'DELETE'] and 'admin' in path:
            score += 0.3

        return min(score, 1.0)

    def _generate_recommendations(self, analysis_results):
        """Generate security recommendations based on analysis."""
        recommendations = []

        if analysis_results['risk_score'] > 0.7:
            recommendations.append(
                "High risk detected - immediate investigation required"
            )
            recommendations.append(
                "Consider blocking source IP after investigation"
            )

        if analysis_results['anomaly_detected']:
            recommendations.append(
                "Anomalous behavior detected - review access patterns"
            )

        threat = analysis_results.get('threat_classification') or {}
        threat_type = threat.get('threat_type')
        confidence = threat.get('confidence', 0)

        if threat_type in ['suspicious', 'malicious'] and confidence > 0.8:
            recommendations.append(
                "High confidence threat classification - investigate and apply appropriate countermeasures"
            )

        log_entry = analysis_results['log_entry']

        if str(log_entry.get('status_code', 200)) in ['401', '403']:
            recommendations.append(
                "Authentication failure detected - correlate repeated failures from the same IP"
            )

        return recommendations

    def save_models(self):
        """Save trained models and scalers to disk."""
        try:
            if self.anomaly_detector is not None:
                with open(os.path.join(self.model_dir, 'anomaly_detector.pkl'), 'wb') as f:
                    pickle.dump(self.anomaly_detector, f)

            if self.threat_classifier is not None:
                with open(os.path.join(self.model_dir, 'threat_classifier.pkl'), 'wb') as f:
                    pickle.dump(self.threat_classifier, f)

            with open(os.path.join(self.model_dir, 'anomaly_scaler.pkl'), 'wb') as f:
                pickle.dump(self.anomaly_scaler, f)

            with open(os.path.join(self.model_dir, 'classifier_scaler.pkl'), 'wb') as f:
                pickle.dump(self.classifier_scaler, f)

            if self.is_trained:
                with open(os.path.join(self.model_dir, 'label_encoder.pkl'), 'wb') as f:
                    pickle.dump(self.label_encoder, f)

            logger.info("Models and scalers saved successfully")

        except Exception as e:
            logger.error(f"Error saving models: {e}")

    def load_models(self):
        """Load trained models and scalers from disk."""
        try:
            anomaly_path = os.path.join(self.model_dir, 'anomaly_detector.pkl')
            if os.path.exists(anomaly_path):
                with open(anomaly_path, 'rb') as f:
                    self.anomaly_detector = pickle.load(f)
                    logger.info("Loaded anomaly detector")

            classifier_path = os.path.join(self.model_dir, 'threat_classifier.pkl')
            if os.path.exists(classifier_path):
                with open(classifier_path, 'rb') as f:
                    self.threat_classifier = pickle.load(f)
                    logger.info("Loaded threat classifier")

            anomaly_scaler_path = os.path.join(self.model_dir, 'anomaly_scaler.pkl')
            if os.path.exists(anomaly_scaler_path):
                with open(anomaly_scaler_path, 'rb') as f:
                    self.anomaly_scaler = pickle.load(f)
                    logger.info("Loaded anomaly scaler")

            classifier_scaler_path = os.path.join(self.model_dir, 'classifier_scaler.pkl')
            if os.path.exists(classifier_scaler_path):
                with open(classifier_scaler_path, 'rb') as f:
                    self.classifier_scaler = pickle.load(f)
                    logger.info("Loaded classifier scaler")

            encoder_path = os.path.join(self.model_dir, 'label_encoder.pkl')
            if os.path.exists(encoder_path):
                with open(encoder_path, 'rb') as f:
                    self.label_encoder = pickle.load(f)
                    self.is_trained = True
                    logger.info("Loaded label encoder")

        except Exception as e:
            logger.warning(f"Could not load existing models: {e}")

    
    def load_comparison_models(self):
        """Load the five independently trained comparison pipelines."""

        model_files = {
            "Random Forest": "random_forest.pkl",
            "XGBoost": "xgboost.pkl",
            "SVM": "svm.pkl",
            "Logistic Regression": "logistic_regression.pkl",
            "Gradient Boosting": "gradient_boosting.pkl"
        }

        summary_path = os.path.join(
            os.path.dirname(self.model_dir),
            "results",
            "model_artifacts_summary.json"
        )

        try:
            if not os.path.exists(summary_path):
                logger.warning(
                    "Comparison model summary not found: %s",
                    summary_path
                )
                return

            with open(summary_path, "r", encoding="utf-8") as file:
                summary = json.load(file)

            class_names = summary.get("class_names", [])
            feature_names = summary.get("feature_names", [])

            if len(class_names) != 3:
                raise ValueError(
                    "Expected three class names in model summary."
                )

            if len(feature_names) != 14:
                raise ValueError(
                    "Expected 14 features in model summary."
                )

            loaded_models = {}

            for model_name, filename in model_files.items():
                model_path = os.path.join(
                    self.model_dir,
                    filename
                )

                if not os.path.exists(model_path):
                    logger.warning(
                        "Model file missing: %s",
                        model_path
                    )
                    continue

                with open(model_path, "rb") as file:
                    model = pickle.load(file)

                if getattr(model, "n_features_in_", None) != 14:
                    raise ValueError(
                        "%s does not accept the expected 14 features."
                        % model_name
                    )

                loaded_models[model_name] = model
                logger.info("Loaded comparison model: %s", model_name)

            self.comparison_models = loaded_models
            self.comparison_class_names = class_names

            logger.info(
                "Loaded %s of 5 comparison models.",
                len(self.comparison_models)
            )

        except Exception as e:
            self.comparison_models = {}
            self.comparison_class_names = []
            logger.exception(
                "Could not load comparison models: %s",
                e
            )

    
    def generate_training_data(self, num_samples=1000):
        """Generate varied synthetic HTTP records for demonstration.

        These records are synthetic and must not be represented as
        real-world traffic or proof of real-world model performance.
        """

        rng = np.random.default_rng(42)

        num_samples = int(num_samples)

        if num_samples < 3:
            raise ValueError("num_samples must be at least 3.")

        # Preserve approximately 70/20/10 class proportions.
        normal_count = int(num_samples * 0.70)
        suspicious_count = int(num_samples * 0.20)
        malicious_count = num_samples - normal_count - suspicious_count

        classes = (
            ["normal"] * normal_count
            + ["suspicious"] * suspicious_count
            + ["malicious"] * malicious_count
        )

        rng.shuffle(classes)

        normal_paths = [
            "/", "/home", "/about", "/contact",
            "/products", "/products/12", "/search?q=books",
            "/api/data", "/api/users", "/login",
            "/admin", "/dashboard", "/profile",
            "/images/logo.png", "/robots.txt"
        ]

        suspicious_paths = [
            "/admin", "/wp-admin", "/wp-login.php",
            "/.env", "/phpmyadmin", "/server-status",
            "/backup.zip", "/old-login", "/api/users",
            "/search?q=admin", "/.git/config",
            "/robots.txt", "/login"
        ]

        malicious_paths = [
            "/search?q=1%20UNION%20SELECT%20password",
            "/product?id=1%20OR%201=1",
            "/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
            "/comment?text=%3Cimg%20src=x%20onerror=alert(1)%3E",
            "/download?file=../../etc/passwd",
            "/view?file=..%2F..%2Fetc%2Fpasswd",
            "/api/data?id=1",
            "/login",
            "/admin"
        ]

        methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]

        user_agents = [
            "Mozilla/5.0 Chrome/120.0",
            "Mozilla/5.0 Firefox/121.0",
            "Mozilla/5.0 Safari/605.1",
            "Mozilla/5.0 Edge/120.0",
            "curl/8.0",
            "python-requests/2.31",
            "Googlebot/2.1",
            "Wget/1.21",
            ""
        ]

        training_data = []

        for label in classes:

            # Normal traffic can still visit login/admin pages
            # and can occasionally receive error responses.
            if label == "normal":
                path = rng.choice(normal_paths)
                method = rng.choice(
                    methods,
                    p=[0.65, 0.25, 0.03, 0.01, 0.04, 0.02]
                )
                status_code = rng.choice(
                    [200, 201, 204, 301, 304, 400, 401, 403, 404, 500],
                    p=[0.60, 0.08, 0.04, 0.04, 0.08,
                       0.03, 0.03, 0.02, 0.06, 0.02]
                )

            # Suspicious traffic contains ambiguous scanning or
            # probing behaviour, not necessarily a confirmed exploit.
            elif label == "suspicious":
                path = rng.choice(suspicious_paths + normal_paths)
                method = rng.choice(methods)
                status_code = rng.choice(
                    [200, 301, 400, 401, 403, 404, 429, 500]
                )

            # Malicious traffic contains exploit-like request payloads.
            else:
                path = rng.choice(
                    malicious_paths,
                    p=[0.17, 0.17, 0.15, 0.12, 0.15,
                       0.10, 0.06, 0.04, 0.04]
                )
                method = rng.choice(
                    ["GET", "POST", "PUT", "DELETE"]
                )
                status_code = rng.choice(
                    [200, 400, 403, 404, 500]
                )

            # Use varied user agents across all classes.
            user_agent = rng.choice(user_agents)

            # Use varied timestamps in ISO format.
            day = int(rng.integers(1, 29))
            hour = int(rng.integers(0, 24))
            minute = int(rng.integers(0, 60))
            second = int(rng.integers(0, 60))

            timestamp = (
                f"2025-01-{day:02d} "
                f"{hour:02d}:{minute:02d}:{second:02d}"
            )

            # Do not use IP address as a class shortcut.
            ip = (
                f"192.168.{int(rng.integers(0, 256))}."
                f"{int(rng.integers(1, 255))}"
            )

            training_data.append({
                "ip": ip,
                "method": method,
                "path": path,
                "status_code": int(status_code),
                "user_agent": user_agent,
                "timestamp": timestamp
            })

        return pd.DataFrame(training_data), classes


# Hook to server for ML