import unittest
import os
import sys
import tempfile
import shutil
import pandas as pd

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import sys; sys.path.append('ai-integration'); from integrator import AIIntegrator


class TestAIIntegration(unittest.TestCase):
    def setUp(self):
        """Set up test environment."""
        # Create temporary directory for models
        self.temp_dir = tempfile.mkdtemp()
        self.ai_integrator = AIIntegrator(model_dir=self.temp_dir)
    
    def tearDown(self):
        """Clean up test environment."""
        shutil.rmtree(self.temp_dir)
    
    def test_feature_extraction(self):
        """Test feature extraction from log entries."""
        log_entry = {
            'ip': '192.168.1.100',
            'method': 'GET',
            'path': '/admin',
            'status_code': 401,
            'user_agent': 'Mozilla/5.0 (compatible browser)',
            'timestamp': '2025-01-15 14:30:00'
        }
        
        features = self.ai_integrator.prepare_features(log_entry)
        
        self.assertIsInstance(features, type(pd.DataFrame().values))
        self.assertEqual(features.shape[0], 1)  # Single sample
        self.assertEqual(features.shape[1], 7)  # 7 features
        
        # Check specific feature values
        self.assertEqual(features[0][0], 401)  # Status code
        self.assertEqual(features[0][3], 1)     # GET method = 1
        self.assertEqual(features[0][5], 1)     # Private IP = 1
    
    def test_generate_training_data(self):
        """Test training data generation."""
        training_data, labels = self.ai_integrator.generate_training_data(num_samples=100)
        
        self.assertIsInstance(training_data, pd.DataFrame)
        self.assertEqual(len(training_data), 100)
        self.assertEqual(len(labels), 100)
        self.assertTrue(set(labels).issubset({'normal', 'suspicious', 'malicious'}))
        
        # Check data structure
        required_columns = ['ip', 'method', 'path', 'status_code', 'user_agent', 'timestamp']
        for col in required_columns:
            self.assertIn(col, training_data.columns)
    
    def test_anomaly_detection_training(self):
        """Test anomaly detection model training."""
        training_data, _ = self.ai_integrator.generate_training_data(num_samples=50)
        
        result = self.ai_integrator.train_anomaly_detector(training_data)
        
        self.assertTrue(result)
        self.assertIsNotNone(self.ai_integrator.anomaly_detector)
    
    def test_threat_classification_training(self):
        """Test threat classification model training."""
        training_data, labels = self.ai_integrator.generate_training_data(num_samples=50)
        
        result = self.ai_integrator.train_threat_classifier(training_data, labels)
        
        self.assertTrue(result)
        self.assertIsNotNone(self.ai_integrator.threat_classifier)
        self.assertTrue(self.ai_integrator.is_trained)
    
    def test_comprehensive_analysis(self):
        """Test comprehensive log entry analysis."""
        # Train models first
        training_data, labels = self.ai_integrator.generate_training_data(num_samples=100)
        self.ai_integrator.train_anomaly_detector(training_data)
        self.ai_integrator.train_threat_classifier(training_data, labels)
        
        # Test analysis
        suspicious_log = {
            'ip': '10.0.0.1',
            'method': 'POST',
            'path': '/admin/delete_all',
            'status_code': 403,
            'user_agent': 'suspicious_bot',
            'timestamp': '2025-01-15 14:30:00'
        }
        
        results = self.ai_integrator.analyze_log_entry(suspicious_log)
        
        self.assertIn('timestamp', results)
        self.assertIn('log_entry', results)
        self.assertIn('anomaly_detected', results)
        self.assertIn('threat_classification', results)
        self.assertIn('risk_score', results)
        self.assertIn('recommendations', results)
        
        # Should have high risk score for suspicious activity
        self.assertGreater(results['risk_score'], 0.3)
    
    def test_rule_based_analysis(self):
        """Test rule-based threat detection."""
        # Test admin path access
        admin_log = {
            'ip': '192.168.1.100',
            'method': 'GET',
            'path': '/admin/users',
            'status_code': 200,
            'user_agent': 'Mozilla/5.0',
            'timestamp': '2025-01-15 14:30:00'
        }
        
        score = self.ai_integrator._apply_rules(admin_log)
        self.assertGreater(score, 0)
        
        # Test SQL injection attempt
        sql_injection_log = {
            'ip': '10.0.0.1',
            'method': 'GET',
            'path': '/search?q=SELECT * FROM users',
            'status_code': 200,
            'user_agent': 'AttackBot',
            'timestamp': '2025-01-15 14:30:00'
        }
        
        score = self.ai_integrator._apply_rules(sql_injection_log)
        self.assertGreater(score, 0.4)
    
    def test_model_persistence(self):
        """Test model saving and loading."""
        # Train a simple model
        training_data, labels = self.ai_integrator.generate_training_data(num_samples=50)
        self.ai_integrator.train_anomaly_detector(training_data)
        self.ai_integrator.train_threat_classifier(training_data, labels)
        
        # Save models
        self.ai_integrator.save_models()
        
        # Check that model files were created
        model_files = ['anomaly_detector.pkl', 'threat_classifier.pkl', 'scaler.pkl', 'label_encoder.pkl']
        for file_name in model_files:
            file_path = os.path.join(self.temp_dir, file_name)
            self.assertTrue(os.path.exists(file_path), f"Model file {file_name} was not created")
        
        # Create new integrator and load models
        new_integrator = AIIntegrator(model_dir=self.temp_dir)
        
        # Should have loaded the models
        self.assertIsNotNone(new_integrator.anomaly_detector)
        self.assertIsNotNone(new_integrator.threat_classifier)
        self.assertTrue(new_integrator.is_trained)
    
    def test_recommendations_generation(self):
        """Test security recommendations generation."""
        high_risk_results = {
            'risk_score': 0.8,
            'anomaly_detected': True,
            'threat_classification': {'confidence': 0.9},
            'log_entry': {'status_code': 401}
        }
        
        recommendations = self.ai_integrator._generate_recommendations(high_risk_results)
        
        self.assertIsInstance(recommendations, list)
        self.assertGreater(len(recommendations), 0)
        
        # Should have high-risk recommendations
        recommendations_text = ' '.join(recommendations)
        self.assertIn('High risk', recommendations_text)


class TestAIIntegrationEdgeCases(unittest.TestCase):
    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.ai_integrator = AIIntegrator(model_dir=self.temp_dir)
    
    def tearDown(self):
        """Clean up test environment."""
        shutil.rmtree(self.temp_dir)
    
    def test_empty_log_entry(self):
        """Test handling of empty log entries."""
        empty_log = {}
        features = self.ai_integrator.prepare_features(empty_log)
        
        self.assertIsInstance(features, type(pd.DataFrame().values))
        self.assertEqual(features.shape[0], 1)
    
    def test_malformed_data(self):
        """Test handling of malformed data."""
        malformed_log = {
            'status_code': 'invalid',
            'timestamp': 'not_a_timestamp',
            'method': None,
            'path': None
        }
        
        # Should not raise exception
        features = self.ai_integrator.prepare_features(malformed_log)
        self.assertIsInstance(features, type(pd.DataFrame().values))
    
    def test_analysis_without_trained_models(self):
        """Test analysis when models are not trained."""
        log_entry = {
            'ip': '192.168.1.1',
            'method': 'GET',
            'path': '/',
            'status_code': 200,
            'user_agent': 'Mozilla/5.0',
            'timestamp': '2025-01-15 14:30:00'
        }
        
        # Should not crash even without trained models
        results = self.ai_integrator.analyze_log_entry(log_entry)
        
        self.assertIsInstance(results, dict)
        self.assertIn('risk_score', results)


if __name__ == '__main__':
    unittest.main()
