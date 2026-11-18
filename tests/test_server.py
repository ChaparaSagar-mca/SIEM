import unittest
import os
import sys
import json
import tempfile
import shutil
from unittest.mock import patch, MagicMock

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server.analyzer import app, init_database, analyze_log_entry, store_alerts


class TestFlaskServer(unittest.TestCase):
    def setUp(self):
        """Set up test environment."""
        self.app = app.test_client()
        self.app.testing = True
        
        # Use in-memory database for testing
        app.config['DATABASE'] = ':memory:'
        
        with app.app_context():
            init_database()
    
    def test_health_check(self):
        """Test health check endpoint."""
        response = self.app.get('/health')
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.data)
        self.assertEqual(data['status'], 'healthy')
        self.assertIn('timestamp', data)
    
    def test_dashboard_endpoint_structure(self):
        """Test dashboard endpoint returns proper structure."""
        response = self.app.get('/api/dashboard')
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.data)
        
        # Check required keys
        required_keys = ['alerts', 'logs', 'threats', 'system']
        for key in required_keys:
            self.assertIn(key, data)
        
        # Check alerts structure
        alert_keys = ['total', 'high', 'medium', 'low', 'recent']
        for key in alert_keys:
            self.assertIn(key, data['alerts'])
        
        # Check logs structure
        log_keys = ['processed', 'errors', 'success_rate']
        for key in log_keys:
            self.assertIn(key, data['logs'])
    
    def test_alerts_endpoint(self):
        """Test alerts endpoint."""
        response = self.app.get('/api/alerts')
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.data)
        
        required_keys = ['alerts', 'total', 'page', 'per_page']
        for key in required_keys:
            self.assertIn(key, data)
        
        self.assertIsInstance(data['alerts'], list)
        self.assertIsInstance(data['total'], int)
    
    def test_alerts_endpoint_with_pagination(self):
        """Test alerts endpoint with pagination parameters."""
        response = self.app.get('/api/alerts?page=2&per_page=10')
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.data)
        self.assertEqual(data['page'], 2)
        self.assertEqual(data['per_page'], 10)
    
    def test_alerts_endpoint_with_severity_filter(self):
        """Test alerts endpoint with severity filter."""
        response = self.app.get('/api/alerts?severity=high')
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.data)
        self.assertIsInstance(data['alerts'], list)
    
    def test_logs_endpoint(self):
        """Test logs endpoint."""
        response = self.app.get('/api/logs')
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.data)
        
        required_keys = ['logs', 'total', 'page', 'per_page']
        for key in required_keys:
            self.assertIn(key, data)
        
        self.assertIsInstance(data['logs'], list)
        self.assertIsInstance(data['total'], int)
    
    def test_analyze_custom_log(self):
        """Test custom log analysis endpoint."""
        test_log = {
            'ip': '192.168.1.100',
            'method': 'GET',
            'path': '/admin',
            'status_code': 401,
            'user_agent': 'Mozilla/5.0',
            'timestamp': '2025-01-15 14:30:00'
        }
        
        response = self.app.post('/api/analyze',
                               data=json.dumps(test_log),
                               content_type='application/json')
        
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.data)
        self.assertIn('alerts_generated', data)
        self.assertIn('alerts', data)
    
    def test_analyze_empty_data(self):
        """Test analysis with empty data."""
        response = self.app.post('/api/analyze',
                               data='',
                               content_type='application/json')
        
        self.assertEqual(response.status_code, 400)
        
        data = json.loads(response.data)
        self.assertIn('error', data)


class TestLogAnalysis(unittest.TestCase):
    def test_analyze_normal_log_entry(self):
        """Test analysis of normal log entry."""
        normal_log = {
            'ip': '192.168.1.100',
            'method': 'GET',
            'path': '/home',
            'status_code': 200,
            'user_agent': 'Mozilla/5.0',
            'timestamp': '2025-01-15 14:30:00'
        }
        
        alerts = analyze_log_entry(normal_log)
        
        # Should generate few or no alerts for normal traffic
        self.assertIsInstance(alerts, list)
        self.assertEqual(len(alerts), 0)  # No alerts for normal traffic
    
    def test_analyze_suspicious_log_entry(self):
        """Test analysis of suspicious log entry."""
        suspicious_log = {
            'ip': '10.0.0.1',
            'method': 'GET',
            'path': '/admin',
            'status_code': 404,
            'user_agent': 'AttackBot',
            'timestamp': '2025-01-15 14:30:00'
        }
        
        alerts = analyze_log_entry(suspicious_log)
        
        self.assertIsInstance(alerts, list)
        self.assertGreater(len(alerts), 0)  # Should generate alerts
        
        # Check alert structure
        for alert in alerts:
            required_keys = ['severity', 'message', 'source', 'timestamp']
            for key in required_keys:
                self.assertIn(key, alert)
    
    def test_analyze_malicious_log_entry(self):
        """Test analysis of malicious log entry."""
        malicious_log = {
            'ip': '10.0.0.1',
            'method': 'POST',
            'path': '/admin/delete',
            'status_code': 401,
            'user_agent': 'MaliciousScript',
            'timestamp': '2025-01-15 14:30:00'
        }
        
        alerts = analyze_log_entry(malicious_log)
        
        self.assertIsInstance(alerts, list)
        self.assertGreater(len(alerts), 0)
        
        # Should have high severity alerts
        severity_levels = [alert['severity'] for alert in alerts]
        self.assertIn('high', severity_levels)
    
    def test_brute_force_detection(self):
        """Test brute force attack detection."""
        brute_force_log = {
            'ip': '10.0.0.1',
            'method': 'POST',
            'path': '/login',
            'status_code': 401,
            'user_agent': 'BruteForcer',
            'timestamp': '2025-01-15 14:30:00'
        }
        
        alerts = analyze_log_entry(brute_force_log)
        
        self.assertGreater(len(alerts), 0)
        
        # Check for brute force related messages
        messages = [alert['message'] for alert in alerts]
        brute_force_detected = any('brute force' in msg.lower() for msg in messages)
        self.assertTrue(brute_force_detected)
    
    def test_sql_injection_detection(self):
        """Test SQL injection detection."""
        sql_injection_log = {
            'ip': '10.0.0.1',
            'method': 'GET',
            'path': "/search?q='; DROP TABLE users; --",
            'status_code': 200,
            'user_agent': 'SQLBot',
            'timestamp': '2025-01-15 14:30:00'
        }
        
        alerts = analyze_log_entry(sql_injection_log)
        
        # Should detect suspicious SQL patterns in path
        self.assertGreater(len(alerts), 0)


class TestAlertStorage(unittest.TestCase):
    def setUp(self):
        """Set up test environment."""
        with app.app_context():
            init_database()
    
    def test_store_alerts(self):
        """Test alert storage functionality."""
        test_alerts = [
            {
                'severity': 'high',
                'message': 'Test alert 1',
                'source': '192.168.1.100',
                'timestamp': '2025-01-15 14:30:00'
            },
            {
                'severity': 'medium',
                'message': 'Test alert 2',
                'source': '192.168.1.101',
                'timestamp': '2025-01-15 14:31:00'
            }
        ]
        
        # Should not raise any exceptions
        store_alerts(test_alerts)
    
    def test_store_empty_alerts(self):
        """Test storing empty alert list."""
        # Should handle empty list gracefully
        store_alerts([])
    
    def test_store_none_alerts(self):
        """Test storing None alerts."""
        # Should handle None gracefully
        store_alerts(None)


class TestIntegrationWithMocks(unittest.TestCase):
    def setUp(self):
        """Set up test environment."""
        self.app = app.test_client()
        self.app.testing = True
    
    @patch('server.analyzer.log_collector')
    @patch('server.analyzer.ai_integrator')
    def test_server_initialization_with_mocks(self, mock_ai, mock_log_collector):
        """Test server initialization with mocked components."""
        # Mock the components to avoid real initialization
        mock_log_collector.return_value = MagicMock()
        mock_ai.return_value = MagicMock()
        
        # Test health endpoint works
        response = self.app.get('/health')
        self.assertEqual(response.status_code, 200)


if __name__ == '__main__':
    unittest.main()
