import unittest
import os
import sys
import tempfile
import shutil

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.log_collector import LogCollector


class TestLogCollector(unittest.TestCase):
    def setUp(self):
        """Set up test environment."""
        # Create a temporary directory for test files
        self.temp_dir = tempfile.mkdtemp()
        self.test_log = os.path.join(self.temp_dir, "access.log")
        
        # Create test log file
        with open(self.test_log, 'w') as f:
            f.write('127.0.0.1 - - [07/Sep/2025:16:41:00 +0000] "GET /cart HTTP/1.1" 200 1024 "-" "Mozilla/5.0"\n')
            f.write('192.168.1.100 - - [07/Sep/2025:16:42:00 +0000] "POST /login HTTP/1.1" 200 512 "-" "Mozilla/5.0"\n')
        
        # Create test config
        self.test_config = {
            "logs": [
                {"path": self.test_log, "format": "combined"}
            ]
        }
        
        self.collector = LogCollector()
        self.collector.config = self.test_config
        self.collector.log_sources = self.test_config.get("logs", [])
    
    def tearDown(self):
        """Clean up test environment."""
        shutil.rmtree(self.temp_dir)

    def test_load_config(self):
        """Test config loading."""
        # Test with nonexistent config (should use default)
        config = self.collector.load_config("nonexistent_config.yaml")
        self.assertIn("logs", config)
        
        # Test the loaded config structure
        self.assertIsInstance(config["logs"], list)

    def test_process_logs_with_queue_data(self):
        """Test log processing from queue."""
        # Manually add log entries to queue
        test_logs = [
            '127.0.0.1 - - [07/Sep/2025:16:41:00 +0000] "GET /cart HTTP/1.1" 200 1024 "-" "Mozilla/5.0"',
            '192.168.1.100 - - [07/Sep/2025:16:42:00 +0000] "POST /login HTTP/1.1" 200 512 "-" "Mozilla/5.0"'
        ]
        
        for log in test_logs:
            self.collector.log_queue.put(log)
        
        df = self.collector.process_logs()
        
        self.assertFalse(df.empty, "DataFrame should not be empty")
        self.assertIn("ip", df.columns, "IP column should exist")
        self.assertIn("user_agent", df.columns, "User agent column should exist")
        self.assertIn("method", df.columns, "Method column should exist")
        self.assertIn("path", df.columns, "Path column should exist")
        self.assertIn("status", df.columns, "Status column should exist")
        
        # Check specific values
        self.assertEqual(df.iloc[0]["path"], "/cart", "Path should match test log")
        self.assertEqual(df.iloc[0]["ip"], "127.0.0.1", "IP should match test log")
        self.assertEqual(df.iloc[1]["method"], "POST", "Method should match test log")
    
    def test_log_regex_parsing(self):
        """Test log regex parsing functionality."""
        from agents.log_collector import LOG_REGEX
        
        test_log = '127.0.0.1 - - [07/Sep/2025:16:41:00 +0000] "GET /cart HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'
        match = LOG_REGEX.match(test_log)
        
        self.assertIsNotNone(match, "Log should match regex")
        
        groups = match.groupdict()
        self.assertEqual(groups['ip'], '127.0.0.1')
        self.assertEqual(groups['method'], 'GET')
        self.assertEqual(groups['path'], '/cart')
        self.assertEqual(groups['status'], '200')
    
    def test_malformed_log_handling(self):
        """Test handling of malformed log entries."""
        # Add malformed log to queue
        malformed_log = "This is not a valid log entry"
        self.collector.log_queue.put(malformed_log)
        
        # Should not crash and should return empty DataFrame
        df = self.collector.process_logs()
        self.assertTrue(df.empty, "DataFrame should be empty for malformed logs")


if __name__ == "__main__":
    unittest.main()
