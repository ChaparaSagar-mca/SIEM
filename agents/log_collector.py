import os
import yaml
import pandas as pd
import re
from queue import Queue
import time
import threading
import tailer  # For real-time log tailing

# A more robust regex to parse common log format
LOG_REGEX = re.compile(
    r'(?P<ip>[\d\.]+) - - \[(?P<timestamp>.*?)\] "(?P<method>\w+) (?P<path>.*?) (?P<protocol>.*?)" (?P<status>\d{3}) (?P<bytes>\d+) ".*?" "(?P<user_agent>.*?)"'
)


class LogCollector:
    def __init__(self, config_path=None):
        if config_path is None:
            config_path = os.path.join(
                os.path.dirname(__file__), "config.yaml")
        self.config = self.load_config(config_path)
        self.log_queue = Queue()
        self.shutdown_event = threading.Event()
        self.log_sources = self.config.get("logs", [])
        
    def start(self):
        self.threads = []

        for log_source in self.log_sources:
            log_path = log_source.get("path")

            if log_path:
                thread = threading.Thread(
                    target=self._collect_logs_worker,
                    args=(log_path,),
                    daemon=True
                )

                thread.start()
                self.threads.append(thread)

                print(f"Started monitoring: {log_path}")


    def load_config(self, config_path: str) -> dict:
        """Load YAML config with log sources."""
        try:
            with open(config_path, 'r') as file:
                return yaml.safe_load(file) or {"logs": [{"path": "test_logs/access.log"}]}
        except FileNotFoundError:
            print(f"Config file {config_path} not found. Using default.")
            return {"logs": [{"path": "test_logs/access.log"}]}

    
    def _collect_logs_worker(self, log_file_path: str):
        """Read existing logs once, then continuously monitor new logs."""

        if os.path.isabs(log_file_path):
            log_file = log_file_path
        else:
            log_file = os.path.join(os.path.dirname(__file__), log_file_path)

        try:
            with open(log_file, "r", encoding="utf-8", errors="replace") as file:

                # First collect existing log entries.
                for line in file:
                    if self.shutdown_event.is_set():
                        return
                    if line.strip():
                        self.log_queue.put(line.strip())

                print(f"Collected existing logs from: {log_file}")

                # Then monitor newly appended entries.
                for line in tailer.follow(file):
                    if self.shutdown_event.is_set():
                        break
                    if line.strip():
                        self.log_queue.put(line.strip())

        except FileNotFoundError:
            print(f"Log file {log_file} not found.")
        except Exception as e:
            print(f"An error occurred while tailing log file: {e}")

        print(f"Collector worker for {log_file_path} is shutting down.")

    def process_logs(self):
        """Process logs into structured format."""
        logs = []
        while not self.log_queue.empty():
            log = self.log_queue.get()
            match = LOG_REGEX.match(log)
            if match:
                logs.append(match.groupdict())
            else:
                print(f"Could not parse log line: {log}")

        return pd.DataFrame(logs)

    def run(self):
        """Main loop to collect and process logs."""
        threads = []
        if not self.log_sources:
            print("No log sources configured. Exiting.")
            return

        for log_source in self.log_sources:
            log_path = log_source.get("path")
            if log_path:
                thread = threading.Thread(
                    target=self._collect_logs_worker, args=(log_path,))
                thread.start()
                threads.append(thread)
                print(f"Started monitoring: {log_path}")

        print("Log collector running...")
        while not self.shutdown_event.is_set():
            try:
                df = self.process_logs()
                if not df.empty:
                    print(f"Processed {len(df)} log entries.")
                    # In a real scenario, you'd send this to a database or a log management system
                    print(df.to_dict('records'))
                time.sleep(5)  # Process queue every 5 seconds.
            except KeyboardInterrupt:
                print("\nShutting down log collector.")
                self.shutdown_event.set()
                break


if __name__ == "__main__":
    collector = LogCollector()
    collector.run()
