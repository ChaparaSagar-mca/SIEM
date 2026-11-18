#!/usr/bin/env python3
"""Development runner script for SIEM Lite."""

import os
import sys
import subprocess
import argparse
import time
import signal
from threading import Thread

def run_command(command, name, cwd=None):
    """Run a command in a subprocess."""
    print(f"\n🚀 Starting {name}...")
    try:
        process = subprocess.Popen(
            command,
            shell=True,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1
        )
        
        # Print output in real-time
        for line in process.stdout:
            print(f"[{name}] {line.strip()}")
        
        process.wait()
        
    except KeyboardInterrupt:
        print(f"\n⚠️ Stopping {name}...")
        process.terminate()
        process.wait()
    except Exception as e:
        print(f"❌ Error running {name}: {e}")

def setup_environment():
    """Set up the development environment."""
    print("🔧 Setting up development environment...")
    
    # Create necessary directories
    os.makedirs('data', exist_ok=True)
    os.makedirs('logs', exist_ok=True)
    os.makedirs('models', exist_ok=True)
    os.makedirs('agents/test_logs', exist_ok=True)
    
    # Create test log file if it doesn't exist
    test_log_path = 'agents/test_logs/access.log'
    if not os.path.exists(test_log_path):
        with open(test_log_path, 'w') as f:
            f.write('127.0.0.1 - - [08/Sep/2025:12:00:00 +0000] "GET /home HTTP/1.1" 200 1024 "-" "Mozilla/5.0"\n')
            f.write('192.168.1.100 - - [08/Sep/2025:12:01:00 +0000] "POST /login HTTP/1.1" 200 512 "-" "Mozilla/5.0"\n')
            f.write('10.0.0.1 - - [08/Sep/2025:12:02:00 +0000] "GET /admin HTTP/1.1" 401 0 "-" "AttackBot/1.0"\n')
    
    print("✅ Environment setup complete!")

def run_backend():
    """Run the Flask backend server."""
    # Activate virtual environment and run server
    if os.name == 'nt':  # Windows
        activate_script = '.venv\\Scripts\\activate'
        command = f'{activate_script} && python server/analyzer.py'
    else:  # Unix/Linux/macOS
        activate_script = 'source .venv/bin/activate'
        command = f'{activate_script} && python server/analyzer.py'
    
    run_command(command, "Backend", cwd='.')

def run_frontend():
    """Run the React frontend development server."""
    run_command("npm start", "Frontend", cwd='dashboard')

def run_tests():
    """Run all tests."""
    print("🧪 Running tests...")
    
    # Run Python tests
    if os.name == 'nt':  # Windows
        python_test_cmd = 'source .venv/bin/activate && python -m pytest tests/ -v'
    else:  # Unix/Linux/macOS
        python_test_cmd = 'source .venv/bin/activate && python -m pytest tests/ -v'
    
    run_command(python_test_cmd, "Python Tests", cwd='.')
    
    # Run React tests
    run_command("npm test -- --watchAll=false", "React Tests", cwd='dashboard')

def train_ai_models():
    """Train AI models."""
    print("🤖 Training AI models...")
    
    if os.name == 'nt':  # Windows
        command = 'source .venv/bin/activate && python ai-integration/trainer.py'
    else:  # Unix/Linux/macOS
        command = 'source .venv/bin/activate && python ai-integration/trainer.py'
    
    run_command(command, "AI Training", cwd='.')

def run_full_stack():
    """Run both frontend and backend simultaneously."""
    print("🏗️ Starting full-stack development environment...")
    
    # Start processes in threads
    backend_thread = Thread(target=run_backend)
    frontend_thread = Thread(target=run_frontend)
    
    backend_thread.daemon = True
    frontend_thread.daemon = True
    
    backend_thread.start()
    time.sleep(3)  # Give backend time to start
    frontend_thread.start()
    
    try:
        # Keep main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Shutting down development servers...")
        print("✅ Development environment stopped.")

def build_production():
    """Build for production."""
    print("🏭 Building for production...")
    
    # Build React app
    run_command("npm run build", "React Build", cwd='dashboard')
    
    print("✅ Production build complete!")

def main():
    parser = argparse.ArgumentParser(description='SIEM Lite Development Runner')
    parser.add_argument('command', choices=[
        'setup', 'backend', 'frontend', 'full', 'test', 'train', 'build'
    ], help='Command to run')
    
    args = parser.parse_args()
    
    print("🔰 SIEM Lite Development Runner")
    print("=" * 40)
    
    try:
        if args.command == 'setup':
            setup_environment()
        elif args.command == 'backend':
            run_backend()
        elif args.command == 'frontend':
            run_frontend()
        elif args.command == 'full':
            setup_environment()
            run_full_stack()
        elif args.command == 'test':
            run_tests()
        elif args.command == 'train':
            train_ai_models()
        elif args.command == 'build':
            build_production()
    
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
