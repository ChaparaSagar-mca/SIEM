#!/bin/bash
# SIEM Lite Project Setup Script

set -e  # Exit on any error

echo "🚀 SIEM Lite Project Setup"
echo "=========================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Python 3 is installed
check_python() {
    print_status "Checking Python installation..."
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
        print_success "Python $PYTHON_VERSION found"
    else
        print_error "Python 3 is required but not installed"
        exit 1
    fi
}

# Check if Node.js is installed
check_node() {
    print_status "Checking Node.js installation..."
    if command -v node &> /dev/null; then
        NODE_VERSION=$(node --version)
        print_success "Node.js $NODE_VERSION found"
    else
        print_error "Node.js is required but not installed"
        print_status "Please install Node.js from https://nodejs.org/"
        exit 1
    fi
}

# Check if npm is installed
check_npm() {
    print_status "Checking npm installation..."
    if command -v npm &> /dev/null; then
        NPM_VERSION=$(npm --version)
        print_success "npm $NPM_VERSION found"
    else
        print_error "npm is required but not installed"
        exit 1
    fi
}

# Set up Python virtual environment
setup_python_env() {
    print_status "Setting up Python virtual environment..."
    
    if [ ! -d ".venv" ]; then
        python3 -m venv .venv
        print_success "Virtual environment created"
    else
        print_warning "Virtual environment already exists"
    fi
    
    # Activate virtual environment
    source .venv/bin/activate
    
    # Upgrade pip
    print_status "Upgrading pip..."
    pip install --upgrade pip
    
    # Install Python dependencies
    print_status "Installing Python dependencies..."
    if [ -f "requirements.txt" ]; then
        pip install -r requirements.txt
        print_success "Python dependencies installed"
    else
        print_error "requirements.txt not found"
        exit 1
    fi
}

# Set up Node.js dependencies
setup_node_env() {
    print_status "Setting up Node.js environment..."
    
    # Install root dependencies (if any)
    if [ -f "package.json" ]; then
        print_status "Installing root Node.js dependencies..."
        npm install
    fi
    
    # Install dashboard dependencies
    if [ -d "dashboard" ] && [ -f "dashboard/package.json" ]; then
        print_status "Installing dashboard dependencies..."
        cd dashboard
        npm install
        cd ..
        print_success "Dashboard dependencies installed"
    else
        print_warning "Dashboard package.json not found"
    fi
}

# Create necessary directories
setup_directories() {
    print_status "Creating necessary directories..."
    
    mkdir -p data
    mkdir -p logs
    mkdir -p models
    mkdir -p agents/test_logs
    mkdir -p monitoring
    
    print_success "Directories created"
}

# Create test log files
create_test_logs() {
    print_status "Creating test log files..."
    
    # Create sample access log
    cat > agents/test_logs/access.log << EOF
127.0.0.1 - - [08/Sep/2025:12:00:00 +0000] "GET /home HTTP/1.1" 200 1024 "-" "Mozilla/5.0"
192.168.1.100 - - [08/Sep/2025:12:01:00 +0000] "POST /login HTTP/1.1" 200 512 "-" "Mozilla/5.0"
10.0.0.1 - - [08/Sep/2025:12:02:00 +0000] "GET /admin HTTP/1.1" 401 0 "-" "AttackBot/1.0"
203.0.113.1 - - [08/Sep/2025:12:03:00 +0000] "GET /wp-admin HTTP/1.1" 404 0 "-" "BadBot/2.0"
192.168.1.50 - - [08/Sep/2025:12:04:00 +0000] "GET /dashboard HTTP/1.1" 200 2048 "-" "Mozilla/5.0"
EOF
    
    print_success "Test log files created"
}

# Create configuration files
create_configs() {
    print_status "Creating configuration files..."
    
    # Create .env file if it doesn't exist
    if [ ! -f ".env" ]; then
        cat > .env << EOF
# SIEM Lite Configuration
FLASK_ENV=development
FLASK_DEBUG=1
DATABASE_URL=sqlite:///siem_data.db
LOG_LEVEL=INFO
SECRET_KEY=dev-secret-key-change-in-production
REACT_APP_API_URL=http://localhost:5000
EOF
        print_success ".env file created"
    else
        print_warning ".env file already exists"
    fi
    
    # Create gitignore additions
    if [ ! -f ".gitignore" ] || ! grep -q "siem_data.db" .gitignore; then
        cat >> .gitignore << EOF

# SIEM Lite specific
siem_data.db
*.db
models/*.pkl
logs/*.log
data/*
!data/.gitkeep
!logs/.gitkeep
.env
EOF
        print_success "Updated .gitignore"
    fi
}

# Run initial tests
run_tests() {
    print_status "Running initial tests..."
    
    source .venv/bin/activate
    
    # Test Python imports
    python3 -c "
import sys
sys.path.append('.')
try:
    from agents.log_collector import LogCollector
    import sys; sys.path.append('ai-integration'); from integrator import AIIntegrator
    print('✅ Python modules can be imported successfully')
except ImportError as e:
    print(f'❌ Import error: {e}')
    sys.exit(1)
"
    
    print_success "Basic tests passed"
}

# Train AI models
train_models() {
    print_status "Training AI models (this may take a few minutes)..."
    
    source .venv/bin/activate
    python3 ai-integration/trainer.py
    
    print_success "AI models trained"
}

# Main setup function
main() {
    echo "Starting SIEM Lite setup process..."
    
    # Check prerequisites
    check_python
    check_node
    check_npm
    
    # Set up environments
    setup_directories
    setup_python_env
    setup_node_env
    
    # Create necessary files
    create_test_logs
    create_configs
    
    # Run tests
    run_tests
    
    # Offer to train AI models
    echo
    read -p "Would you like to train AI models now? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        train_models
    else
        print_status "You can train AI models later by running: python3 ai-integration/trainer.py"
    fi
    
    echo
    print_success "🎉 SIEM Lite setup completed successfully!"
    echo
    echo "📋 Next steps:"
    echo "  1. Start development server: python3 scripts/run_dev.py full"
    echo "  2. Or start backend only: python3 scripts/run_dev.py backend"
    echo "  3. Or start frontend only: python3 scripts/run_dev.py frontend"
    echo "  4. Run tests: python3 scripts/run_dev.py test"
    echo "  5. Build for production: python3 scripts/run_dev.py build"
    echo
    echo "🌐 Access points:"
    echo "  - Dashboard: http://localhost:3000"
    echo "  - API: http://localhost:5000"
    echo "  - Health check: http://localhost:5000/health"
    echo
}

# Run main function
main "$@"

#!/bin/bash
echo "Setting up..."