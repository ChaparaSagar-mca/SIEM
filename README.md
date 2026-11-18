# SIEM Lite 🛡️

A lightweight Security Information and Event Management (SIEM) system with AI-powered threat detection capabilities.

![SIEM Lite Dashboard](https://via.placeholder.com/800x400/4CAF50/FFFFFF?text=SIEM+Lite+Dashboard)

## 🌟 Features

- **Real-time Log Processing**: Continuous monitoring and analysis of system logs
- **AI-Powered Threat Detection**: Machine learning models for anomaly detection and threat classification
- **Interactive Dashboard**: React-based web interface for monitoring and analysis
- **REST API**: Comprehensive API for integration with other security tools
- **Alert Management**: Real-time alerts with severity classification
- **Docker Support**: Easy deployment with Docker and Docker Compose
- **Extensible Architecture**: Modular design for easy customization and extension

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Log Sources   │───▶│  Log Collector  │───▶│   AI Analysis   │
│                 │    │                 │    │                 │
│ • Web Servers   │    │ • File Tailing  │    │ • Anomaly Det.  │
│ • Applications  │    │ • Log Parsing   │    │ • Threat Class. │
│ • System Logs   │    │ • Data Cleaning │    │ • Risk Scoring  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                        │
                                                        ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Web Dashboard  │◀───│   Flask API     │◀───│   Database      │
│                 │    │                 │    │                 │
│ • Real-time UI  │    │ • RESTful API   │    │ • SQLite        │
│ • Charts/Graphs │    │ • Alert Mgmt    │    │ • Logs & Alerts │
│ • Alert Display │    │ • Health Check  │    │ • Configuration │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🚀 Quick Start

### Prerequisites

- **Python 3.9+**
- **Node.js 18+**
- **npm or yarn**
- **Docker** (optional)

### 1. Clone and Setup

```bash
# Clone the repository
git clone https://github.com/bbetre/siem-lite-project.git
cd siem-lite-project

# Run the automated setup script
chmod +x scripts/setup.sh
./scripts/setup.sh
```

### 2. Start the Application

```bash
# Start full-stack development environment
python3 scripts/run_dev.py full

# Or start components individually:
python3 scripts/run_dev.py backend   # Flask API server
python3 scripts/run_dev.py frontend  # React development server
```

### 3. Access the Application

- **Dashboard**: http://localhost:3000
- **API**: http://localhost:5000
- **Health Check**: http://localhost:5000/health

## 🐳 Docker Deployment

### Development
```bash
# Start with development profile
docker-compose up siem-app redis

# Or with React dev server
docker-compose --profile dev up
```

### Production
```bash
# Build and start production services
docker-compose up -d siem-app redis
```

### With Monitoring
```bash
# Include Prometheus and Grafana
docker-compose --profile monitoring up -d
```

## 📊 Usage Examples

### API Endpoints

```bash
# Get dashboard data
curl http://localhost:5000/api/dashboard

# Get alerts with pagination
curl "http://localhost:5000/api/alerts?page=1&per_page=10&severity=high"

# Analyze custom log entry
curl -X POST http://localhost:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "192.168.1.100",
    "method": "GET",
    "path": "/admin",
    "status_code": 401,
    "user_agent": "Mozilla/5.0",
    "timestamp": "2025-01-15 14:30:00"
  }'
```

### Training AI Models

```bash
# Train models with synthetic data
python3 ai-integration/trainer.py

# Or use the development script
python3 scripts/run_dev.py train
```

## 🧪 Testing

```bash
# Run all tests
python3 scripts/run_dev.py test

# Run Python tests only
source .venv/bin/activate
python -m pytest tests/ -v

# Run React tests only
cd dashboard
npm test
```

## 📁 Project Structure

```
siem-lite-project/
├── agents/
│   ├── config.yaml         # Log collection configuration
│   ├── log_collector.py    # Main log collection engine
│   └── test_logs/         # Sample log files
├── ai-integration/
│   ├── integrator.py      # AI/ML integration module
│   └── trainer.py         # Model training script
├── dashboard/
│   ├── public/            # React public files
│   ├── src/              # React source code
│   │   └── App.js        # Main dashboard component
│   └── package.json      # React dependencies
├── server/
│   └── analyzer.py       # Flask API server
├── tests/
│   ├── test_agents.py    # Agent tests
│   ├── test_ai_integration.py # AI module tests
│   ├── test_dashboard.js # React component tests
│   └── test_server.py    # API tests
├── scripts/
│   ├── run_dev.py        # Development runner
│   └── setup.sh          # Setup script
├── docker-compose.yml    # Docker services
├── Dockerfile           # Container definition
├── requirements.txt     # Python dependencies
└── README.md           # This file
```

## 🔧 Configuration

### Environment Variables

Create a `.env` file:

```env
# Flask Configuration
FLASK_ENV=development
FLASK_DEBUG=1
DATABASE_URL=sqlite:///siem_data.db
LOG_LEVEL=INFO
SECRET_KEY=your-secret-key-here

# React Configuration
REACT_APP_API_URL=http://localhost:5000
```

### Log Sources Configuration

Edit `agents/config.yaml`:

```yaml
logs:
  - path: /var/log/nginx/access.log
    format: combined
  - path: /var/log/auth.log
    format: syslog
  - path: agents/test_logs/access.log
    format: combined
```

## 🤖 AI/ML Features

### Anomaly Detection
- **Algorithm**: Isolation Forest
- **Features**: IP patterns, request timing, status codes, path lengths
- **Training**: Unsupervised learning on normal traffic patterns

### Threat Classification
- **Algorithm**: Random Forest Classifier
- **Classes**: Normal, Suspicious, Malicious
- **Features**: 7-dimensional feature vector per log entry

### Rule-Based Analysis
- SQL injection detection
- Brute force attack identification
- Admin panel access monitoring
- Suspicious user agent detection

## 📈 Monitoring & Alerting

### Alert Severity Levels
- **High**: Immediate attention required (e.g., confirmed attacks)
- **Medium**: Suspicious activity (e.g., multiple failed logins)
- **Low**: Unusual but not necessarily malicious (e.g., new user agents)

### Dashboard Metrics
- Total alerts (24h)
- Logs processed
- Success rate
- Threat distribution
- Real-time log processing timeline

## 🔌 API Reference

### Core Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | System health check |
| GET | `/api/dashboard` | Dashboard overview data |
| GET | `/api/alerts` | Paginated alerts list |
| GET | `/api/logs` | Processed logs with pagination |
| POST | `/api/analyze` | Analyze custom log entry |

### Response Examples

**Dashboard Data**:
```json
{
  "alerts": {
    "total": 127,
    "high": 15,
    "medium": 42,
    "low": 70,
    "recent": [...]
  },
  "logs": {
    "processed": 15420,
    "errors": 23,
    "success_rate": 99.85
  },
  "threats": {
    "blocked": 89,
    "allowed": 15331
  }
}
```

## 🛠️ Development

### Adding New Features

1. **Log Sources**: Extend `agents/log_collector.py`
2. **AI Models**: Add to `ai-integration/integrator.py`
3. **API Endpoints**: Extend `server/analyzer.py`
4. **Dashboard Components**: Add to `dashboard/src/`

### Code Quality

```bash
# Python linting
flake8 .

# JavaScript/React linting
cd dashboard && npm run lint

# Type checking (if using TypeScript)
npm run type-check
```

## 📚 Documentation

- [API Documentation](docs/api.md)
- [Setup Guide](docs/setup_guide.md)
- [Module Documentation](docs/modules.md)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make changes and add tests
4. Run tests: `python3 scripts/run_dev.py test`
5. Commit changes: `git commit -am 'Add feature'`
6. Push to branch: `git push origin feature-name`
7. Create Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Issues**: Report bugs and request features via GitHub Issues
- **Documentation**: Check the `docs/` directory for detailed guides
- **Community**: Join discussions in GitHub Discussions

## 🗺️ Roadmap

- [ ] **v2.0**: Real-time streaming with Apache Kafka
- [ ] **v2.1**: Advanced ML models (Deep Learning)
- [ ] **v2.2**: Multi-tenant support
- [ ] **v2.3**: Cloud provider integrations (AWS, Azure, GCP)
- [ ] **v2.4**: Advanced visualization and reporting
- [ ] **v3.0**: Distributed deployment with Kubernetes
