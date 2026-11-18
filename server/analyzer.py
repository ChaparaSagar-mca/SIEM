from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
import json
import hashlib
import pandas as pd
import sqlite3
from datetime import datetime, timedelta
import logging
from threading import Thread
import time
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agents.log_collector import LogCollector
# Import AI integrator (handle dash in directory name)
import sys
import os
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'ai-integration'))
from integrator import AIIntegrator

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder='../dashboard/build', static_url_path='')
CORS(app, origins=["http://localhost:3000", "http://localhost:5000"])

# Global variables
log_collector = None
ai_integrator = None


def init_database():
    """Initialize SQLite database for logs, alerts and ML predictions."""
    conn = sqlite3.connect('siem_data.db')
    c = conn.cursor()

    try:
        # 1. Create logs table
        c.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                ip TEXT,
                method TEXT,
                path TEXT,
                status_code INTEGER,
                user_agent TEXT,
                severity TEXT DEFAULT 'info',
                processed_at TEXT DEFAULT CURRENT_TIMESTAMP,
                event_hash TEXT
            )
        ''')

        # 2. Create alerts table
        c.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                source TEXT,
                resolved BOOLEAN DEFAULT FALSE,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Processing attempts and their actual outcomes
        c.execute('''
            CREATE TABLE IF NOT EXISTS processing_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                log_id INTEGER,
                status TEXT NOT NULL CHECK(status IN ('success', 'failed')),
                error_message TEXT,
                processed_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # 3. Create ML predictions table
        c.execute('''
            CREATE TABLE IF NOT EXISTS ml_predictions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                log_id INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                ip TEXT,
                random_forest TEXT,
                xgboost TEXT,
                svm TEXT,
                logistic_regression TEXT,
                gradient_boosting TEXT,
                FOREIGN KEY (log_id) REFERENCES logs(id)
            )
        ''')

        # 4. Add event_hash to an existing logs table if missing
        c.execute("PRAGMA table_info(logs)")
        columns = [row[1] for row in c.fetchall()]

        if "event_hash" not in columns:
            c.execute("ALTER TABLE logs ADD COLUMN event_hash TEXT")

        # 5. Backfill fingerprints without deleting old records
        c.execute("""
            SELECT id, timestamp, ip, method, path,
                status_code, user_agent, event_hash
            FROM logs
            ORDER BY id
        """)

        existing_rows = c.fetchall()
        seen_hashes = set()

        for row in existing_rows:
            (
                log_id, timestamp, ip, method, path,
                status_code, user_agent, event_hash
            ) = row

            if event_hash:
                seen_hashes.add(event_hash)
                continue

            fingerprint_data = json.dumps(
                [
                    timestamp, ip, method, path,
                    status_code, user_agent
                ],
                separators=(",", ":"),
                ensure_ascii=False
            )

            fingerprint = hashlib.sha256(
                fingerprint_data.encode("utf-8")
            ).hexdigest()

            # Only the first occurrence receives a fingerprint.
            if fingerprint not in seen_hashes:
                c.execute(
                    "UPDATE logs SET event_hash = ? WHERE id = ?",
                    (fingerprint, log_id)
                )
                seen_hashes.add(fingerprint)

        # 6. Prevent duplicate event fingerprints
        c.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_logs_event_hash
            ON logs(event_hash)
        """)

        conn.commit()
        logger.info("Database initialized successfully")

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


def analyze_log_entry(log_data):
    alerts = []

    status_code = str(log_data.get('status_code', '')).strip()
    path = log_data.get('path', '')
    ip = log_data.get('ip')
    timestamp = log_data.get('timestamp')

    if status_code == '404':
        if '/admin' in path or '/wp-admin' in path:
            alerts.append({
                'timestamp': timestamp,
                'severity': 'medium',
                'message': f'Admin page access attempt from {ip}',
                'source': ip
            })

    if status_code == '401':
        alerts.append({
            'timestamp': timestamp,
            'severity': 'high',
            'message': f'Unauthorized login attempt from {ip}',
            'source': ip
        })

    if status_code in ['401', '403'] and ip:
        alerts.append({
            'timestamp': timestamp,
            'severity': 'medium',
            'message': f'Potential brute force activity from {ip}',
            'source': ip
        })

    return alerts



def store_alerts(alerts):
    """Store alerts in database."""
    if not alerts:
        return

    conn = sqlite3.connect('siem_data.db')

    try:
        c = conn.cursor()

        for alert in alerts:
            alert_timestamp = (
                alert.get('timestamp')
                or datetime.now().isoformat()
            )

            c.execute('''
                INSERT INTO alerts (
                    timestamp,
                    severity,
                    message,
                    source
                )
                VALUES (?, ?, ?, ?)
            ''', (
                alert_timestamp,
                alert['severity'],
                alert['message'],
                alert['source']
            ))

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()




def log_processing_worker():
    """Process logs and record genuine, traceable processing outcomes."""
    global log_collector, ai_integrator

    while True:
        try:
            if log_collector:
                df = log_collector.process_logs()

                if df is not None and not df.empty:
                    df = df.rename(columns={"status": "status_code"})

                    required_columns = [
                        "timestamp", "ip", "method",
                        "path", "status_code", "user_agent"
                    ]

                    for column in required_columns:
                        if column not in df.columns:
                            df[column] = ""

                    df["status_code"] = (
                        pd.to_numeric(df["status_code"], errors="coerce")
                        .fillna(0)
                        .astype(int)
                    )

                    df = df[required_columns]

                    conn = sqlite3.connect("siem_data.db")
                    cursor = conn.cursor()

                    # Add event_hash to processing history if needed.
                    columns = {
                        row[1]
                        for row in cursor.execute(
                            "PRAGMA table_info(processing_results)"
                        ).fetchall()
                    }

                    if "event_hash" not in columns:
                        cursor.execute(
                            "ALTER TABLE processing_results "
                            "ADD COLUMN event_hash TEXT"
                        )
                        conn.commit()

                    prediction_count = 0
                    success_count = 0
                    failed_count = 0

                    try:
                        for _, row in df.iterrows():
                            event_hash = None
                            cursor.execute("SAVEPOINT log_processing")

                            try:
                                log_data = row.to_dict()

                                fingerprint_data = json.dumps(
                                    [
                                        str(log_data["timestamp"]),
                                        str(log_data["ip"]),
                                        str(log_data["method"]),
                                        str(log_data["path"]),
                                        int(log_data["status_code"]),
                                        str(log_data["user_agent"])
                                    ],
                                    separators=(",", ":"),
                                    ensure_ascii=False
                                )

                                event_hash = hashlib.sha256(
                                    fingerprint_data.encode("utf-8")
                                ).hexdigest()

                                cursor.execute("""
                                    INSERT INTO logs (
                                        timestamp, ip, method, path,
                                        status_code, user_agent, event_hash
                                    )
                                    VALUES (?, ?, ?, ?, ?, ?, ?)
                                    ON CONFLICT(event_hash) DO NOTHING
                                """, (
                                    str(log_data["timestamp"]),
                                    str(log_data["ip"]),
                                    str(log_data["method"]),
                                    str(log_data["path"]),
                                    int(log_data["status_code"]),
                                    str(log_data["user_agent"]),
                                    event_hash
                                ))

                                # Duplicate events are not new attempts.
                                if cursor.rowcount == 0:
                                    cursor.execute(
                                        "RELEASE SAVEPOINT log_processing"
                                    )
                                    continue

                                log_id = cursor.lastrowid

                                # Run all five ML comparison models.
                                if (
                                    ai_integrator
                                    and ai_integrator.comparison_models
                                ):
                                    predictions = (
                                        ai_integrator.predict_with_comparison_models(
                                            log_data
                                        )
                                    )

                                    model_names = [
                                        "Random Forest",
                                        "XGBoost",
                                        "SVM",
                                        "Logistic Regression",
                                        "Gradient Boosting"
                                    ]

                                    if predictions and all(
                                        name in predictions
                                        and len(predictions[name]) == 1
                                        for name in model_names
                                    ):
                                        cursor.execute("""
                                            INSERT INTO ml_predictions (
                                                log_id, timestamp, ip,
                                                random_forest, xgboost, svm,
                                                logistic_regression,
                                                gradient_boosting
                                            )
                                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                                        """, (
                                            log_id,
                                            str(log_data["timestamp"]),
                                            str(log_data["ip"]),
                                            predictions["Random Forest"][0],
                                            predictions["XGBoost"][0],
                                            predictions["SVM"][0],
                                            predictions["Logistic Regression"][0],
                                            predictions["Gradient Boosting"][0]
                                        ))

                                        prediction_count += 1

                                # Generate rule-based alerts.
                                alerts = analyze_log_entry(log_data)

                                for alert in alerts:
                                    cursor.execute("""
                                        INSERT INTO alerts (
                                            timestamp, severity, message, source
                                        )
                                        VALUES (?, ?, ?, ?)
                                    """, (
                                        alert["timestamp"],
                                        alert["severity"],
                                        alert["message"],
                                        alert["source"]
                                    ))

                                # Record successful processing.
                                cursor.execute("""
                                    INSERT INTO processing_results (
                                        log_id, event_hash, status
                                    )
                                    VALUES (?, ?, 'success')
                                """, (log_id, event_hash))

                                cursor.execute(
                                    "RELEASE SAVEPOINT log_processing"
                                )

                                # Persist each completed attempt.
                                conn.commit()
                                success_count += 1

                            except Exception as row_error:
                                # Roll back only this event.
                                try:
                                    cursor.execute(
                                        "ROLLBACK TO SAVEPOINT log_processing"
                                    )
                                    cursor.execute(
                                        "RELEASE SAVEPOINT log_processing"
                                    )
                                except sqlite3.Error:
                                    conn.rollback()

                                # Store failure outside the rolled-back savepoint.
                                cursor.execute("""
                                    INSERT INTO processing_results (
                                        log_id, event_hash, status,
                                        error_message
                                    )
                                    VALUES (NULL, ?, 'failed', ?)
                                """, (
                                    event_hash,
                                    str(row_error)[:1000]
                                ))

                                conn.commit()
                                failed_count += 1

                                logger.exception(
                                    "Failed to process individual log"
                                )

                    finally:
                        conn.close()

                    logger.info(
                        "Processing results: %s successful, %s failed, "
                        "%s ML predictions",
                        success_count,
                        failed_count,
                        prediction_count
                    )

            time.sleep(10)

        except Exception as e:
            logger.exception(
                "Error in log processing worker: %s", e
            )
            time.sleep(30)

@app.route('/')
def serve_dashboard():
    """Serve the React dashboard."""
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/health')
def health_check():
    """Health check endpoint."""
    return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat()})



@app.route('/api/dashboard')
def get_dashboard_data():
    """Return dashboard statistics from actual database records."""
    conn = None

    try:
        conn = sqlite3.connect("siem_data.db")
        conn.row_factory = sqlite3.Row

        # Alert statistics
        alert_stats = conn.execute("""
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN LOWER(severity) = 'high' THEN 1 ELSE 0 END) AS high,
                SUM(CASE WHEN LOWER(severity) = 'medium' THEN 1 ELSE 0 END) AS medium,
                SUM(CASE WHEN LOWER(severity) = 'low' THEN 1 ELSE 0 END) AS low
            FROM alerts
        """).fetchone()

        recent_alerts = conn.execute("""
            SELECT id, severity, message, source, timestamp, created_at
            FROM alerts
            ORDER BY created_at DESC
            LIMIT 10
        """).fetchall()

        # Actual log processing outcomes
        processing = conn.execute("""
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) AS successful,
                SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed
            FROM processing_results
        """).fetchone()

        total_attempts = int(processing["total"] or 0)
        successful = int(processing["successful"] or 0)
        failed = int(processing["failed"] or 0)

        success_rate = (
            (successful / total_attempts) * 100
            if total_attempts > 0 else 0.0
        )

        # Five-model prediction statistics
        predictions = conn.execute("""
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN
                    LOWER(COALESCE(random_forest, '')) NOT IN ('normal', '')
                    OR LOWER(COALESCE(xgboost, '')) NOT IN ('normal', '')
                    OR LOWER(COALESCE(svm, '')) NOT IN ('normal', '')
                    OR LOWER(COALESCE(logistic_regression, '')) NOT IN ('normal', '')
                    OR LOWER(COALESCE(gradient_boosting, '')) NOT IN ('normal', '')
                THEN 1 ELSE 0 END) AS threat_events
            FROM ml_predictions
        """).fetchone()

        prediction_total = int(predictions["total"] or 0)
        threat_events = int(predictions["threat_events"] or 0)

        predicted_threat_percentage = (
            (threat_events / prediction_total) * 100
            if prediction_total > 0 else 0.0
        )

        dashboard_data = {
            "alerts": {
                "total": int(alert_stats["total"] or 0),
                "high": int(alert_stats["high"] or 0),
                "medium": int(alert_stats["medium"] or 0),
                "low": int(alert_stats["low"] or 0),
                "recent": [dict(row) for row in recent_alerts]
            },
            "logs": {
                "total_attempts": total_attempts,
                "processed": successful,
                "errors": failed,
                "success_rate": round(success_rate, 2)
            },
            "threats": {
                "total_predictions": prediction_total,
                "predicted_threat_events": threat_events,
                "predicted_threat_percentage": round(
                    predicted_threat_percentage, 2
                )
            },
            "metrics_source": "SQLite database"
        }

        return jsonify(dashboard_data)

    except Exception as e:
        logger.exception("Error getting dashboard data")
        return jsonify({"error": str(e)}), 500

    finally:
        if conn is not None:
            conn.close()


@app.route('/api/alerts')
def get_alerts():
    """Get all alerts with pagination."""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        severity = request.args.get('severity', '')
        
        conn = sqlite3.connect('siem_data.db')
        
        query = '''
            SELECT id, timestamp, severity, message, source, resolved, created_at
            FROM alerts
        '''
        params = []
        
        if severity:
            query += ' WHERE severity = ?'
            params.append(severity)
        
        query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?'
        params.extend([per_page, (page - 1) * per_page])
        
        alerts = pd.read_sql_query(query, conn, params=params)
        
        # Get total count
        count_query = 'SELECT COUNT(*) as total FROM alerts'
        if severity:
            count_query += ' WHERE severity = ?'
            total_count = pd.read_sql_query(count_query, conn, params=[severity] if severity else [])
        else:
            total_count = pd.read_sql_query(count_query, conn)
        
        conn.close()
        
        return jsonify({
            "alerts": alerts.to_dict('records'),
            "total": int(total_count.iloc[0]['total']),
            "page": page,
            "per_page": per_page
        })
    
    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        return jsonify({"error": "Failed to fetch alerts"}), 500

@app.route('/api/logs')
def get_logs():
    """Get processed logs with pagination."""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        
        conn = sqlite3.connect('siem_data.db')
        
        logs = pd.read_sql_query('''
            SELECT id, timestamp, ip, method, path, status_code, user_agent, processed_at
            FROM logs
            ORDER BY processed_at DESC
            LIMIT ? OFFSET ?
        ''', conn, params=[per_page, (page - 1) * per_page])
        
        # Get total count
        total_count = pd.read_sql_query('SELECT COUNT(*) as total FROM logs', conn)
        
        conn.close()
        
        return jsonify({
            "logs": logs.to_dict('records'),
            "total": int(total_count.iloc[0]['total']),
            "page": page,
            "per_page": per_page
        })
    
    except Exception as e:
        logger.error(f"Error getting logs: {e}")
        return jsonify({"error": "Failed to fetch logs"}), 500

@app.route('/api/ml-predictions')
def get_ml_predictions():
    """Get stored predictions from all five ML classifiers."""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)

        page = max(1, page)
        per_page = min(max(1, per_page), 100)

        conn = sqlite3.connect('siem_data.db')

        predictions = pd.read_sql_query('''
            SELECT
                id,
                log_id,
                timestamp,
                ip,
                random_forest,
                xgboost,
                svm,
                logistic_regression,
                gradient_boosting
            FROM ml_predictions
            ORDER BY id DESC
            LIMIT ? OFFSET ?
        ''', conn, params=[per_page, (page - 1) * per_page])

        total_count = pd.read_sql_query(
            'SELECT COUNT(*) AS total FROM ml_predictions',
            conn
        )

        conn.close()

        return jsonify({
            "predictions": predictions.to_dict('records'),
            "total": int(total_count.iloc[0]['total']),
            "page": page,
            "per_page": per_page
        })

    except Exception as e:
        logger.exception("Error getting ML predictions: %s", e)
        return jsonify({"error": "Failed to fetch ML predictions"}), 500



@app.route('/api/analyze', methods=['POST'])
def analyze_custom_log():
    """Analyze custom log data."""
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        alerts = analyze_log_entry(data)
        
        # Store the analysis results
        store_alerts(alerts)
        
        return jsonify({
            "alerts_generated": len(alerts),
            "alerts": alerts
        })
    
    except Exception as e:
        logger.error(f"Error analyzing custom log: {e}")
        return jsonify({"error": "Failed to analyze log"}), 500

def initialize_components():
    """Initialize all SIEM components."""
    global log_collector, ai_integrator
    
    try:
        # Initialize database
        init_database()
        
        # Initialize log collector
        log_collector = LogCollector()
        logger.info("Log collector initialized")
        log_collector.start()
        
        # Initialize AI integrator
        try:
            ai_integrator = AIIntegrator()
            logger.info("AI integrator initialized")
        except Exception as e:
            logger.warning(f"AI integrator initialization failed: {e}")
        
        # Start log processing worker
        worker_thread = Thread(target=log_processing_worker, daemon=True)
        worker_thread.start()
        logger.info("Log processing worker started")
        
    except Exception as e:
        logger.error(f"Failed to initialize components: {e}")
        raise

if __name__ == '__main__':
    try:
        initialize_components()
        logger.info("Starting SIEM Lite server...")
        app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)
    except Exception as e:
        logger.error(f"Failed to start server: {e}")
        sys.exit(1)
