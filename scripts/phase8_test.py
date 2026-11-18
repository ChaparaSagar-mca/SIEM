
import os
import sqlite3
import tempfile
import importlib.util
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parent.parent
ANALYZER_PATH = PROJECT_DIR / "server" / "analyzer.py"
REAL_DB_PATH = PROJECT_DIR / "siem_data.db"


def read_real_processing_counts():
    """Read production processing statistics without modifying the database."""
    if not REAL_DB_PATH.exists():
        return None

    conn = sqlite3.connect(
        f"file:{REAL_DB_PATH.as_posix()}?mode=ro",
        uri=True
    )

    try:
        row = conn.execute("""
            SELECT
                COUNT(*),
                SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END),
                SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END)
            FROM processing_results
        """).fetchone()

        total = int(row[0] or 0)
        successful = int(row[1] or 0)
        failed = int(row[2] or 0)

        rate = (
            successful / total * 100
            if total > 0 else 0.0
        )

        return {
            "total": total,
            "successful": successful,
            "failed": failed,
            "rate": rate
        }

    finally:
        conn.close()


def main():
    if not ANALYZER_PATH.exists():
        print("[FAIL] server/analyzer.py not found.")
        return 1

    before = read_real_processing_counts()

    print("\n[PRODUCTION DATABASE - BEFORE TEST]")

    if before is not None:
        print(
            f"Processing success rate: "
            f"{before['successful']}/{before['total']} = "
            f"{before['rate']:.2f}%"
        )
    else:
        print("[WARNING] Production database not found.")

    # Import the existing backend.
    spec = importlib.util.spec_from_file_location(
        "analyzer",
        ANALYZER_PATH
    )

    analyzer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(analyzer)

    app = analyzer.app
    app.config["TESTING"] = True

    checks = []

    old_cwd = os.getcwd()

    try:
        with tempfile.TemporaryDirectory(
            ignore_cleanup_errors=True
        ) as temp_dir:
            os.chdir(temp_dir)

            # Initialize the isolated test database.
            analyzer.init_database()

            client = app.test_client()
            # Initialize an isolated test database.

            analyzer.init_database()

            client = app.test_client()

            # Test normal event.
            normal_response = client.post(
                "/api/analyze",
                json={
                    "ip": "198.51.100.98",
                    "status_code": 200,
                    "path": "/home",
                    "method": "GET",
                    "user_agent": "Phase8-Test"
                }
            )

            normal_ok = (
                normal_response.status_code == 200
                and normal_response.get_json() is not None
                and normal_response.get_json().get("alerts_generated") == 0
            )

            checks.append((
                "Normal event produces no security alerts",
                normal_ok
            ))

            # Test suspicious event.
            suspicious_response = client.post(
                "/api/analyze",
                json={
                    "ip": "198.51.100.99",
                    "status_code": 401,
                    "path": "/login",
                    "method": "POST",
                    "user_agent": "Phase8-Test"
                }
            )

            suspicious_data = suspicious_response.get_json() or {}

            suspicious_ok = (
                suspicious_response.status_code == 200
                and suspicious_data.get("alerts_generated") == 2
            )

            checks.append((
                "Suspicious login generates two alerts",
                suspicious_ok
            ))

            # Verify alerts are stored in the temporary database.
            temp_db_path = Path(temp_dir) / "siem_data.db"

            if temp_db_path.exists():
                temp_conn = sqlite3.connect(temp_db_path)

                alert_rows = temp_conn.execute("""
                    SELECT severity, message, source
                    FROM alerts
                    ORDER BY id
                """).fetchall()

                temp_conn.close()

                persistence_ok = (
                    len(alert_rows) == 2
                    and {
                        row[0].lower()
                        for row in alert_rows
                    } == {"high", "medium"}
                    and all(
                        row[2] == "198.51.100.99"
                        for row in alert_rows
                    )
                )

            else:
                persistence_ok = False

            checks.append((
                "Suspicious-event alerts are stored in SQLite",
                persistence_ok
            ))

            # Check core API routes.
            for route in (
                "/health",
                "/api/dashboard",
                "/api/alerts",
                "/api/logs",
                "/api/ml-predictions"
            ):
                response = client.get(route)

                checks.append((
                    f"GET {route} returns HTTP 200",
                    response.status_code == 200
                ))

                if route == "/api/dashboard" and response.status_code == 200:
                    dashboard_data = response.get_json() or {}

                    numeric_rate = isinstance(
                        dashboard_data.get(
                            "logs", {}
                        ).get("success_rate"),
                        (int, float)
                    )

                    checks.append((
                        "Dashboard processing rate is numeric",
                        numeric_rate
                    ))

            
            # Check prediction-based threat metric fields.
            dashboard_response = client.get("/api/dashboard")

            if dashboard_response.status_code == 200:
                threat_data = (
                    dashboard_response.get_json() or {}
                ).get("threats", {})

                prediction_fields_exist = (
                    "total_predictions" in threat_data
                    and "predicted_threat_events" in threat_data
                    and "predicted_threat_percentage" in threat_data
                    and "detection_rate" not in threat_data
                )

                
                checks.append((
                    "Threat metrics use correct prediction-based field names",
                    prediction_fields_exist
                ))

    finally:
        os.chdir(old_cwd)

    # Audit hard-coded dashboard values.



    # Audit hard-coded dashboard values.
    source = ANALYZER_PATH.read_text(encoding="utf-8")

    static_flags = []

    hardcoded_values = (
        ('"blocked": 89', "Threats Blocked = 89"),
        ('"allowed": 15331', "Allowed = 15331"),
        ('"cpu": 45', "CPU = 45"),
        ('"memory": 67', "Memory = 67"),
        ('"disk": 23', "Disk = 23"),
        ('"uptime": "15d 7h 23m"', "Uptime")
    )

    for code_value, description in hardcoded_values:
        if code_value in source:
            static_flags.append(description)

    print("\n[STATIC/METRIC AUDIT]")

    if static_flags:
        for item in static_flags:
            print("[ACTION REQUIRED]", item)
    else:
        print("[PASS] No listed hard-coded dashboard values found.")

    print(
        "[ACTION REQUIRED] A prediction-based threat share "
        "is not a validated detection rate without ground-truth labels."
    )

    # Verify production database was not changed.
    after = read_real_processing_counts()
    unchanged = before == after

    print("\n[PRODUCTION DATABASE SAFETY]")

    if unchanged:
        print("[PASS] Real processing history unchanged.")
    else:
        print("[FAIL] Real processing history changed.")

    if after is not None:
        print(
            f"Final processing rate: "
            f"{after['successful']}/{after['total']} = "
            f"{after['rate']:.2f}% "
            f"({after['failed']} failed)"
        )

    failed_checks = [
        label
        for label, passed in checks
        if not passed
    ]

    print("\n" + "=" * 62)

    if failed_checks or not unchanged:
        print("PHASE 8 RESULT: SOME CHECKS NEED ATTENTION")
        print("=" * 62)
        return 1

    print("PHASE 8 RESULT: BACKEND FUNCTIONAL CHECKS PASSED")
    print("Static dashboard metrics and detection-rate validation")
    print("remain separate tasks.")
    print("=" * 62)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
