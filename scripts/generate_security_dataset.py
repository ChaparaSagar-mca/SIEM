
import csv
import json
import random
import argparse
from pathlib import Path
from datetime import datetime, timedelta

SEED = 42
RECORDS_PER_CAMPAIGN = 5

# Preserve the original project class distribution.
DISTRIBUTION = {
    "normal": 3000,
    "failed_authentication": 1500,
    "suspicious_network_activity": 1500,
    "malware_related_activity": 1500,
    "unauthorized_access": 1500,
    "anomalous_system_activity": 1000,
}

FIELDS = [
    "event_id", "campaign_id", "timestamp",
    "source_ip", "destination_ip", "username",
    "event_source", "event_type", "protocol",
    "source_port", "destination_port",
    "bytes_sent", "bytes_received", "duration_seconds",
    "auth_result", "failed_login_count",
    "process_name", "file_operation", "privilege_level",
    "connection_count", "unique_destination_count",
    "cpu_percent", "memory_percent", "process_count",
    "label",
]

# Overlapping statistical profiles, not fixed class rules.
# Each feature also receives campaign-level and event-level noise.
PROFILES = {
    "normal": {
        "failed": (0.9, 1.3),
        "connections": (4.5, 3.0),
        "destinations": (2.5, 1.8),
        "sent": (5500, 3500),
        "received": (7000, 4500),
        "duration": (14, 12),
        "cpu": (40, 17),
        "memory": (46, 17),
        "processes": (95, 35),
    },
    "failed_authentication": {
        "failed": (3.4, 2.5),
        "connections": (5.0, 3.5),
        "destinations": (2.8, 2.0),
        "sent": (5500, 3800),
        "received": (6800, 4500),
        "duration": (16, 14),
        "cpu": (42, 18),
        "memory": (47, 18),
        "processes": (98, 38),
    },
    "suspicious_network_activity": {
        "failed": (1.2, 1.5),
        "connections": (7.0, 4.5),
        "destinations": (4.0, 2.8),
        "sent": (8500, 6000),
        "received": (8000, 5500),
        "duration": (22, 18),
        "cpu": (44, 19),
        "memory": (48, 18),
        "processes": (100, 40),
    },
    "malware_related_activity": {
        "failed": (1.1, 1.5),
        "connections": (5.0, 3.5),
        "destinations": (2.8, 2.0),
        "sent": (7500, 5500),
        "received": (7500, 5000),
        "duration": (19, 16),
        "cpu": (50, 21),
        "memory": (54, 20),
        "processes": (108, 42),
    },
    "unauthorized_access": {
        "failed": (2.2, 2.0),
        "connections": (5.0, 3.5),
        "destinations": (2.8, 2.0),
        "sent": (6000, 4200),
        "received": (7200, 4800),
        "duration": (17, 15),
        "cpu": (45, 19),
        "memory": (49, 19),
        "processes": (100, 40),
    },
    "anomalous_system_activity": {
        "failed": (1.1, 1.5),
        "connections": (5.5, 4.0),
        "destinations": (2.7, 2.0),
        "sent": (6000, 4500),
        "received": (9000, 6500),
        "duration": (21, 18),
        "cpu": (53, 21),
        "memory": (57, 21),
        "processes": (115, 48),
    },
}


def bounded_int(mean, std, minimum, maximum):
    value = random.gauss(mean, std)
    return max(minimum, min(maximum, round(value)))


def bounded_float(mean, std, minimum, maximum):
    value = random.gauss(mean, std)
    return round(max(minimum, min(maximum, value)), 2)


def random_ip():
    prefixes = [
        "10.0", "172.16", "192.168",
        "198.51", "203.0"
    ]
    prefix = random.choice(prefixes)
    return f"{prefix}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def random_auth_result(label):
    # All classes can contain success, failure and non-auth events.
    probabilities = {
        "normal": [0.75, 0.08, 0.17],
        "failed_authentication": [0.25, 0.65, 0.10],
        "suspicious_network_activity": [0.55, 0.20, 0.25],
        "malware_related_activity": [0.55, 0.15, 0.30],
        "unauthorized_access": [0.45, 0.35, 0.20],
        "anomalous_system_activity": [0.55, 0.15, 0.30],
    }

    return random.choices(
        ["success", "failure", "not_applicable"],
        weights=probabilities[label]
    )[0]


def make_event(label, campaign_id, event_number, profile):
    timestamp = profile["start_time"] + timedelta(
        minutes=random.randint(0, 180)
    )

    stats = PROFILES[label]

    # Campaign offsets create related but non-identical events.
    # They are random and do not directly encode the class.
    row = {
        "event_id": f"EVT-{campaign_id}-{event_number}",
        "campaign_id": campaign_id,
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),

        "source_ip": random_ip(),
        "destination_ip": random_ip(),

        "username": random.choice([
            "admin", "user01", "guest", "service",
            "root", "operator", "unknown"
        ]),

        # Metadata is generated independently of the target.
        "event_source": random.choice([
            "authentication", "network", "endpoint",
            "system", "web_server"
        ]),
        "event_type": random.choice([
            "login", "connection", "process",
            "file_activity", "system_activity", "web_request"
        ]),

        "protocol": random.choice([
            "TCP", "UDP", "HTTP", "HTTPS", "SSH", "DNS"
        ]),

        "source_port": random.randint(1024, 65535),
        "destination_port": random.choice([
            22, 53, 80, 135, 443, 445, 3306, 3389, 8080
        ]),

        "bytes_sent": bounded_int(
            stats["sent"][0] + profile["sent_offset"],
            stats["sent"][1], 100, 50000
        ),
        "bytes_received": bounded_int(
            stats["received"][0] + profile["received_offset"],
            stats["received"][1], 100, 50000
        ),
        "duration_seconds": bounded_float(
            stats["duration"][0] + profile["duration_offset"],
            stats["duration"][1], 0.1, 180
        ),

        "auth_result": random_auth_result(label),
        "failed_login_count": bounded_int(
            stats["failed"][0] + profile["failed_offset"],
            stats["failed"][1], 0, 15
        ),

        # These fields are not assigned using the threat label.
        "process_name": random.choice([
            "system", "browser", "python", "sshd",
            "powershell", "cmd", "unknown_process"
        ]),
        "file_operation": random.choice([
            "none", "read", "write", "execute", "modify", "delete"
        ]),
        "privilege_level": random.choice([
            "user", "standard", "admin", "root"
        ]),

        "connection_count": bounded_int(
            stats["connections"][0] + profile["connection_offset"],
            stats["connections"][1], 1, 50
        ),
        "unique_destination_count": bounded_int(
            stats["destinations"][0] + profile["destination_offset"],
            stats["destinations"][1], 1, 20
        ),

        "cpu_percent": bounded_float(
            stats["cpu"][0] + profile["cpu_offset"],
            stats["cpu"][1], 1, 100
        ),
        "memory_percent": bounded_float(
            stats["memory"][0] + profile["memory_offset"],
            stats["memory"][1], 1, 100
        ),
        "process_count": bounded_int(
            stats["processes"][0] + profile["process_offset"],
            stats["processes"][1], 10, 400
        ),

        "label": label,
    }

    return row


def generate_campaign_profile():
    return {
        "start_time": datetime(2025, 1, 1) + timedelta(
            minutes=random.randint(0, 60 * 24 * 365)
        ),
        "failed_offset": random.gauss(0, 0.5),
        "connection_offset": random.gauss(0, 1.0),
        "destination_offset": random.gauss(0, 0.5),
        "sent_offset": random.gauss(0, 500),
        "received_offset": random.gauss(0, 500),
        "duration_offset": random.gauss(0, 2),
        "cpu_offset": random.gauss(0, 2),
        "memory_offset": random.gauss(0, 2),
        "process_offset": random.gauss(0, 5),
    }


def generate_dataset():
    random.seed(SEED)

    records = []
    campaign_number = 0

    for label, total in DISTRIBUTION.items():
        if total % RECORDS_PER_CAMPAIGN != 0:
            raise ValueError(
                f"{label} count must be divisible by "
                f"{RECORDS_PER_CAMPAIGN}"
            )

        campaign_count = total // RECORDS_PER_CAMPAIGN

        for _ in range(campaign_count):
            campaign_number += 1
            campaign_id = f"CMP-{campaign_number:05d}"
            profile = generate_campaign_profile()

            for event_number in range(RECORDS_PER_CAMPAIGN):
                records.append(
                    make_event(
                        label,
                        campaign_id,
                        event_number + 1,
                        profile
                    )
                )

    random.shuffle(records)

    for index, record in enumerate(records, start=1):
        record["event_id"] = f"SEC-{index:05d}"

    return records


def validate_dataset(records):
    if len(records) != sum(DISTRIBUTION.values()):
        raise ValueError("Unexpected total record count.")

    campaign_labels = {}
    campaign_sizes = {}

    for record in records:
        campaign_id = record["campaign_id"]
        label = record["label"]

        campaign_labels.setdefault(campaign_id, set()).add(label)
        campaign_sizes[campaign_id] = (
            campaign_sizes.get(campaign_id, 0) + 1
        )

    if any(len(labels) != 1 for labels in campaign_labels.values()):
        raise ValueError("A campaign contains multiple labels.")

    if any(size != RECORDS_PER_CAMPAIGN
           for size in campaign_sizes.values()):
        raise ValueError("Unexpected number of events in a campaign.")

    actual_counts = {}
    for record in records:
        label = record["label"]
        actual_counts[label] = actual_counts.get(label, 0) + 1

    if actual_counts != DISTRIBUTION:
        raise ValueError("Class distribution does not match target.")

    return actual_counts, len(campaign_labels)


def main():
    parser = argparse.ArgumentParser()

    # New filename protects the original experiment.
    parser.add_argument(
        "--output",
        default="datasets/security_events_v2.csv"
    )
    parser.add_argument(
        "--summary-output",
        default="results/security_v2/dataset_summary_v2.json"
    )

    args = parser.parse_args()

    output_path = Path(args.output)
    summary_path = Path(args.summary_output)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)

    records = generate_dataset()
    actual_counts, campaign_count = validate_dataset(records)

    with output_path.open(
        "w", newline="", encoding="utf-8"
    ) as file:
        writer = csv.DictWriter(file, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(records)

    summary = {
        "dataset": str(output_path),
        "total_records": len(records),
        "unique_campaigns": campaign_count,
        "records_per_campaign": RECORDS_PER_CAMPAIGN,
        "random_seed": SEED,
        "synthetic_data": True,
        "class_distribution": actual_counts,
        "feature_policy": (
            "Exclude identifiers, timestamp, raw IP addresses, "
            "event_source, event_type, process_name, file_operation "
            "and label from model inputs during this experiment. "
            "Audit remaining features for shortcuts before "
            "interpreting model performance."
        ),
        "note": (
            "Synthetic proof-of-concept data. Statistical overlap "
            "does not establish real-world validity."
        )
    }

    with summary_path.open("w", encoding="utf-8") as file:
        json.dump(summary, file, indent=4)

    print("Revised dataset generation completed.")
    print(f"Output: {output_path}")
    print(f"Total records: {len(records)}")
    print(f"Unique campaigns: {campaign_count}")
    print(f"Events per campaign: {RECORDS_PER_CAMPAIGN}")
    print("\nCategory distribution:")

    for label, count in actual_counts.items():
        print(f"{label}: {count}")

    print(f"\nSummary saved: {summary_path}")


if __name__ == "__main__":
    main()
