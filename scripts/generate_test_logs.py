#!/usr/bin/env python3
"""
Test Log Generator for SIEM Lite
Generates realistic log entries for testing and development
"""

import random
import time
import sys
from datetime import datetime, timedelta
from faker import Faker
import os

fake = Faker()

# Common paths for web requests
COMMON_PATHS = [
    '/', '/home', '/about', '/contact', '/login', '/logout',
    '/api/users', '/api/data', '/api/status', '/dashboard',
    '/search', '/profile', '/settings', '/help', '/faq',
    '/products', '/services', '/blog', '/news', '/cart'
]

# Suspicious/malicious paths
SUSPICIOUS_PATHS = [
    '/admin', '/wp-admin', '/admin/login', '/admin/users',
    '/admin/config', '/phpmyadmin', '/.env', '/config.php',
    '/etc/passwd', '/../../../etc/passwd', '/admin/delete',
    '/api/admin', '/backup.sql', '/.git/config', '/shell.php',
    '/wp-config.php', '/admin.php', '/login.php?admin=true'
]

# SQL injection patterns
SQL_INJECTION_PATHS = [
    "/search?q=' OR 1=1--",
    "/login?user=admin'--",
    "/api/users?id=1' UNION SELECT * FROM passwords--",
    "/search?term='; DROP TABLE users; --",
    "/profile?id=1' OR '1'='1",
]

# User agents
NORMAL_USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101',
]

SUSPICIOUS_USER_AGENTS = [
    'AttackBot/1.0', 'SQLBot/2.0', 'HackTool', 'Penetrator',
    'curl/7.68.0', 'wget/1.20.3', 'python-requests/2.25.1',
    'Bot/malicious', 'Scanner/1.0', 'Exploit/test'
]

def generate_ip():
    """Generate realistic IP addresses."""
    ip_type = random.choice(['internal', 'external'])
    
    if ip_type == 'internal':
        # Generate internal IP addresses
        return f"192.168.{random.randint(1, 255)}.{random.randint(1, 254)}"
    else:
        # Generate external IP addresses (avoiding private ranges)
        first_octet = random.choice([203, 198, 185, 8, 74, 104, 208])
        return f"{first_octet}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 254)}"

def generate_timestamp():
    """Generate timestamp in log format."""
    # Generate timestamp within last 24 hours
    now = datetime.now()
    time_delta = timedelta(hours=random.randint(0, 24))
    log_time = now - time_delta
    return log_time.strftime("%d/%b/%Y:%H:%M:%S +0000")

def generate_normal_log():
    """Generate a normal log entry."""
    methods = ['GET', 'POST']
    method = random.choice(methods)
    path = random.choice(COMMON_PATHS)
    
    # Mostly successful status codes for normal traffic
    status_codes = [200, 200, 200, 200, 201, 204, 301, 302, 304]
    status = random.choice(status_codes)
    
    bytes_sent = random.randint(100, 5000)
    user_agent = random.choice(NORMAL_USER_AGENTS)
    ip = generate_ip()
    timestamp = generate_timestamp()
    
    return f'{ip} - - [{timestamp}] "{method} {path} HTTP/1.1" {status} {bytes_sent} "-" "{user_agent}"'

def generate_suspicious_log():
    """Generate a suspicious log entry."""
    methods = ['GET', 'POST', 'PUT', 'DELETE']
    method = random.choice(methods)
    
    # Mix of suspicious paths and SQL injection attempts
    if random.random() < 0.3:
        path = random.choice(SQL_INJECTION_PATHS)
    else:
        path = random.choice(SUSPICIOUS_PATHS)
    
    # More error status codes
    status_codes = [401, 403, 404, 500, 200]  # Include some 200s to make it realistic
    status = random.choice(status_codes)
    
    bytes_sent = random.randint(0, 500)  # Often smaller responses for failed requests
    user_agent = random.choice(SUSPICIOUS_USER_AGENTS + NORMAL_USER_AGENTS)
    
    # More likely to be external IPs
    if random.random() < 0.7:
        ip = generate_ip().replace('192.168', random.choice(['203.0', '198.51', '185.76']))
    else:
        ip = generate_ip()
        
    timestamp = generate_timestamp()
    
    return f'{ip} - - [{timestamp}] "{method} {path} HTTP/1.1" {status} {bytes_sent} "-" "{user_agent}"'

def generate_malicious_log():
    """Generate a clearly malicious log entry."""
    methods = ['POST', 'PUT', 'DELETE']
    method = random.choice(methods)
    
    # Clearly malicious paths
    malicious_paths = [
        '/admin/delete_all_users',
        '/admin/backdoor.php',
        '/shell.php?cmd=rm%20-rf%20/',
        '/admin/config?action=delete',
        '/.env?show=true',
        '/api/admin/users/delete/all'
    ]
    
    path = random.choice(malicious_paths + SQL_INJECTION_PATHS)
    
    # Mostly error codes
    status_codes = [401, 403, 500, 404]
    status = random.choice(status_codes)
    
    bytes_sent = random.randint(0, 100)
    user_agent = random.choice(SUSPICIOUS_USER_AGENTS)
    
    # External IPs only
    ip = f"{random.randint(1, 223)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 254)}"
    timestamp = generate_timestamp()
    
    return f'{ip} - - [{timestamp}] "{method} {path} HTTP/1.1" {status} {bytes_sent} "-" "{user_agent}"'

def generate_logs(output_file='/logs/access.log', num_logs=1000, append=True):
    """Generate and write logs to file."""
    mode = 'a' if append else 'w'
    
    print(f"Generating {num_logs} log entries to {output_file}")
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    with open(output_file, mode) as f:
        for i in range(num_logs):
            # Distribution: 70% normal, 20% suspicious, 10% malicious
            rand = random.random()
            
            if rand < 0.7:
                log_entry = generate_normal_log()
            elif rand < 0.9:
                log_entry = generate_suspicious_log()
            else:
                log_entry = generate_malicious_log()
            
            f.write(log_entry + '\n')
            
            # Print progress
            if (i + 1) % 100 == 0:
                print(f"Generated {i + 1}/{num_logs} logs...")
    
    print(f"✅ Successfully generated {num_logs} log entries")

def continuous_generation(output_file='/logs/access.log', delay=1):
    """Continuously generate logs for real-time testing."""
    print(f"Starting continuous log generation to {output_file}")
    print(f"Generating 1 log entry every {delay} seconds...")
    print("Press Ctrl+C to stop")
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    try:
        while True:
            rand = random.random()
            
            if rand < 0.7:
                log_entry = generate_normal_log()
            elif rand < 0.9:
                log_entry = generate_suspicious_log()
            else:
                log_entry = generate_malicious_log()
            
            with open(output_file, 'a') as f:
                f.write(log_entry + '\n')
            
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Generated: {log_entry[:100]}...")
            time.sleep(delay)
            
    except KeyboardInterrupt:
        print("\n✅ Log generation stopped")

def main():
    """Main function with command line options."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate test logs for SIEM Lite')
    parser.add_argument('--output', '-o', default='/logs/access.log', help='Output file path')
    parser.add_argument('--count', '-c', type=int, default=1000, help='Number of logs to generate')
    parser.add_argument('--continuous', action='store_true', help='Generate logs continuously')
    parser.add_argument('--delay', '-d', type=float, default=1.0, help='Delay between logs in continuous mode')
    parser.add_argument('--no-append', action='store_true', help='Overwrite output file instead of appending')
    
    args = parser.parse_args()
    
    print("🚀 SIEM Lite Test Log Generator")
    print("=" * 40)
    
    if args.continuous:
        continuous_generation(args.output, args.delay)
    else:
        generate_logs(args.output, args.count, not args.no_append)

if __name__ == '__main__':
    main()
