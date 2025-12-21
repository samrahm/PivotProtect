"""
Generate dummy log data for performance testing
Creates log files with various sizes (10³, 10⁴, 10⁵ entries)
"""

import random
import os
from datetime import datetime, timedelta


class LogDataGenerator:
    """Generate realistic-looking server log entries"""
    
    def __init__(self, seed=42):
        random.seed(seed)
        self.start_time = datetime(2024, 1, 1, 9, 0, 0)
        
        # IP pools
        self.normal_ips = [f"192.168.{random.randint(1,255)}.{random.randint(1,255)}" for _ in range(100)]
        self.attacker_ips = [f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}" for _ in range(50)]
        
        # Endpoints
        self.normal_endpoints = [
            "/", "/home", "/about", "/contact", "/products", "/services",
            "/login", "/dashboard", "/profile", "/settings", "/help",
            "/api/v1/users", "/api/v1/data", "/static/css/style.css"
        ]
        self.suspicious_endpoints = [
            "/admin", "/../../../etc/passwd", "/config.php", "/.git/config",
            "/.env", "/backup.sql", "/api/v1/users?id=1' OR '1'='1"
        ]
    
    def generate_normal_entry(self, timestamp):
        ip = random.choice(self.normal_ips)
        method = random.choice(["GET", "POST"])
        endpoint = random.choice(self.normal_endpoints)
        status = random.choice([200, 200, 200, 201, 304])
        size = random.randint(100, 5000)
        return f'{ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "{method} {endpoint} HTTP/1.1" {status} {size} "-" "Mozilla/5.0"'
    
    def generate_attack_entry(self, timestamp, attack_type):
        ip = random.choice(self.attacker_ips)
        
        if attack_type == 'brute_force':
            return f'{ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "POST /login HTTP/1.1" 401 150 "-" "Python-requests/2.28"'
        elif attack_type == 'sql_injection':
            endpoint = "/api/user?id=1' OR '1'='1"
            return f'{ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET {endpoint} HTTP/1.1" 400 200 "-" "sqlmap/1.0"'
        elif attack_type == 'path_traversal':
            endpoint = random.choice(self.suspicious_endpoints)
            return f'{ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET {endpoint} HTTP/1.1" 403 100 "-" "curl/7.68"'
        elif attack_type == 'port_scan':
            endpoint = random.choice(self.normal_endpoints + self.suspicious_endpoints)
            return f'{ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET {endpoint} HTTP/1.1" {random.choice([200,404,403])} 100 "-" "Nmap/7.80"'
        else:
            return self.generate_normal_entry(timestamp)
    
    def generate_dataset(self, num_entries, attack_ratio=0.3):
        entries = []
        current_time = self.start_time
        num_attacks = int(num_entries * attack_ratio)
        num_normal = num_entries - num_attacks
        
        # Normal entries
        for _ in range(num_normal):
            entries.append(self.generate_normal_entry(current_time))
            current_time += timedelta(seconds=random.randint(1, 10))
        
        # Attack entries
        attack_types = ['brute_force', 'sql_injection', 'path_traversal', 'port_scan']
        remaining = num_attacks
        while remaining > 0:
            attack_type = random.choice(attack_types)
            if attack_type == 'brute_force':
                ip = random.choice(self.attacker_ips)
                count = min(random.randint(5, 15), remaining)
                for _ in range(count):
                    entries.append(self.generate_attack_entry(current_time, 'brute_force'))
                    current_time += timedelta(seconds=random.uniform(0.5, 2))
                remaining -= count
            elif attack_type == 'port_scan':
                count = min(random.randint(8, 15), remaining)
                for _ in range(count):
                    entries.append(self.generate_attack_entry(current_time, 'port_scan'))
                    current_time += timedelta(seconds=0.2)
                remaining -= count
            else:
                entries.append(self.generate_attack_entry(current_time, attack_type))
                current_time += timedelta(seconds=random.randint(1, 5))
                remaining -= 1
        
        random.shuffle(entries)
        return entries
    
    def save_to_file(self, entries, filepath):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'w') as f:
            for entry in entries:
                f.write(entry + '\n')
        print(f"Generated {len(entries)} entries → {filepath}")


def main():
    generator = LogDataGenerator(seed=42)
    
    sizes = {
        "small": 1000,
        "medium": 10000,
        "large": 100000
    }
    
    base_dir = "data/performance_test"
    
    print("=" * 60)
    print("GENERATING PERFORMANCE TEST DATASETS")
    print("=" * 60)
    
    for name, size in sizes.items():
        print(f"\n📊 Generating {name} dataset ({size:,} entries)...")
        entries = generator.generate_dataset(size, attack_ratio=0.3)
        filepath = os.path.join(base_dir, f"{name}_{size}.log")
        generator.save_to_file(entries, filepath)
    
    print("\n" + "=" * 60)
    print("✅ DATASET GENERATION COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
