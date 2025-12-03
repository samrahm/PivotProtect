"""
Log File Parser for PivotProtect Static Analysis
Parses Apache Combined Log Format and extracts structured data.
"""

import re
from typing import List, Dict, Optional
from datetime import datetime


class LogEntry:
    """Represents a single parsed log entry"""
    
    def __init__(self, ip: str, timestamp: str, method: str, endpoint: str,
                 status: int, bytes_sent: int, referrer: str, user_agent: str,
                 response_time: int = 0):
        self.ip = ip
        self.timestamp = timestamp
        self.method = method
        self.endpoint = endpoint
        self.status = status
        self.bytes_sent = bytes_sent
        self.referrer = referrer
        self.user_agent = user_agent
        self.response_time = response_time
        self.datetime = self._parse_timestamp(timestamp)
    
    def _parse_timestamp(self, timestamp: str) -> Optional[datetime]:
        """Parse timestamp string to datetime object"""
        try:
            # Format: 29/Nov/2025:10:15:30 +0530
            ts_part = timestamp.split()[0] if ' ' in timestamp else timestamp
            return datetime.strptime(ts_part, '%d/%b/%Y:%H:%M:%S')
        except:
            return None
    
    def to_dict(self) -> Dict:
        """Convert log entry to dictionary"""
        return {
            'ip': self.ip,
            'timestamp': self.timestamp,
            'method': self.method,
            'endpoint': self.endpoint,
            'status': self.status,
            'bytes_sent': self.bytes_sent,
            'referrer': self.referrer,
            'user_agent': self.user_agent,
            'response_time': self.response_time
        }
    
    def __str__(self) -> str:
        return f"{self.ip} [{self.timestamp}] {self.method} {self.endpoint} {self.status}"


class LogParser:
    """
    Parser for Apache Combined Log Format.
    
    Format: IP - - [timestamp] "METHOD endpoint HTTP/version" status bytes "referrer" "user_agent" response_time
    """
    
    # Regex pattern for Apache Combined Log Format
    LOG_PATTERN = re.compile(
        r'(?P<ip>[\d.]+)\s+'           # IP address
        r'-\s+-\s+'                      # Two dashes (ident and user)
        r'\[(?P<timestamp>[^\]]+)\]\s+'  # Timestamp in brackets
        r'"(?P<method>\w+)\s+'           # HTTP method
        r'(?P<endpoint>\S+)\s+'          # Endpoint/URL
        r'HTTP/[\d.]+"\s+'               # HTTP version
        r'(?P<status>\d+)\s+'            # Status code
        r'(?P<bytes>\d+)\s+'             # Bytes sent
        r'"(?P<referrer>[^"]*)"\s+'      # Referrer
        r'"(?P<user_agent>[^"]*)"\s*'    # User agent
        r'(?P<response_time>\d+)?'       # Response time (optional)
    )
    
    def __init__(self):
        self.entries: List[LogEntry] = []
        self.parse_errors: int = 0
        self.total_lines: int = 0
    
    def parse_line(self, line: str) -> Optional[LogEntry]:
        """
        Parse a single log line.
        
        Args:
            line: Raw log line string
            
        Returns:
            LogEntry object or None if parsing fails
        """
        line = line.strip()
        
        # Skip empty lines and comments
        if not line or line.startswith('#'):
            return None
        
        match = self.LOG_PATTERN.match(line)
        if match:
            data = match.groupdict()
            return LogEntry(
                ip=data['ip'],
                timestamp=data['timestamp'],
                method=data['method'],
                endpoint=data['endpoint'],
                status=int(data['status']),
                bytes_sent=int(data['bytes']),
                referrer=data['referrer'],
                user_agent=data['user_agent'],
                response_time=int(data['response_time']) if data['response_time'] else 0
            )
        return None
    
    def parse_file(self, filepath: str) -> List[LogEntry]:
        """
        Parse an entire log file.
        
        Args:
            filepath: Path to the log file
            
        Returns:
            List of LogEntry objects
        """
        self.entries = []
        self.parse_errors = 0
        self.total_lines = 0
        
        print(f"Parsing log file: {filepath}")
        
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                self.total_lines += 1
                entry = self.parse_line(line)
                if entry:
                    self.entries.append(entry)
                elif line.strip() and not line.strip().startswith('#'):
                    self.parse_errors += 1
        
        print(f"  Total lines: {self.total_lines}")
        print(f"  Parsed entries: {len(self.entries)}")
        print(f"  Parse errors: {self.parse_errors}")
        
        return self.entries
    
    def get_unique_ips(self) -> List[str]:
        """Get list of unique IP addresses"""
        return list(set(entry.ip for entry in self.entries))
    
    def get_unique_endpoints(self) -> List[str]:
        """Get list of unique endpoints"""
        return list(set(entry.endpoint for entry in self.entries))
    
    def get_entries_by_ip(self, ip: str) -> List[LogEntry]:
        """Get all entries for a specific IP"""
        return [entry for entry in self.entries if entry.ip == ip]
    
    def get_entries_by_status(self, status: int) -> List[LogEntry]:
        """Get all entries with a specific status code"""
        return [entry for entry in self.entries if entry.status == status]
    
    def get_entries_by_method(self, method: str) -> List[LogEntry]:
        """Get all entries with a specific HTTP method"""
        return [entry for entry in self.entries if entry.method.upper() == method.upper()]
    
    def get_summary(self) -> Dict:
        """Get summary statistics of parsed logs"""
        if not self.entries:
            return {}
        
        # Count by status code
        status_counts = {}
        for entry in self.entries:
            status_counts[entry.status] = status_counts.get(entry.status, 0) + 1
        
        # Count by method
        method_counts = {}
        for entry in self.entries:
            method_counts[entry.method] = method_counts.get(entry.method, 0) + 1
        
        # Count by IP
        ip_counts = {}
        for entry in self.entries:
            ip_counts[entry.ip] = ip_counts.get(entry.ip, 0) + 1
        
        return {
            'total_entries': len(self.entries),
            'unique_ips': len(set(entry.ip for entry in self.entries)),
            'unique_endpoints': len(set(entry.endpoint for entry in self.entries)),
            'status_distribution': status_counts,
            'method_distribution': method_counts,
            'top_ips': sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        }


def main():
    """Test the parser with sample log file"""
    import os
    
    # Get path to sample log file
    script_dir = os.path.dirname(os.path.abspath(__file__))
    sample_log = os.path.join(script_dir, '..', '..', 'data', 'sample_static_logs.txt')
    
    # Parse the file
    parser = LogParser()
    entries = parser.parse_file(sample_log)
    
    # Print summary
    print("\n" + "=" * 50)
    print("LOG SUMMARY")
    print("=" * 50)
    
    summary = parser.get_summary()
    print(f"Total entries: {summary['total_entries']}")
    print(f"Unique IPs: {summary['unique_ips']}")
    print(f"Unique endpoints: {summary['unique_endpoints']}")
    
    print("\nStatus code distribution:")
    for status, count in sorted(summary['status_distribution'].items()):
        print(f"  {status}: {count}")
    
    print("\nHTTP method distribution:")
    for method, count in summary['method_distribution'].items():
        print(f"  {method}: {count}")
    
    print("\nTop 10 IPs by request count:")
    for ip, count in summary['top_ips']:
        print(f"  {ip}: {count}")


if __name__ == '__main__':
    main()
