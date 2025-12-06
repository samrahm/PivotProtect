"""
Static Detector for PivotProtect
Implements detection rules for various attack types using DSA structures.

Day 2 Task: Complete static detection rules and integrate HashMap, Trie, Graph.
"""

import re
from typing import List, Dict, Set, Tuple, Optional
from datetime import datetime
from collections import defaultdict

from .parser import LogParser, LogEntry
from .dsa_structures import HashMap, Trie, Graph, create_ip_frequency_map, create_endpoint_trie, create_ip_endpoint_graph


# =============================================================================
# DETECTION THRESHOLDS (Configurable)
# =============================================================================

class DetectionConfig:
    """Configuration thresholds for detection rules"""
    
    # Brute Force Detection
    BRUTE_FORCE_THRESHOLD = 5          # Failed attempts before flagging
    BRUTE_FORCE_WINDOW_SECONDS = 60    # Time window for attempts
    
    # Port Scanning Detection
    PORT_SCAN_THRESHOLD = 8            # Unique endpoints in short time
    PORT_SCAN_WINDOW_SECONDS = 5       # Time window for scanning
    
    # DDoS Detection
    DDOS_REQUEST_THRESHOLD = 5         # Requests per second threshold
    DDOS_UNIQUE_IPS_THRESHOLD = 5      # Multiple IPs hitting same endpoint
    DDOS_503_THRESHOLD = 3             # 503 errors indicating overload
    
    # Off-Hours Detection
    WORK_HOURS_START = 6               # 6 AM
    WORK_HOURS_END = 22                # 10 PM
    
    # High Activity Detection
    HIGH_ACTIVITY_THRESHOLD = 20       # Requests from single IP


# =============================================================================
# ATTACK PATTERNS (Regex)
# =============================================================================

class AttackPatterns:
    """Regex patterns for detecting various attack types"""
    
    # SQL Injection patterns
    SQL_INJECTION = [
        re.compile(r"('|%27).*?(OR|AND|UNION|SELECT|DROP|INSERT|UPDATE|DELETE)", re.IGNORECASE),
        re.compile(r"(;|%3B).*(DROP|DELETE|UPDATE|INSERT)", re.IGNORECASE),
        re.compile(r"UNION\s+(ALL\s+)?SELECT", re.IGNORECASE),
        re.compile(r"1\s*=\s*1", re.IGNORECASE),
        re.compile(r"'.*?'.*?=.*?'.*?'", re.IGNORECASE),
    ]
    
    # XSS patterns
    XSS = [
        re.compile(r"<\s*script[^>]*>", re.IGNORECASE),
        re.compile(r"javascript\s*:", re.IGNORECASE),
        re.compile(r"on(load|error|click|mouseover)\s*=", re.IGNORECASE),
        re.compile(r"<\s*img[^>]+onerror", re.IGNORECASE),
        re.compile(r"alert\s*\(", re.IGNORECASE),
    ]
    
    # Path Traversal patterns
    PATH_TRAVERSAL = [
        re.compile(r"\.\./", re.IGNORECASE),
        re.compile(r"\.\.\\", re.IGNORECASE),
        re.compile(r"%2e%2e[/\\%]", re.IGNORECASE),
        re.compile(r"etc/(passwd|shadow|hosts)", re.IGNORECASE),
        re.compile(r"windows/(system32|win\.ini)", re.IGNORECASE),
    ]
    
    # Suspicious User Agents
    SUSPICIOUS_USER_AGENTS = [
        re.compile(r"sqlmap", re.IGNORECASE),
        re.compile(r"nmap", re.IGNORECASE),
        re.compile(r"nikto", re.IGNORECASE),
        re.compile(r"masscan", re.IGNORECASE),
        re.compile(r"dirbuster", re.IGNORECASE),
        re.compile(r"gobuster", re.IGNORECASE),
        re.compile(r"curl/", re.IGNORECASE),  # Often used in automated attacks
    ]


# =============================================================================
# THREAT CLASSES
# =============================================================================

class Threat:
    """Represents a detected threat"""
    
    SEVERITY_LOW = "LOW"
    SEVERITY_MEDIUM = "MEDIUM"
    SEVERITY_HIGH = "HIGH"
    SEVERITY_CRITICAL = "CRITICAL"
    
    def __init__(self, threat_type: str, severity: str, source_ip: str,
                 description: str, evidence: List[str] = None,
                 timestamp: str = None):
        self.threat_type = threat_type
        self.severity = severity
        self.source_ip = source_ip
        self.description = description
        self.evidence = evidence or []
        self.timestamp = timestamp or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def to_dict(self) -> Dict:
        return {
            'type': self.threat_type,
            'severity': self.severity,
            'source_ip': self.source_ip,
            'description': self.description,
            'evidence': self.evidence,
            'timestamp': self.timestamp
        }
    
    def __str__(self) -> str:
        return f"[{self.severity}] {self.threat_type} from {self.source_ip}: {self.description}"


class DetectionResult:
    """Container for all detection results"""
    
    def __init__(self):
        self.threats: List[Threat] = []
        self.summary: Dict = {}
        self.statistics: Dict = {}
    
    def add_threat(self, threat: Threat):
        self.threats.append(threat)
    
    def get_threats_by_severity(self, severity: str) -> List[Threat]:
        return [t for t in self.threats if t.severity == severity]
    
    def get_threats_by_type(self, threat_type: str) -> List[Threat]:
        return [t for t in self.threats if t.threat_type == threat_type]
    
    def get_unique_attackers(self) -> Set[str]:
        return set(t.source_ip for t in self.threats)
    
    def to_dict(self) -> Dict:
        return {
            'total_threats': len(self.threats),
            'threats': [t.to_dict() for t in self.threats],
            'summary': self.summary,
            'statistics': self.statistics
        }
    
    def __str__(self) -> str:
        lines = [
            "=" * 60,
            "STATIC ANALYSIS DETECTION REPORT",
            "=" * 60,
            f"Total Threats Detected: {len(self.threats)}",
            f"Unique Attackers: {len(self.get_unique_attackers())}",
            "",
            "Threats by Severity:",
            f"  CRITICAL: {len(self.get_threats_by_severity(Threat.SEVERITY_CRITICAL))}",
            f"  HIGH: {len(self.get_threats_by_severity(Threat.SEVERITY_HIGH))}",
            f"  MEDIUM: {len(self.get_threats_by_severity(Threat.SEVERITY_MEDIUM))}",
            f"  LOW: {len(self.get_threats_by_severity(Threat.SEVERITY_LOW))}",
            "",
            "-" * 60,
            "DETAILED THREATS:",
            "-" * 60,
        ]
        
        for threat in self.threats:
            lines.append(str(threat))
            if threat.evidence:
                for ev in threat.evidence[:3]:  # Show max 3 evidence items
                    lines.append(f"    Evidence: {ev[:80]}...")
            lines.append("")
        
        if self.statistics:
            lines.append("-" * 60)
            lines.append("STATISTICS:")
            lines.append("-" * 60)
            for key, value in self.statistics.items():
                lines.append(f"  {key}: {value}")
        
        lines.append("=" * 60)
        
        return "\n".join(lines)


# =============================================================================
# STATIC DETECTOR
# =============================================================================

class StaticDetector:
    """
    Main detector class that uses DSA structures to analyze log entries
    and detect various attack patterns.
    """
    
    def __init__(self, config: DetectionConfig = None):
        """
        Initialize the detector.
        
        Args:
            config: Detection configuration (uses defaults if None)
        """
        self.config = config or DetectionConfig()
        self.patterns = AttackPatterns()
        
        # DSA Structures - will be populated during analysis
        self.ip_map: Optional[HashMap] = None
        self.endpoint_trie: Optional[Trie] = None
        self.connection_graph: Optional[Graph] = None
        
        # Additional tracking
        self.failed_logins: Dict[str, List[LogEntry]] = defaultdict(list)
        self.requests_by_time: Dict[str, List[LogEntry]] = defaultdict(list)
    
    def analyze(self, entries: List[LogEntry]) -> DetectionResult:
        """
        Analyze log entries and detect threats.
        
        Args:
            entries: List of parsed log entries
            
        Returns:
            DetectionResult containing all detected threats
        """
        result = DetectionResult()
        
        if not entries:
            result.summary = {"message": "No entries to analyze"}
            return result
        
        # Build DSA structures
        self._build_structures(entries)
        
        # Run all detection rules
        self._detect_brute_force(entries, result)
        self._detect_sql_injection(entries, result)
        self._detect_xss(entries, result)
        self._detect_path_traversal(entries, result)
        self._detect_port_scanning(entries, result)
        self._detect_ddos(entries, result)
        self._detect_off_hours_admin(entries, result)
        self._detect_suspicious_user_agents(entries, result)
        
        # Add statistics
        result.statistics = self._compute_statistics(entries)
        result.summary = self._create_summary(result)
        
        return result
    
    def _build_structures(self, entries: List[LogEntry]):
        """Build DSA structures from log entries"""
        # HashMap for IP frequencies
        self.ip_map = create_ip_frequency_map(entries)
        
        # Trie for endpoint patterns
        self.endpoint_trie = create_endpoint_trie(entries)
        
        # Graph for IP-endpoint connections
        self.connection_graph = create_ip_endpoint_graph(entries)
        
        # Track failed logins by IP
        self.failed_logins.clear()
        for entry in entries:
            if entry.status == 401 and 'login' in entry.endpoint.lower():
                self.failed_logins[entry.ip].append(entry)
        
        # Track requests by timestamp (second granularity)
        self.requests_by_time.clear()
        for entry in entries:
            if entry.datetime:
                time_key = entry.datetime.strftime("%Y-%m-%d %H:%M:%S")
                self.requests_by_time[time_key].append(entry)
    
    # -------------------------------------------------------------------------
    # DETECTION RULES
    # -------------------------------------------------------------------------
    
    def _detect_brute_force(self, entries: List[LogEntry], result: DetectionResult):
        """Detect brute force login attempts"""
        for ip, failed_entries in self.failed_logins.items():
            if len(failed_entries) >= self.config.BRUTE_FORCE_THRESHOLD:
                # Check if attempts are within time window
                if len(failed_entries) >= 2:
                    first = failed_entries[0].datetime
                    last = failed_entries[-1].datetime
                    if first and last:
                        delta = (last - first).total_seconds()
                        if delta <= self.config.BRUTE_FORCE_WINDOW_SECONDS:
                            threat = Threat(
                                threat_type="BRUTE_FORCE",
                                severity=Threat.SEVERITY_HIGH,
                                source_ip=ip,
                                description=f"{len(failed_entries)} failed login attempts in {delta:.0f} seconds",
                                evidence=[str(e) for e in failed_entries[:5]],
                                timestamp=failed_entries[0].timestamp
                            )
                            result.add_threat(threat)
    
    def _detect_sql_injection(self, entries: List[LogEntry], result: DetectionResult):
        """Detect SQL injection attempts"""
        for entry in entries:
            for pattern in self.patterns.SQL_INJECTION:
                if pattern.search(entry.endpoint):
                    threat = Threat(
                        threat_type="SQL_INJECTION",
                        severity=Threat.SEVERITY_CRITICAL,
                        source_ip=entry.ip,
                        description=f"SQL injection pattern detected in request",
                        evidence=[entry.endpoint],
                        timestamp=entry.timestamp
                    )
                    result.add_threat(threat)
                    break  # One match is enough per entry
    
    def _detect_xss(self, entries: List[LogEntry], result: DetectionResult):
        """Detect XSS (Cross-Site Scripting) attempts"""
        for entry in entries:
            for pattern in self.patterns.XSS:
                if pattern.search(entry.endpoint):
                    threat = Threat(
                        threat_type="XSS",
                        severity=Threat.SEVERITY_HIGH,
                        source_ip=entry.ip,
                        description=f"XSS pattern detected in request",
                        evidence=[entry.endpoint],
                        timestamp=entry.timestamp
                    )
                    result.add_threat(threat)
                    break
    
    def _detect_path_traversal(self, entries: List[LogEntry], result: DetectionResult):
        """Detect path traversal attempts"""
        # Use Trie to find suspicious patterns
        suspicious_paths = self.endpoint_trie.find_suspicious_patterns()
        
        if suspicious_paths:
            # Find which IPs accessed these paths
            for entry in entries:
                for pattern in self.patterns.PATH_TRAVERSAL:
                    if pattern.search(entry.endpoint):
                        threat = Threat(
                            threat_type="PATH_TRAVERSAL",
                            severity=Threat.SEVERITY_HIGH,
                            source_ip=entry.ip,
                            description=f"Path traversal attempt detected",
                            evidence=[entry.endpoint],
                            timestamp=entry.timestamp
                        )
                        result.add_threat(threat)
                        break
    
    def _detect_port_scanning(self, entries: List[LogEntry], result: DetectionResult):
        """Detect port scanning behavior using Graph analysis"""
        # Use Graph to find IPs with high out-degree (many endpoints accessed)
        high_degree_ips = self.connection_graph.get_high_degree_nodes(
            threshold=self.config.PORT_SCAN_THRESHOLD
        )
        
        for ip, degree in high_degree_ips:
            # Skip endpoints (they start with /)
            if ip.startswith('/'):
                continue
            
            # Get entries for this IP and check time window
            ip_entries = [e for e in entries if e.ip == ip]
            
            if len(ip_entries) >= self.config.PORT_SCAN_THRESHOLD:
                # Check if requests are rapid (within time window)
                times = [e.datetime for e in ip_entries if e.datetime]
                if len(times) >= 2:
                    times.sort()
                    delta = (times[-1] - times[0]).total_seconds()
                    if delta <= self.config.PORT_SCAN_WINDOW_SECONDS:
                        endpoints = list(set(e.endpoint for e in ip_entries))
                        threat = Threat(
                            threat_type="PORT_SCAN",
                            severity=Threat.SEVERITY_MEDIUM,
                            source_ip=ip,
                            description=f"Scanned {degree} endpoints in {delta:.0f} seconds",
                            evidence=endpoints[:5],
                            timestamp=ip_entries[0].timestamp
                        )
                        result.add_threat(threat)
    
    def _detect_ddos(self, entries: List[LogEntry], result: DetectionResult):
        """Detect DDoS-like behavior"""
        # Check for multiple IPs hitting same endpoint at same time
        endpoint_hits: Dict[str, Dict[str, Set[str]]] = defaultdict(lambda: defaultdict(set))
        
        for entry in entries:
            if entry.datetime:
                time_key = entry.datetime.strftime("%Y-%m-%d %H:%M:%S")
                endpoint_hits[entry.endpoint][time_key].add(entry.ip)
        
        for endpoint, time_data in endpoint_hits.items():
            for time_key, ips in time_data.items():
                if len(ips) >= self.config.DDOS_UNIQUE_IPS_THRESHOLD:
                    threat = Threat(
                        threat_type="DDOS",
                        severity=Threat.SEVERITY_CRITICAL,
                        source_ip=",".join(list(ips)[:5]),
                        description=f"{len(ips)} unique IPs hit {endpoint} simultaneously",
                        evidence=[f"Time: {time_key}", f"Endpoint: {endpoint}"],
                        timestamp=time_key
                    )
                    result.add_threat(threat)
        
        # Check for 503 errors (service unavailable)
        errors_503 = [e for e in entries if e.status == 503]
        if len(errors_503) >= self.config.DDOS_503_THRESHOLD:
            threat = Threat(
                threat_type="DDOS_INDICATOR",
                severity=Threat.SEVERITY_HIGH,
                source_ip="MULTIPLE",
                description=f"{len(errors_503)} service unavailable (503) errors detected",
                evidence=[str(e) for e in errors_503[:3]],
                timestamp=errors_503[0].timestamp if errors_503 else None
            )
            result.add_threat(threat)
    
    def _detect_off_hours_admin(self, entries: List[LogEntry], result: DetectionResult):
        """Detect admin access during off-hours"""
        for entry in entries:
            if 'admin' in entry.endpoint.lower() and entry.datetime:
                hour = entry.datetime.hour
                if hour < self.config.WORK_HOURS_START or hour >= self.config.WORK_HOURS_END:
                    threat = Threat(
                        threat_type="OFF_HOURS_ADMIN",
                        severity=Threat.SEVERITY_MEDIUM,
                        source_ip=entry.ip,
                        description=f"Admin access at {hour:02d}:00 (off-hours)",
                        evidence=[entry.endpoint, f"Method: {entry.method}"],
                        timestamp=entry.timestamp
                    )
                    result.add_threat(threat)
    
    def _detect_suspicious_user_agents(self, entries: List[LogEntry], result: DetectionResult):
        """Detect requests from known attack tools"""
        detected_agents: Dict[str, List[LogEntry]] = defaultdict(list)
        
        for entry in entries:
            for pattern in self.patterns.SUSPICIOUS_USER_AGENTS:
                if pattern.search(entry.user_agent):
                    detected_agents[entry.user_agent].append(entry)
                    break
        
        for agent, agent_entries in detected_agents.items():
            # Get unique IPs using this agent
            ips = set(e.ip for e in agent_entries)
            threat = Threat(
                threat_type="SUSPICIOUS_TOOL",
                severity=Threat.SEVERITY_MEDIUM,
                source_ip=",".join(list(ips)[:3]),
                description=f"Detected attack tool: {agent[:50]}",
                evidence=[f"Requests: {len(agent_entries)}", f"IPs: {len(ips)}"],
                timestamp=agent_entries[0].timestamp
            )
            result.add_threat(threat)
    
    # -------------------------------------------------------------------------
    # STATISTICS & SUMMARY
    # -------------------------------------------------------------------------
    
    def _compute_statistics(self, entries: List[LogEntry]) -> Dict:
        """Compute analysis statistics"""
        stats = {
            'total_entries': len(entries),
            'unique_ips': len(self.ip_map.keys()),
            'unique_endpoints': len(self.endpoint_trie.get_all_paths()),
            'graph_stats': self.connection_graph.get_statistics(),
        }
        
        # Top IPs by request count
        top_ips = self.ip_map.get_top_n(5)
        stats['top_ips'] = top_ips
        
        # Status code distribution
        status_dist = defaultdict(int)
        for entry in entries:
            status_dist[entry.status] += 1
        stats['status_distribution'] = dict(status_dist)
        
        # Method distribution
        method_dist = defaultdict(int)
        for entry in entries:
            method_dist[entry.method] += 1
        stats['method_distribution'] = dict(method_dist)
        
        return stats
    
    def _create_summary(self, result: DetectionResult) -> Dict:
        """Create analysis summary"""
        threat_types = defaultdict(int)
        for threat in result.threats:
            threat_types[threat.threat_type] += 1
        
        return {
            'total_threats': len(result.threats),
            'unique_attackers': len(result.get_unique_attackers()),
            'threat_breakdown': dict(threat_types),
            'critical_count': len(result.get_threats_by_severity(Threat.SEVERITY_CRITICAL)),
            'high_count': len(result.get_threats_by_severity(Threat.SEVERITY_HIGH)),
            'medium_count': len(result.get_threats_by_severity(Threat.SEVERITY_MEDIUM)),
            'low_count': len(result.get_threats_by_severity(Threat.SEVERITY_LOW)),
        }


# =============================================================================
# MAIN ENTRY POINT - run_static_analysis()
# =============================================================================

def run_static_analysis(filepath: str, config: DetectionConfig = None) -> DetectionResult:
    """
    Main entry point for static analysis.
    This function is called by the GUI to analyze a log file.
    
    Args:
        filepath: Path to the log file to analyze
        config: Optional detection configuration
        
    Returns:
        DetectionResult containing all detected threats and statistics
    """
    # Parse the log file
    parser = LogParser()
    entries = parser.parse_file(filepath)
    
    if not entries:
        result = DetectionResult()
        result.summary = {
            "error": f"Failed to parse log file: {filepath}",
            "parse_errors": parser.parse_errors,
            "total_lines": parser.total_lines
        }
        return result
    
    # Run detection
    detector = StaticDetector(config)
    result = detector.analyze(entries)
    
    # Add parsing info to statistics
    result.statistics['parsed_entries'] = len(entries)
    result.statistics['parse_errors'] = parser.parse_errors
    result.statistics['total_lines'] = parser.total_lines
    
    return result


# =============================================================================
# TEST / DEMO
# =============================================================================

def main():
    """Test the static detector with sample logs"""
    import os
    
    # Get the sample log file path
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(os.path.dirname(script_dir))
    sample_log = os.path.join(project_root, 'data', 'sample_static_logs.txt')
    
    print(f"Analyzing: {sample_log}")
    print()
    
    # Run analysis
    result = run_static_analysis(sample_log)
    
    # Print results
    print(result)
    
    # Print summary dict
    print("\n--- Summary Dict ---")
    for key, value in result.summary.items():
        print(f"  {key}: {value}")


if __name__ == '__main__':
    main()
