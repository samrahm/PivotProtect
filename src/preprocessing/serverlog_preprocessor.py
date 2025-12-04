"""
Server Log Dataset Preprocessor
This module handles preprocessing of Apache/nginx style server access logs.
"""

import re
import pandas as pd
import numpy as np
from pathlib import Path
from typing import Tuple, List, Optional, Dict
from datetime import datetime
from collections import Counter
import warnings
warnings.filterwarnings('ignore')


class ServerLogPreprocessor:
    """Preprocessor for Server Log dataset (using NumPy/Pandas only)"""
    
    # Apache Combined Log Format regex pattern
    # Format: IP - - [timestamp] "METHOD endpoint HTTP/version" status bytes "referrer" "user_agent" response_time
    LOG_PATTERN = re.compile(
        r'(?P<ip>[\d.]+)\s+'
        r'-\s+-\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>\w+)\s+(?P<endpoint>\S+)\s+HTTP/[\d.]+"\s+'
        r'(?P<status>\d+)\s+'
        r'(?P<bytes>\d+)\s+'
        r'"(?P<referrer>[^"]*)"\s+'
        r'"(?P<user_agent>[^"]*)"\s*'
        r'(?P<response_time>\d+)?'
    )
    
    def __init__(self, data_dir: str):
        """
        Initialize the Server Log preprocessor.
        
        Args:
            data_dir: Path to the serverlogs directory
        """
        self.data_dir = Path(data_dir)
        self.feature_columns = []
        # Store scaling parameters (replaces StandardScaler)
        self.feature_means = {}
        self.feature_stds = {}
        
        # Known attack patterns
        self.attack_patterns = {
            'sql_injection': [
                r'(\%27)|(\')|(\-\-)|(\%23)|(#)',
                r'(\%22)|(\")',
                r'union.*select',
                r'select.*from',
                r'insert.*into',
                r'drop.*table',
                r'update.*set',
                r'delete.*from'
            ],
            'xss': [
                r'<script>',
                r'javascript:',
                r'onerror=',
                r'onload=',
                r'alert\(',
                r'<img.*onerror'
            ],
            'path_traversal': [
                r'\.\./\.\.',
                r'/etc/passwd',
                r'/etc/shadow',
                r'%2e%2e',
                r'%252e%252e'
            ],
            'command_injection': [
                r';\s*cat\s+',
                r';\s*ls\s+',
                r'\|\s*cat',
                r'`.*`',
                r'\$\(.*\)'
            ]
        }
        
    def parse_log_line(self, line: str) -> Optional[Dict]:
        """
        Parse a single log line into components.
        
        Args:
            line: Raw log line string
            
        Returns:
            Dictionary with parsed components or None if parsing fails
        """
        match = self.LOG_PATTERN.match(line.strip())
        if match:
            return match.groupdict()
        return None
    
    def load_log_file(self, filepath: str, max_lines: Optional[int] = None) -> pd.DataFrame:
        """
        Load and parse a log file.
        
        Args:
            filepath: Path to the log file
            max_lines: Maximum number of lines to load
            
        Returns:
            DataFrame with parsed log entries
        """
        print(f"Loading {Path(filepath).name}...")
        
        records = []
        parse_errors = 0
        
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for i, line in enumerate(f):
                if max_lines and i >= max_lines:
                    break
                    
                parsed = self.parse_log_line(line)
                if parsed:
                    records.append(parsed)
                else:
                    parse_errors += 1
                    
                if (i + 1) % 100000 == 0:
                    print(f"  Processed {i + 1} lines...")
                    
        df = pd.DataFrame(records)
        print(f"  Loaded {len(df)} records ({parse_errors} parse errors)")
        
        return df
    
    def extract_timestamp_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract time-based features from timestamp.
        
        Args:
            df: DataFrame with 'timestamp' column
            
        Returns:
            DataFrame with additional time features
        """
        print("\nExtracting timestamp features...")
        
        # Parse timestamp (format: 27/Dec/2037:12:00:00 +0530)
        def parse_timestamp(ts):
            try:
                return datetime.strptime(ts.split()[0], '%d/%b/%Y:%H:%M:%S')
            except:
                return None
        
        df['datetime'] = df['timestamp'].apply(parse_timestamp)
        
        # Extract time features
        df['hour'] = df['datetime'].apply(lambda x: x.hour if x else 0)
        df['day_of_week'] = df['datetime'].apply(lambda x: x.weekday() if x else 0)
        df['month'] = df['datetime'].apply(lambda x: x.month if x else 0)
        df['is_weekend'] = df['day_of_week'].apply(lambda x: 1 if x >= 5 else 0)
        df['is_business_hours'] = df['hour'].apply(lambda x: 1 if 9 <= x <= 17 else 0)
        
        return df
    
    def extract_request_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract features from HTTP request.
        
        Args:
            df: DataFrame with request columns
            
        Returns:
            DataFrame with additional request features
        """
        print("Extracting request features...")
        
        # Method encoding
        method_map = {'GET': 0, 'POST': 1, 'PUT': 2, 'DELETE': 3, 'HEAD': 4, 'OPTIONS': 5}
        df['method_encoded'] = df['method'].map(method_map).fillna(6)
        
        # Endpoint features
        df['endpoint_length'] = df['endpoint'].str.len()
        df['endpoint_depth'] = df['endpoint'].str.count('/')
        df['has_query_params'] = df['endpoint'].str.contains(r'\?', regex=True).astype(int)
        df['query_param_count'] = df['endpoint'].str.count('&') + df['has_query_params']
        
        # Special character count in endpoint
        df['special_char_count'] = df['endpoint'].str.count(r'[%\'\"\<\>\;\|]')
        
        # Admin endpoint detection
        df['is_admin_endpoint'] = df['endpoint'].str.contains('admin', case=False).astype(int)
        
        return df
    
    def extract_response_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract features from HTTP response.
        
        Args:
            df: DataFrame with response columns
            
        Returns:
            DataFrame with additional response features
        """
        print("Extracting response features...")
        
        # Convert to numeric
        df['status'] = pd.to_numeric(df['status'], errors='coerce').fillna(0).astype(int)
        df['bytes'] = pd.to_numeric(df['bytes'], errors='coerce').fillna(0).astype(int)
        df['response_time'] = pd.to_numeric(df['response_time'], errors='coerce').fillna(0).astype(int)
        
        # Status code categories
        df['status_1xx'] = ((df['status'] >= 100) & (df['status'] < 200)).astype(int)
        df['status_2xx'] = ((df['status'] >= 200) & (df['status'] < 300)).astype(int)
        df['status_3xx'] = ((df['status'] >= 300) & (df['status'] < 400)).astype(int)
        df['status_4xx'] = ((df['status'] >= 400) & (df['status'] < 500)).astype(int)
        df['status_5xx'] = (df['status'] >= 500).astype(int)
        
        # Error indicator
        df['is_error'] = (df['status'] >= 400).astype(int)
        
        return df
    
    def extract_user_agent_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract features from User-Agent string.
        
        Args:
            df: DataFrame with 'user_agent' column
            
        Returns:
            DataFrame with additional UA features
        """
        print("Extracting user agent features...")
        
        df['ua_length'] = df['user_agent'].str.len()
        
        # Browser detection
        df['is_chrome'] = df['user_agent'].str.contains('Chrome', case=False).astype(int)
        df['is_firefox'] = df['user_agent'].str.contains('Firefox', case=False).astype(int)
        df['is_safari'] = df['user_agent'].str.contains('Safari', case=False).astype(int)
        df['is_edge'] = df['user_agent'].str.contains('Edge|Edg', case=False).astype(int)
        df['is_opera'] = df['user_agent'].str.contains('Opera|OPR', case=False).astype(int)
        
        # OS detection
        df['is_windows'] = df['user_agent'].str.contains('Windows', case=False).astype(int)
        df['is_mac'] = df['user_agent'].str.contains('Macintosh|Mac OS', case=False).astype(int)
        df['is_linux'] = df['user_agent'].str.contains('Linux', case=False).astype(int)
        df['is_android'] = df['user_agent'].str.contains('Android', case=False).astype(int)
        df['is_ios'] = df['user_agent'].str.contains('iPhone|iPad', case=False).astype(int)
        
        # Mobile detection
        df['is_mobile'] = df['user_agent'].str.contains('Mobile|Android|iPhone', case=False).astype(int)
        
        # Bot detection
        df['is_bot'] = df['user_agent'].str.contains('bot|crawler|spider', case=False).astype(int)
        
        return df
    
    def extract_referrer_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract features from referrer.
        
        Args:
            df: DataFrame with 'referrer' column
            
        Returns:
            DataFrame with additional referrer features
        """
        print("Extracting referrer features...")
        
        df['has_referrer'] = (df['referrer'] != '-').astype(int)
        df['referrer_length'] = df['referrer'].apply(lambda x: len(x) if x != '-' else 0)
        df['is_external_referrer'] = df['referrer'].str.contains('http', case=False).astype(int)
        
        return df
    
    def detect_attacks(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Detect potential attacks based on patterns.
        
        Args:
            df: DataFrame with endpoint column
            
        Returns:
            DataFrame with attack detection columns
        """
        print("Detecting potential attacks...")
        
        # Check for each attack type
        for attack_type, patterns in self.attack_patterns.items():
            combined_pattern = '|'.join(patterns)
            df[f'is_{attack_type}'] = df['endpoint'].str.contains(
                combined_pattern, case=False, regex=True
            ).fillna(False).astype(int)
        
        # Combined attack indicator
        attack_cols = [f'is_{at}' for at in self.attack_patterns.keys()]
        df['is_attack'] = df[attack_cols].max(axis=1)
        
        return df
    
    def extract_ip_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract features from IP addresses.
        
        Args:
            df: DataFrame with 'ip' column
            
        Returns:
            DataFrame with IP features
        """
        print("Extracting IP features...")
        
        # IP octets
        ip_parts = df['ip'].str.split('.', expand=True).astype(float)
        df['ip_octet_1'] = ip_parts[0]
        df['ip_octet_2'] = ip_parts[1]
        df['ip_octet_3'] = ip_parts[2]
        df['ip_octet_4'] = ip_parts[3]
        
        # Private IP detection
        df['is_private_ip'] = (
            (df['ip_octet_1'] == 10) |
            ((df['ip_octet_1'] == 172) & (df['ip_octet_2'] >= 16) & (df['ip_octet_2'] <= 31)) |
            ((df['ip_octet_1'] == 192) & (df['ip_octet_2'] == 168))
        ).astype(int)
        
        return df
    
    def create_labels(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Create labels based on status codes and attack patterns.
        For this synthetic dataset, we'll use heuristics.
        
        Args:
            df: DataFrame with features
            
        Returns:
            DataFrame with labels
        """
        print("\nCreating labels...")
        
        # Anomaly score based on multiple factors
        df['anomaly_score'] = 0
        
        # High error rate
        df['anomaly_score'] += df['is_error'] * 2
        
        # Attack patterns detected
        df['anomaly_score'] += df['is_attack'] * 5
        
        # Unusual endpoints
        df['anomaly_score'] += (df['endpoint_depth'] > 5).astype(int) * 1
        df['anomaly_score'] += (df['special_char_count'] > 2).astype(int) * 2
        
        # Off-hours access to admin
        df['anomaly_score'] += ((df['is_admin_endpoint'] == 1) & (df['is_business_hours'] == 0)).astype(int) * 2
        
        # Very long endpoints (potential injection)
        df['anomaly_score'] += (df['endpoint_length'] > 100).astype(int) * 2
        
        # Create binary label (threshold-based)
        df['label'] = (df['anomaly_score'] >= 3).astype(int)
        
        # Create categorical labels
        conditions = [
            df['is_sql_injection'] == 1,
            df['is_xss'] == 1,
            df['is_path_traversal'] == 1,
            df['is_command_injection'] == 1,
            df['status'] >= 500,
            df['status'] >= 400,
        ]
        choices = ['SQL_INJECTION', 'XSS', 'PATH_TRAVERSAL', 'CMD_INJECTION', 'SERVER_ERROR', 'CLIENT_ERROR']
        df['label_category'] = np.select(conditions, choices, default='NORMAL')
        
        print(f"  Label distribution:")
        print(f"    Normal: {sum(df['label'] == 0)}")
        print(f"    Anomaly: {sum(df['label'] == 1)}")
        
        return df
    
    def preprocess(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series, pd.Series]:
        """
        Full preprocessing pipeline.
        
        Args:
            df: Raw parsed log DataFrame
            
        Returns:
            Tuple of (features DataFrame, binary labels, category labels)
        """
        # Extract all features
        df = self.extract_timestamp_features(df)
        df = self.extract_request_features(df)
        df = self.extract_response_features(df)
        df = self.extract_user_agent_features(df)
        df = self.extract_referrer_features(df)
        df = self.extract_ip_features(df)
        df = self.detect_attacks(df)
        df = self.create_labels(df)
        
        # Select numeric feature columns
        feature_cols = [
            # Time features
            'hour', 'day_of_week', 'month', 'is_weekend', 'is_business_hours',
            # Request features
            'method_encoded', 'endpoint_length', 'endpoint_depth', 
            'has_query_params', 'query_param_count', 'special_char_count', 'is_admin_endpoint',
            # Response features
            'status', 'bytes', 'response_time',
            'status_1xx', 'status_2xx', 'status_3xx', 'status_4xx', 'status_5xx', 'is_error',
            # User agent features
            'ua_length', 'is_chrome', 'is_firefox', 'is_safari', 'is_edge', 'is_opera',
            'is_windows', 'is_mac', 'is_linux', 'is_android', 'is_ios', 'is_mobile', 'is_bot',
            # Referrer features
            'has_referrer', 'referrer_length', 'is_external_referrer',
            # IP features
            'ip_octet_1', 'ip_octet_2', 'ip_octet_3', 'ip_octet_4', 'is_private_ip',
            # Attack indicators
            'is_sql_injection', 'is_xss', 'is_path_traversal', 'is_command_injection'
        ]
        
        self.feature_columns = feature_cols
        
        # Extract features and labels
        features = df[feature_cols].copy()
        labels_binary = df['label'].copy()
        labels_category = df['label_category'].copy()
        
        # Fill any NaN
        features = features.fillna(0)
        
        # Normalize features using Z-score standardization (replaces sklearn StandardScaler)
        print("\nNormalizing features...")
        for col in feature_cols:
            self.feature_means[col] = features[col].mean()
            self.feature_stds[col] = features[col].std()
            # Avoid division by zero
            if self.feature_stds[col] == 0:
                self.feature_stds[col] = 1.0
            features[col] = (features[col] - self.feature_means[col]) / self.feature_stds[col]
        
        print(f"  Normalized {len(feature_cols)} features")
        print(f"\nPreprocessed data shape: {features.shape}")
        
        return features, labels_binary, labels_category
    
    def save_preprocessed(self, features: pd.DataFrame, labels_binary: pd.Series,
                         labels_category: pd.Series, output_dir: str):
        """
        Save preprocessed data to files.
        
        Args:
            features: Preprocessed features DataFrame
            labels_binary: Binary labels Series
            labels_category: Category labels Series
            output_dir: Directory to save output files
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Save features
        features.to_csv(output_path / 'serverlog_features.csv', index=False)
        
        # Save binary labels
        labels_binary.to_csv(output_path / 'serverlog_labels_binary.csv', index=False, header=['label'])
        
        # Save category labels
        labels_category.to_csv(output_path / 'serverlog_labels_category.csv', index=False, header=['label'])
        
        # Save combined
        combined = features.copy()
        combined['label_binary'] = labels_binary.values
        combined['label_category'] = labels_category.values
        combined.to_csv(output_path / 'serverlog_preprocessed.csv', index=False)
        
        # Save feature column names
        with open(output_path / 'feature_columns.txt', 'w') as f:
            f.write('\n'.join(self.feature_columns))
        
        print(f"Saved preprocessed data to {output_path}")


def main():
    """Main function to run Server Log preprocessing"""
    # Paths
    data_dir = Path(__file__).parent.parent.parent / 'data' / 'server_log' / 'serverlogs'
    output_dir = Path(__file__).parent.parent.parent / 'data' / 'processed' / 'serverlog'
    log_file = data_dir / 'logfiles.log'
    
    # Initialize preprocessor
    preprocessor = ServerLogPreprocessor(str(data_dir))
    
    # Load log file
    print("=" * 50)
    print("Loading Server Log Data")
    print("=" * 50)
    raw_df = preprocessor.load_log_file(str(log_file))
    
    # Preprocess
    print("\n" + "=" * 50)
    print("Preprocessing Data")
    print("=" * 50)
    features, labels_binary, labels_category = preprocessor.preprocess(raw_df)
    
    # Save preprocessed data
    print("\n" + "=" * 50)
    print("Saving Preprocessed Data")
    print("=" * 50)
    preprocessor.save_preprocessed(features, labels_binary, labels_category, str(output_dir))
    
    print("\nServer Log preprocessing complete!")


if __name__ == '__main__':
    main()
