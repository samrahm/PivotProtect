"""
PivotProtect - Main Preprocessing Script
Runs preprocessing for all three datasets:
1. EMBER (File Malware)
2. CICIDS2017 (Network Detection)
3. Server Logs

Usage:
    python run_preprocessing.py [--all] [--ember] [--network] [--serverlog]
"""

import argparse
from pathlib import Path
import sys

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent))

from preprocessing.ember_preprocessor import EmberPreprocessor
from preprocessing.network_preprocessor import NetworkPreprocessor
from preprocessing.serverlog_preprocessor import ServerLogPreprocessor


def run_ember_preprocessing(max_samples_per_file: int = 5000):
    """Run EMBER dataset preprocessing"""
    print("\n" + "=" * 70)
    print("EMBER (File Malware) Dataset Preprocessing")
    print("=" * 70)
    
    base_path = Path(__file__).parent.parent
    data_dir = base_path / 'data' / 'file_malware' / 'file_malware' / 'ember_2017_2'
    output_dir = base_path / 'data' / 'processed' / 'ember'
    
    if not data_dir.exists():
        print(f"Error: EMBER data directory not found at {data_dir}")
        return False
        
    preprocessor = EmberPreprocessor(str(data_dir))
    
    # Load training data
    print("\nLoading Training Data...")
    train_df = preprocessor.load_all_training_data(max_samples_per_file=max_samples_per_file)
    
    if train_df.empty:
        print("Warning: No training data loaded")
        return False
    
    # Load test data
    print("\nLoading Test Data...")
    test_df = preprocessor.load_test_data(max_samples=max_samples_per_file)
    
    # Preprocess training data
    print("\nPreprocessing Training Data...")
    train_features, train_labels = preprocessor.preprocess(train_df)
    
    # Save training data
    preprocessor.save_preprocessed(train_features, train_labels, str(output_dir / 'train'))
    
    # Preprocess and save test data if available
    if not test_df.empty:
        print("\nPreprocessing Test Data...")
        test_features, test_labels = preprocessor.preprocess(test_df)
        preprocessor.save_preprocessed(test_features, test_labels, str(output_dir / 'test'))
    
    print("\n✓ EMBER preprocessing complete!")
    return True


def run_network_preprocessing():
    """Run Network Detection dataset preprocessing"""
    print("\n" + "=" * 70)
    print("CICIDS2017 (Network Detection) Dataset Preprocessing")
    print("=" * 70)
    
    base_path = Path(__file__).parent.parent
    data_dir = base_path / 'data' / 'network_detect' / 'network' / 'MachineLearningCVE'
    output_dir = base_path / 'data' / 'processed' / 'network'
    
    if not data_dir.exists():
        print(f"Error: Network data directory not found at {data_dir}")
        return False
        
    preprocessor = NetworkPreprocessor(str(data_dir))
    
    # Load all data
    print("\nLoading Network Detection Data...")
    raw_df = preprocessor.load_all_data()
    
    if raw_df.empty:
        print("Warning: No network data loaded")
        return False
    
    # Preprocess
    print("\nPreprocessing Data...")
    features, labels_multiclass, labels_binary, label_mapping = preprocessor.preprocess(raw_df)
    
    # Save
    preprocessor.save_preprocessed(features, labels_multiclass, labels_binary, label_mapping, str(output_dir))
    
    print("\n✓ Network preprocessing complete!")
    return True


def run_serverlog_preprocessing(max_lines: int = None):
    """Run Server Log dataset preprocessing"""
    print("\n" + "=" * 70)
    print("Server Log Dataset Preprocessing")
    print("=" * 70)
    
    base_path = Path(__file__).parent.parent
    data_dir = base_path / 'data' / 'server_log' / 'serverlogs'
    output_dir = base_path / 'data' / 'processed' / 'serverlog'
    log_file = data_dir / 'logfiles.log'
    
    if not log_file.exists():
        print(f"Error: Server log file not found at {log_file}")
        return False
        
    preprocessor = ServerLogPreprocessor(str(data_dir))
    
    # Load log file
    print("\nLoading Server Log Data...")
    raw_df = preprocessor.load_log_file(str(log_file), max_lines=max_lines)
    
    if raw_df.empty:
        print("Warning: No server log data loaded")
        return False
    
    # Preprocess
    print("\nPreprocessing Data...")
    features, labels_binary, labels_category = preprocessor.preprocess(raw_df)
    
    # Save
    preprocessor.save_preprocessed(features, labels_binary, labels_category, str(output_dir))
    
    print("\n✓ Server Log preprocessing complete!")
    return True


def main():
    parser = argparse.ArgumentParser(description='PivotProtect Dataset Preprocessing')
    parser.add_argument('--all', action='store_true', help='Preprocess all datasets')
    parser.add_argument('--ember', action='store_true', help='Preprocess EMBER (malware) dataset')
    parser.add_argument('--network', action='store_true', help='Preprocess Network (CICIDS2017) dataset')
    parser.add_argument('--serverlog', action='store_true', help='Preprocess Server Log dataset')
    parser.add_argument('--ember-samples', type=int, default=5000, 
                        help='Max samples per EMBER file (default: 5000)')
    parser.add_argument('--serverlog-lines', type=int, default=None,
                        help='Max lines from server log (default: all)')
    
    args = parser.parse_args()
    
    # Default to all if no specific dataset selected
    if not (args.all or args.ember or args.network or args.serverlog):
        args.all = True
    
    print("=" * 70)
    print("PivotProtect - Dataset Preprocessing Pipeline")
    print("=" * 70)
    
    results = {}
    
    if args.all or args.ember:
        results['EMBER'] = run_ember_preprocessing(args.ember_samples)
        
    if args.all or args.network:
        results['Network'] = run_network_preprocessing()
        
    if args.all or args.serverlog:
        results['ServerLog'] = run_serverlog_preprocessing(args.serverlog_lines)
    
    # Summary
    print("\n" + "=" * 70)
    print("Preprocessing Summary")
    print("=" * 70)
    
    for dataset, success in results.items():
        status = "✓ Success" if success else "✗ Failed"
        print(f"  {dataset}: {status}")
        
    # Output location
    output_base = Path(__file__).parent.parent / 'data' / 'processed'
    print(f"\nPreprocessed data saved to: {output_base}")
    

if __name__ == '__main__':
    main()
