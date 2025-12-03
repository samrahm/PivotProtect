"""
CICIDS2017 Network Intrusion Detection Dataset Preprocessor
This module handles preprocessing of the CIC-IDS2017 network traffic dataset.
"""

import pandas as pd
import numpy as np
from pathlib import Path
from typing import Tuple, List, Optional
import warnings
warnings.filterwarnings('ignore')


class NetworkPreprocessor:
    """Preprocessor for CICIDS2017 Network Detection dataset (using NumPy/Pandas only)"""
    
    def __init__(self, data_dir: str):
        """
        Initialize the Network preprocessor.
        
        Args:
            data_dir: Path to the MachineLearningCVE directory containing CSV files
        """
        self.data_dir = Path(data_dir)
        self.feature_columns = []
        self.label_classes = []
        # Store scaling parameters (replaces StandardScaler)
        self.feature_means = {}
        self.feature_stds = {}
        
    def load_single_file(self, filepath: str) -> pd.DataFrame:
        """
        Load a single CSV file.
        
        Args:
            filepath: Path to the CSV file
            
        Returns:
            DataFrame with loaded data
        """
        print(f"Loading {Path(filepath).name}...")
        df = pd.read_csv(filepath, low_memory=False, encoding='utf-8')
        
        # Clean column names (remove leading/trailing whitespace)
        df.columns = df.columns.str.strip()
        
        print(f"  Loaded {len(df)} samples with {len(df.columns)} columns")
        return df
    
    def load_all_data(self) -> pd.DataFrame:
        """
        Load all CSV files from the data directory.
        
        Returns:
            Combined DataFrame with all data
        """
        csv_files = sorted(self.data_dir.glob('*.csv'))
        
        dfs = []
        for csv_file in csv_files:
            df = self.load_single_file(str(csv_file))
            dfs.append(df)
            
        if dfs:
            combined_df = pd.concat(dfs, ignore_index=True)
            print(f"\nTotal samples: {len(combined_df)}")
            return combined_df
        return pd.DataFrame()
    
    def clean_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Clean the raw data by handling invalid values.
        
        Args:
            df: Raw DataFrame
            
        Returns:
            Cleaned DataFrame
        """
        print("\nCleaning data...")
        initial_count = len(df)
        
        # Standardize column names
        df.columns = df.columns.str.strip()
        
        # Replace infinity values with NaN
        df = df.replace([np.inf, -np.inf], np.nan)
        
        # Remove rows with NaN values
        df = df.dropna()
        
        # Remove duplicate rows
        df = df.drop_duplicates()
        
        final_count = len(df)
        print(f"  Removed {initial_count - final_count} invalid rows")
        print(f"  Remaining samples: {final_count}")
        
        return df
    
    def get_feature_columns(self, df: pd.DataFrame) -> List[str]:
        """
        Get list of feature columns (excluding label column).
        
        Args:
            df: DataFrame
            
        Returns:
            List of feature column names
        """
        # Label column is typically named 'Label' in CICIDS2017
        label_cols = ['Label', 'label']
        feature_cols = [col for col in df.columns if col not in label_cols]
        return feature_cols
    
    def encode_labels(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, dict]:
        """
        Encode categorical labels to numeric values.
        
        Args:
            df: DataFrame with 'Label' column
            
        Returns:
            Tuple of (DataFrame with encoded labels, label mapping dict)
        """
        print("\nEncoding labels...")
        
        # Find the label column
        label_col = 'Label' if 'Label' in df.columns else 'label'
        
        # Clean label values
        df[label_col] = df[label_col].str.strip()
        
        # Print label distribution before encoding
        print(f"  Label distribution:")
        label_counts = df[label_col].value_counts()
        for label, count in label_counts.items():
            print(f"    {label}: {count}")
        
        # Get unique labels and sort them for consistent encoding
        self.label_classes = sorted(df[label_col].unique())
        
        # Create label mapping dictionary (replaces sklearn LabelEncoder)
        label_mapping = {label: idx for idx, label in enumerate(self.label_classes)}
        
        # Encode labels using the mapping
        df['label_encoded'] = df[label_col].map(label_mapping)
        
        # Create binary label (0 = BENIGN, 1 = Attack)
        df['label_binary'] = (df[label_col] != 'BENIGN').astype(int)
        
        print(f"\n  Label mapping: {label_mapping}")
        print(f"  Binary distribution: BENIGN={sum(df['label_binary']==0)}, Attack={sum(df['label_binary']==1)}")
        
        return df, label_mapping
    
    def preprocess_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Preprocess feature columns.
        
        Args:
            df: DataFrame with features
            
        Returns:
            DataFrame with preprocessed features
        """
        print("\nPreprocessing features...")
        
        # Get feature columns
        feature_cols = self.get_feature_columns(df)
        feature_cols = [c for c in feature_cols if c not in ['label_encoded', 'label_binary']]
        
        # Convert all features to numeric
        for col in feature_cols:
            df[col] = pd.to_numeric(df[col], errors='coerce')
            
        # Fill any remaining NaN with 0
        df[feature_cols] = df[feature_cols].fillna(0)
        
        # Remove columns with zero variance
        zero_var_cols = []
        for col in feature_cols:
            if df[col].std() == 0:
                zero_var_cols.append(col)
        
        if zero_var_cols:
            print(f"  Removing {len(zero_var_cols)} zero-variance columns")
            feature_cols = [c for c in feature_cols if c not in zero_var_cols]
            
        self.feature_columns = feature_cols
        print(f"  Final feature count: {len(feature_cols)}")
        
        return df
    
    def normalize_features(self, df: pd.DataFrame, fit: bool = True) -> pd.DataFrame:
        """
        Normalize features using Z-score standardization (mean=0, std=1).
        Implemented with NumPy/Pandas instead of sklearn StandardScaler.
        
        Args:
            df: DataFrame with features
            fit: Whether to compute scaling parameters (True for training, False for test)
            
        Returns:
            DataFrame with normalized features
        """
        print("\nNormalizing features...")
        
        feature_cols = self.feature_columns
        
        if fit:
            # Compute and store mean and std for each feature
            for col in feature_cols:
                self.feature_means[col] = df[col].mean()
                self.feature_stds[col] = df[col].std()
                # Avoid division by zero
                if self.feature_stds[col] == 0:
                    self.feature_stds[col] = 1.0
        
        # Apply standardization: (x - mean) / std
        for col in feature_cols:
            df[col] = (df[col] - self.feature_means[col]) / self.feature_stds[col]
            
        print(f"  Normalized {len(feature_cols)} features")
        
        return df
    
    def preprocess(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series, pd.Series]:
        """
        Full preprocessing pipeline.
        
        Args:
            df: Raw DataFrame
            
        Returns:
            Tuple of (processed features, multiclass labels, binary labels)
        """
        # Clean data
        df = self.clean_data(df)
        
        # Encode labels
        df, label_mapping = self.encode_labels(df)
        
        # Preprocess features
        df = self.preprocess_features(df)
        
        # Normalize features
        df = self.normalize_features(df)
        
        # Separate features and labels
        features = df[self.feature_columns]
        labels_multiclass = df['label_encoded']
        labels_binary = df['label_binary']
        
        print(f"\nPreprocessed data shape: {features.shape}")
        
        return features, labels_multiclass, labels_binary, label_mapping
    
    def save_preprocessed(self, features: pd.DataFrame, labels_multiclass: pd.Series, 
                         labels_binary: pd.Series, label_mapping: dict, output_dir: str):
        """
        Save preprocessed data to files.
        
        Args:
            features: Preprocessed features DataFrame
            labels_multiclass: Multiclass labels Series
            labels_binary: Binary labels Series
            label_mapping: Dictionary mapping labels to numeric values
            output_dir: Directory to save output files
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Save features
        features.to_csv(output_path / 'network_features.csv', index=False)
        
        # Save multiclass labels
        labels_multiclass.to_csv(output_path / 'network_labels_multiclass.csv', index=False, header=['label'])
        
        # Save binary labels
        labels_binary.to_csv(output_path / 'network_labels_binary.csv', index=False, header=['label'])
        
        # Save combined (with binary labels for simplicity)
        combined = features.copy()
        combined['label_multiclass'] = labels_multiclass.values
        combined['label_binary'] = labels_binary.values
        combined.to_csv(output_path / 'network_preprocessed.csv', index=False)
        
        # Save label mapping
        import json
        with open(output_path / 'label_mapping.json', 'w') as f:
            json.dump(label_mapping, f, indent=2)
            
        # Save feature column names
        with open(output_path / 'feature_columns.txt', 'w') as f:
            f.write('\n'.join(self.feature_columns))
        
        print(f"Saved preprocessed data to {output_path}")


def main():
    """Main function to run Network preprocessing"""
    # Paths
    data_dir = Path(__file__).parent.parent.parent / 'data' / 'network_detect' / 'network' / 'MachineLearningCVE'
    output_dir = Path(__file__).parent.parent.parent / 'data' / 'processed' / 'network'
    
    # Initialize preprocessor
    preprocessor = NetworkPreprocessor(str(data_dir))
    
    # Load all data
    print("=" * 50)
    print("Loading Network Detection Data")
    print("=" * 50)
    raw_df = preprocessor.load_all_data()
    
    # Preprocess
    print("\n" + "=" * 50)
    print("Preprocessing Data")
    print("=" * 50)
    features, labels_multiclass, labels_binary, label_mapping = preprocessor.preprocess(raw_df)
    
    # Save preprocessed data
    print("\n" + "=" * 50)
    print("Saving Preprocessed Data")
    print("=" * 50)
    preprocessor.save_preprocessed(features, labels_multiclass, labels_binary, label_mapping, str(output_dir))
    
    print("\nNetwork preprocessing complete!")


if __name__ == '__main__':
    main()
