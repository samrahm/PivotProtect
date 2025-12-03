"""
EMBER (Endgame Malware BEnchmark for Research) Dataset Preprocessor
This module handles preprocessing of the EMBER 2017 malware detection dataset.
"""

import json
import pandas as pd
import numpy as np
from pathlib import Path
from typing import Tuple, List, Optional
import os


class EmberPreprocessor:
    """Preprocessor for EMBER malware dataset (JSONL format)"""
    
    def __init__(self, data_dir: str):
        """
        Initialize the EMBER preprocessor.
        
        Args:
            data_dir: Path to the ember_2017_2 directory containing JSONL files
        """
        self.data_dir = Path(data_dir)
        self.feature_columns = []
        
    def _extract_features_from_json(self, json_obj: dict) -> dict:
        """
        Extract flat features from a single EMBER JSON object.
        
        Args:
            json_obj: Dictionary containing EMBER sample features
            
        Returns:
            Dictionary with flattened features
        """
        features = {}
        
        # Extract histogram features (byte histogram - 256 values)
        if 'histogram' in json_obj:
            hist = json_obj['histogram']
            for i, val in enumerate(hist):
                features[f'histogram_{i}'] = val
                
        # Extract byteentropy features (256 values)
        if 'byteentropy' in json_obj:
            entropy = json_obj['byteentropy']
            for i, val in enumerate(entropy):
                features[f'byteentropy_{i}'] = val
                
        # Extract string features
        if 'strings' in json_obj:
            strings = json_obj['strings']
            features['strings_numstrings'] = strings.get('numstrings', 0)
            features['strings_avlength'] = strings.get('avlength', 0)
            features['strings_printables'] = strings.get('printables', 0)
            features['strings_entropy'] = strings.get('entropy', 0)
            features['strings_paths'] = strings.get('paths', 0)
            features['strings_urls'] = strings.get('urls', 0)
            features['strings_registry'] = strings.get('registry', 0)
            features['strings_MZ'] = strings.get('MZ', 0)
            
        # Extract general info features
        if 'general' in json_obj:
            general = json_obj['general']
            features['general_size'] = general.get('size', 0)
            features['general_vsize'] = general.get('vsize', 0)
            features['general_has_debug'] = int(general.get('has_debug', False))
            features['general_exports'] = general.get('exports', 0)
            features['general_imports'] = general.get('imports', 0)
            features['general_has_relocations'] = int(general.get('has_relocations', False))
            features['general_has_resources'] = int(general.get('has_resources', False))
            features['general_has_signature'] = int(general.get('has_signature', False))
            features['general_has_tls'] = int(general.get('has_tls', False))
            features['general_symbols'] = general.get('symbols', 0)
            
        # Extract header features
        if 'header' in json_obj:
            header = json_obj['header']
            # COFF header
            coff = header.get('coff', {})
            features['header_timestamp'] = coff.get('timestamp', 0)
            features['header_machine'] = hash(str(coff.get('machine', ''))) % (10**8)
            features['header_characteristics'] = len(coff.get('characteristics', []))
            
            # Optional header
            optional = header.get('optional', {})
            features['header_subsystem'] = hash(str(optional.get('subsystem', ''))) % (10**8)
            features['header_dll_characteristics'] = len(optional.get('dll_characteristics', []))
            features['header_magic'] = hash(str(optional.get('magic', ''))) % (10**8)
            features['header_major_image_version'] = optional.get('major_image_version', 0)
            features['header_minor_image_version'] = optional.get('minor_image_version', 0)
            features['header_major_linker_version'] = optional.get('major_linker_version', 0)
            features['header_minor_linker_version'] = optional.get('minor_linker_version', 0)
            features['header_major_operating_system_version'] = optional.get('major_operating_system_version', 0)
            features['header_minor_operating_system_version'] = optional.get('minor_operating_system_version', 0)
            features['header_major_subsystem_version'] = optional.get('major_subsystem_version', 0)
            features['header_minor_subsystem_version'] = optional.get('minor_subsystem_version', 0)
            features['header_sizeof_code'] = optional.get('sizeof_code', 0)
            features['header_sizeof_headers'] = optional.get('sizeof_headers', 0)
            features['header_sizeof_heap_commit'] = optional.get('sizeof_heap_commit', 0)
            
        # Extract section info
        if 'section' in json_obj:
            section = json_obj['section']
            # Section statistics
            features['section_entry'] = hash(str(section.get('entry', ''))) % (10**8)
            
            sections = section.get('sections', [])
            features['section_count'] = len(sections)
            
            # Aggregate section properties
            total_size = 0
            total_entropy = 0
            total_vsize = 0
            for sec in sections:
                total_size += sec.get('size', 0)
                total_entropy += sec.get('entropy', 0)
                total_vsize += sec.get('vsize', 0)
            features['section_total_size'] = total_size
            features['section_avg_entropy'] = total_entropy / max(len(sections), 1)
            features['section_total_vsize'] = total_vsize
            
        # Extract imports features
        if 'imports' in json_obj:
            imports = json_obj['imports']
            features['imports_dll_count'] = len(imports)
            total_functions = sum(len(funcs) for funcs in imports.values())
            features['imports_function_count'] = total_functions
            
            # Check for suspicious DLLs
            suspicious_dlls = ['ntdll.dll', 'kernel32.dll', 'advapi32.dll', 'ws2_32.dll']
            for dll in suspicious_dlls:
                features[f'imports_has_{dll.replace(".", "_")}'] = int(dll.lower() in [d.lower() for d in imports.keys()])
                
        # Extract exports features
        if 'exports' in json_obj:
            exports = json_obj['exports']
            features['exports_count'] = len(exports)
            
        # Extract data directories features
        if 'datadirectories' in json_obj:
            datadirs = json_obj['datadirectories']
            for dd in datadirs:
                name = dd.get('name', 'unknown').lower().replace(' ', '_')
                features[f'datadir_{name}_size'] = dd.get('size', 0)
                features[f'datadir_{name}_vaddr'] = dd.get('virtual_address', 0)
                
        # Extract label
        features['label'] = json_obj.get('label', -1)
        
        return features
    
    def load_jsonl_file(self, filepath: str, max_samples: Optional[int] = None) -> pd.DataFrame:
        """
        Load a single JSONL file and convert to DataFrame.
        
        Args:
            filepath: Path to the JSONL file
            max_samples: Maximum number of samples to load (None for all)
            
        Returns:
            DataFrame with extracted features
        """
        features_list = []
        
        print(f"Loading {filepath}...")
        with open(filepath, 'r') as f:
            for i, line in enumerate(f):
                if max_samples and i >= max_samples:
                    break
                try:
                    json_obj = json.loads(line.strip())
                    features = self._extract_features_from_json(json_obj)
                    features_list.append(features)
                except json.JSONDecodeError:
                    print(f"Warning: Could not parse line {i}")
                    continue
                    
                if (i + 1) % 10000 == 0:
                    print(f"  Processed {i + 1} samples...")
                    
        df = pd.DataFrame(features_list)
        print(f"  Loaded {len(df)} samples with {len(df.columns)} features")
        return df
    
    def load_all_training_data(self, max_samples_per_file: Optional[int] = None) -> pd.DataFrame:
        """
        Load all training JSONL files.
        
        Args:
            max_samples_per_file: Maximum samples to load from each file
            
        Returns:
            Combined DataFrame with all training data
        """
        train_files = sorted(self.data_dir.glob('train_features_*.jsonl'))
        
        dfs = []
        for train_file in train_files:
            df = self.load_jsonl_file(str(train_file), max_samples_per_file)
            dfs.append(df)
            
        if dfs:
            combined_df = pd.concat(dfs, ignore_index=True)
            print(f"\nTotal training samples: {len(combined_df)}")
            return combined_df
        return pd.DataFrame()
    
    def load_test_data(self, max_samples: Optional[int] = None) -> pd.DataFrame:
        """
        Load test JSONL file.
        
        Args:
            max_samples: Maximum samples to load
            
        Returns:
            DataFrame with test data
        """
        test_file = self.data_dir / 'test_features.jsonl'
        if test_file.exists():
            return self.load_jsonl_file(str(test_file), max_samples)
        return pd.DataFrame()
    
    def preprocess(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
        """
        Preprocess the loaded data.
        
        Args:
            df: DataFrame with raw features
            
        Returns:
            Tuple of (processed features DataFrame, labels Series)
        """
        # Separate features and labels
        if 'label' in df.columns:
            labels = df['label'].copy()
            features = df.drop('label', axis=1)
        else:
            labels = pd.Series()
            features = df.copy()
            
        # Handle missing values
        features = features.fillna(0)
        
        # Convert all columns to numeric
        for col in features.columns:
            features[col] = pd.to_numeric(features[col], errors='coerce').fillna(0)
            
        # Remove samples with unknown labels (-1)
        if len(labels) > 0:
            valid_mask = labels != -1
            features = features[valid_mask]
            labels = labels[valid_mask]
            
        # Normalize features (Min-Max scaling)
        for col in features.columns:
            col_min = features[col].min()
            col_max = features[col].max()
            if col_max > col_min:
                features[col] = (features[col] - col_min) / (col_max - col_min)
                
        print(f"Preprocessed data shape: {features.shape}")
        print(f"Label distribution:\n{labels.value_counts()}")
        
        return features, labels
    
    def save_preprocessed(self, features: pd.DataFrame, labels: pd.Series, output_dir: str):
        """
        Save preprocessed data to files.
        
        Args:
            features: Preprocessed features DataFrame
            labels: Labels Series
            output_dir: Directory to save output files
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Save features
        features.to_csv(output_path / 'ember_features.csv', index=False)
        
        # Save labels
        labels.to_csv(output_path / 'ember_labels.csv', index=False, header=['label'])
        
        # Save combined
        combined = features.copy()
        combined['label'] = labels.values
        combined.to_csv(output_path / 'ember_preprocessed.csv', index=False)
        
        # Save feature column names
        with open(output_path / 'feature_columns.txt', 'w') as f:
            f.write('\n'.join(features.columns.tolist()))
        
        print(f"Saved preprocessed data to {output_path}")


def main():
    """Main function to run EMBER preprocessing"""
    # Paths
    data_dir = Path(__file__).parent.parent.parent / 'data' / 'file_malware' / 'file_malware' / 'ember_2017_2'
    output_dir = Path(__file__).parent.parent.parent / 'data' / 'processed' / 'ember'
    
    # Initialize preprocessor
    preprocessor = EmberPreprocessor(str(data_dir))
    
    # Load training data (limit samples for testing)
    print("=" * 50)
    print("Loading Training Data")
    print("=" * 50)
    train_df = preprocessor.load_all_training_data(max_samples_per_file=5000)
    
    # Load test data
    print("\n" + "=" * 50)
    print("Loading Test Data")
    print("=" * 50)
    test_df = preprocessor.load_test_data(max_samples=5000)
    
    # Preprocess training data
    print("\n" + "=" * 50)
    print("Preprocessing Training Data")
    print("=" * 50)
    train_features, train_labels = preprocessor.preprocess(train_df)
    
    # Preprocess test data
    print("\n" + "=" * 50)
    print("Preprocessing Test Data")  
    print("=" * 50)
    test_features, test_labels = preprocessor.preprocess(test_df)
    
    # Save preprocessed data
    print("\n" + "=" * 50)
    print("Saving Preprocessed Data")
    print("=" * 50)
    preprocessor.save_preprocessed(train_features, train_labels, str(output_dir / 'train'))
    preprocessor.save_preprocessed(test_features, test_labels, str(output_dir / 'test'))
    
    print("\nEMBER preprocessing complete!")
    

if __name__ == '__main__':
    main()
