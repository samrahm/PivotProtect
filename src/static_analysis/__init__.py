# Static Analysis Module for PivotProtect
# Nabiha's Part - Day 1 & Day 2

from .parser import LogParser, LogEntry
from .dsa_structures import HashMap, Trie, Graph
from .dsa_structures import create_ip_frequency_map, create_endpoint_trie, create_ip_endpoint_graph
from .static_detector import StaticDetector, DetectionResult, Threat, DetectionConfig
from .static_detector import run_static_analysis

__all__ = [
    # Parser
    'LogParser',
    'LogEntry', 
    # DSA Structures
    'HashMap',
    'Trie',
    'Graph',
    'create_ip_frequency_map',
    'create_endpoint_trie',
    'create_ip_endpoint_graph',
    # Detector (Day 2)
    'StaticDetector',
    'DetectionResult',
    'Threat',
    'DetectionConfig',
    'run_static_analysis',
]
