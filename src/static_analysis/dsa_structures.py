"""
DSA Structures for PivotProtect Static Analysis
Implements HashMap, Trie, and Graph for efficient log analysis.
"""

from typing import List, Dict, Optional, Set, Any
from collections import defaultdict


# =============================================================================
# HASHMAP IMPLEMENTATION
# =============================================================================

class HashMap:
    """
    Custom HashMap implementation for storing IP frequencies and log data.
    Uses separate chaining for collision resolution.
    """
    
    def __init__(self, initial_capacity: int = 16, load_factor: float = 0.75):
        """
        Initialize HashMap.
        
        Args:
            initial_capacity: Initial number of buckets
            load_factor: Threshold for resizing (size/capacity)
        """
        self.capacity = initial_capacity
        self.load_factor = load_factor
        self.size = 0
        self.buckets: List[List] = [[] for _ in range(self.capacity)]
    
    def _hash(self, key: str) -> int:
        """
        Compute hash value for a key.
        
        Args:
            key: The key to hash
            
        Returns:
            Bucket index
        """
        hash_value = 0
        for char in str(key):
            hash_value = (hash_value * 31 + ord(char)) % self.capacity
        return hash_value
    
    def _resize(self):
        """Double the capacity and rehash all entries"""
        old_buckets = self.buckets
        self.capacity *= 2
        self.buckets = [[] for _ in range(self.capacity)]
        self.size = 0
        
        for bucket in old_buckets:
            for key, value in bucket:
                self.put(key, value)
    
    def put(self, key: str, value: Any) -> None:
        """
        Insert or update a key-value pair.
        
        Args:
            key: The key
            value: The value to store
        """
        # Check if resize needed
        if self.size / self.capacity >= self.load_factor:
            self._resize()
        
        index = self._hash(key)
        bucket = self.buckets[index]
        
        # Check if key exists, update if so
        for i, (k, v) in enumerate(bucket):
            if k == key:
                bucket[i] = (key, value)
                return
        
        # Key doesn't exist, add new entry
        bucket.append((key, value))
        self.size += 1
    
    def get(self, key: str) -> Optional[Any]:
        """
        Retrieve value for a key.
        
        Args:
            key: The key to look up
            
        Returns:
            The value or None if not found
        """
        index = self._hash(key)
        bucket = self.buckets[index]
        
        for k, v in bucket:
            if k == key:
                return v
        return None
    
    def contains(self, key: str) -> bool:
        """Check if key exists in the map"""
        return self.get(key) is not None
    
    def remove(self, key: str) -> Optional[Any]:
        """
        Remove a key-value pair.
        
        Args:
            key: The key to remove
            
        Returns:
            The removed value or None
        """
        index = self._hash(key)
        bucket = self.buckets[index]
        
        for i, (k, v) in enumerate(bucket):
            if k == key:
                bucket.pop(i)
                self.size -= 1
                return v
        return None
    
    def keys(self) -> List[str]:
        """Get all keys in the map"""
        all_keys = []
        for bucket in self.buckets:
            for key, _ in bucket:
                all_keys.append(key)
        return all_keys
    
    def values(self) -> List[Any]:
        """Get all values in the map"""
        all_values = []
        for bucket in self.buckets:
            for _, value in bucket:
                all_values.append(value)
        return all_values
    
    def items(self) -> List[tuple]:
        """Get all key-value pairs"""
        all_items = []
        for bucket in self.buckets:
            for key, value in bucket:
                all_items.append((key, value))
        return all_items
    
    def increment(self, key: str, amount: int = 1) -> int:
        """
        Increment a counter value for a key.
        
        Args:
            key: The key to increment
            amount: Amount to add (default 1)
            
        Returns:
            New value after increment
        """
        current = self.get(key)
        if current is None:
            current = 0
        new_value = current + amount
        self.put(key, new_value)
        return new_value
    
    def get_top_n(self, n: int = 10) -> List[tuple]:
        """
        Get top N items by value (assumes numeric values).
        
        Args:
            n: Number of top items to return
            
        Returns:
            List of (key, value) tuples sorted by value descending
        """
        return sorted(self.items(), key=lambda x: x[1], reverse=True)[:n]
    
    def __len__(self) -> int:
        return self.size
    
    def __str__(self) -> str:
        return str(dict(self.items()))


# =============================================================================
# TRIE IMPLEMENTATION
# =============================================================================

class TrieNode:
    """Node in a Trie structure"""
    
    def __init__(self):
        self.children: Dict[str, 'TrieNode'] = {}
        self.is_end: bool = False
        self.count: int = 0  # Number of times this path was inserted
        self.data: Any = None  # Optional data associated with this node


class Trie:
    """
    Trie (Prefix Tree) implementation for URL/endpoint pattern matching.
    Useful for detecting path traversal attacks and analyzing endpoint patterns.
    """
    
    def __init__(self, delimiter: str = '/'):
        """
        Initialize Trie.
        
        Args:
            delimiter: Character to split paths (default '/')
        """
        self.root = TrieNode()
        self.delimiter = delimiter
        self.total_insertions = 0
    
    def _tokenize(self, path: str) -> List[str]:
        """
        Split path into tokens.
        
        Args:
            path: The path string to tokenize
            
        Returns:
            List of path segments
        """
        # Remove leading delimiter and split
        path = path.strip(self.delimiter)
        if not path:
            return []
        return path.split(self.delimiter)
    
    def insert(self, path: str, data: Any = None) -> None:
        """
        Insert a path into the Trie.
        
        Args:
            path: The path to insert (e.g., "/usr/admin/developer")
            data: Optional data to associate with this path
        """
        tokens = self._tokenize(path)
        node = self.root
        
        for token in tokens:
            if token not in node.children:
                node.children[token] = TrieNode()
            node = node.children[token]
            node.count += 1
        
        node.is_end = True
        node.data = data
        self.total_insertions += 1
    
    def search(self, path: str) -> bool:
        """
        Check if exact path exists in Trie.
        
        Args:
            path: The path to search for
            
        Returns:
            True if path exists, False otherwise
        """
        tokens = self._tokenize(path)
        node = self.root
        
        for token in tokens:
            if token not in node.children:
                return False
            node = node.children[token]
        
        return node.is_end
    
    def starts_with(self, prefix: str) -> bool:
        """
        Check if any path starts with the given prefix.
        
        Args:
            prefix: The prefix to check
            
        Returns:
            True if any path has this prefix
        """
        tokens = self._tokenize(prefix)
        node = self.root
        
        for token in tokens:
            if token not in node.children:
                return False
            node = node.children[token]
        
        return True
    
    def get_count(self, path: str) -> int:
        """
        Get the number of insertions for a path prefix.
        
        Args:
            path: The path to check
            
        Returns:
            Count of insertions through this path
        """
        tokens = self._tokenize(path)
        node = self.root
        
        for token in tokens:
            if token not in node.children:
                return 0
            node = node.children[token]
        
        return node.count
    
    def get_all_paths(self) -> List[str]:
        """
        Get all complete paths in the Trie.
        
        Returns:
            List of all paths
        """
        paths = []
        self._collect_paths(self.root, [], paths)
        return paths
    
    def _collect_paths(self, node: TrieNode, current_path: List[str], paths: List[str]):
        """Recursively collect all paths"""
        if node.is_end:
            paths.append(self.delimiter + self.delimiter.join(current_path))
        
        for token, child in node.children.items():
            current_path.append(token)
            self._collect_paths(child, current_path, paths)
            current_path.pop()
    
    def find_suspicious_patterns(self) -> List[str]:
        """
        Find suspicious patterns like path traversal attempts.
        
        Returns:
            List of suspicious paths
        """
        suspicious = []
        all_paths = self.get_all_paths()
        
        suspicious_indicators = ['..', '%2e', '%2E', 'etc', 'passwd', 'shadow', 
                                  'config', '.git', '.env', 'backup']
        
        for path in all_paths:
            for indicator in suspicious_indicators:
                if indicator in path:
                    suspicious.append(path)
                    break
        
        return suspicious
    
    def get_path_depth_distribution(self) -> Dict[int, int]:
        """
        Get distribution of path depths.
        
        Returns:
            Dictionary mapping depth to count
        """
        depths = {}
        for path in self.get_all_paths():
            depth = len(self._tokenize(path))
            depths[depth] = depths.get(depth, 0) + 1
        return depths


# =============================================================================
# GRAPH IMPLEMENTATION
# =============================================================================

class Graph:
    """
    Graph implementation for analyzing connections between IPs, endpoints, etc.
    Uses adjacency list representation.
    """
    
    def __init__(self, directed: bool = True):
        """
        Initialize Graph.
        
        Args:
            directed: Whether the graph is directed (default True)
        """
        self.directed = directed
        self.adjacency_list: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self.node_data: Dict[str, Dict] = {}  # Store additional node data
        self.edge_count = 0
    
    def add_node(self, node: str, data: Dict = None) -> None:
        """
        Add a node to the graph.
        
        Args:
            node: Node identifier
            data: Optional data dictionary for the node
        """
        if node not in self.adjacency_list:
            self.adjacency_list[node] = defaultdict(int)
        if data:
            self.node_data[node] = data
    
    def add_edge(self, source: str, target: str, weight: int = 1) -> None:
        """
        Add an edge between two nodes.
        
        Args:
            source: Source node
            target: Target node
            weight: Edge weight (default 1, can be used for counting)
        """
        self.add_node(source)
        self.add_node(target)
        
        self.adjacency_list[source][target] += weight
        self.edge_count += 1
        
        if not self.directed:
            self.adjacency_list[target][source] += weight
    
    def get_neighbors(self, node: str) -> List[str]:
        """
        Get all neighbors of a node.
        
        Args:
            node: The node to get neighbors for
            
        Returns:
            List of neighbor nodes
        """
        return list(self.adjacency_list[node].keys())
    
    def get_edge_weight(self, source: str, target: str) -> int:
        """
        Get the weight of an edge.
        
        Args:
            source: Source node
            target: Target node
            
        Returns:
            Edge weight (0 if edge doesn't exist)
        """
        return self.adjacency_list[source][target]
    
    def get_out_degree(self, node: str) -> int:
        """Get number of outgoing edges from a node"""
        return len(self.adjacency_list[node])
    
    def get_in_degree(self, node: str) -> int:
        """Get number of incoming edges to a node"""
        count = 0
        for source in self.adjacency_list:
            if node in self.adjacency_list[source]:
                count += 1
        return count
    
    def get_total_weight_out(self, node: str) -> int:
        """Get total weight of outgoing edges"""
        return sum(self.adjacency_list[node].values())
    
    def get_nodes(self) -> List[str]:
        """Get all nodes in the graph"""
        return list(self.adjacency_list.keys())
    
    def get_high_degree_nodes(self, threshold: int = 10) -> List[tuple]:
        """
        Find nodes with high out-degree (potential attackers or targets).
        
        Args:
            threshold: Minimum degree to be considered high
            
        Returns:
            List of (node, degree) tuples
        """
        high_degree = []
        for node in self.adjacency_list:
            degree = self.get_out_degree(node)
            if degree >= threshold:
                high_degree.append((node, degree))
        return sorted(high_degree, key=lambda x: x[1], reverse=True)
    
    def get_heavy_edges(self, threshold: int = 5) -> List[tuple]:
        """
        Find edges with high weight (frequent connections).
        
        Args:
            threshold: Minimum weight to be considered heavy
            
        Returns:
            List of (source, target, weight) tuples
        """
        heavy = []
        for source in self.adjacency_list:
            for target, weight in self.adjacency_list[source].items():
                if weight >= threshold:
                    heavy.append((source, target, weight))
        return sorted(heavy, key=lambda x: x[2], reverse=True)
    
    def bfs(self, start: str) -> List[str]:
        """
        Breadth-first search from a starting node.
        
        Args:
            start: Starting node
            
        Returns:
            List of nodes in BFS order
        """
        if start not in self.adjacency_list:
            return []
        
        visited = set()
        queue = [start]
        result = []
        
        while queue:
            node = queue.pop(0)
            if node not in visited:
                visited.add(node)
                result.append(node)
                for neighbor in self.adjacency_list[node]:
                    if neighbor not in visited:
                        queue.append(neighbor)
        
        return result
    
    def find_connected_components(self) -> List[Set[str]]:
        """
        Find all connected components in the graph.
        
        Returns:
            List of sets, each containing nodes in a component
        """
        visited = set()
        components = []
        
        for node in self.adjacency_list:
            if node not in visited:
                component = set()
                self._dfs_component(node, visited, component)
                components.append(component)
        
        return components
    
    def _dfs_component(self, node: str, visited: Set[str], component: Set[str]):
        """DFS helper for finding connected components"""
        visited.add(node)
        component.add(node)
        
        for neighbor in self.adjacency_list[node]:
            if neighbor not in visited:
                self._dfs_component(neighbor, visited, component)
    
    def get_statistics(self) -> Dict:
        """
        Get graph statistics.
        
        Returns:
            Dictionary with graph statistics
        """
        nodes = self.get_nodes()
        num_nodes = len(nodes)
        
        if num_nodes == 0:
            return {'nodes': 0, 'edges': 0}
        
        degrees = [self.get_out_degree(n) for n in nodes]
        
        return {
            'nodes': num_nodes,
            'edges': self.edge_count,
            'avg_degree': sum(degrees) / num_nodes,
            'max_degree': max(degrees),
            'min_degree': min(degrees),
            'components': len(self.find_connected_components())
        }
    
    def __str__(self) -> str:
        stats = self.get_statistics()
        return f"Graph(nodes={stats['nodes']}, edges={stats['edges']})"


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def create_ip_frequency_map(entries: List) -> HashMap:
    """
    Create a HashMap of IP frequencies from log entries.
    
    Args:
        entries: List of LogEntry objects
        
    Returns:
        HashMap with IP as key and count as value
    """
    ip_map = HashMap()
    for entry in entries:
        ip_map.increment(entry.ip)
    return ip_map


def create_endpoint_trie(entries: List) -> Trie:
    """
    Create a Trie of endpoints from log entries.
    
    Args:
        entries: List of LogEntry objects
        
    Returns:
        Trie containing all endpoints
    """
    trie = Trie()
    for entry in entries:
        trie.insert(entry.endpoint)
    return trie


def create_ip_endpoint_graph(entries: List) -> Graph:
    """
    Create a Graph connecting IPs to endpoints they accessed.
    
    Args:
        entries: List of LogEntry objects
        
    Returns:
        Graph with IPs and endpoints as nodes
    """
    graph = Graph(directed=True)
    for entry in entries:
        graph.add_edge(entry.ip, entry.endpoint)
    return graph


# =============================================================================
# TEST / DEMO
# =============================================================================

def main():
    """Test the DSA structures"""
    print("=" * 50)
    print("Testing DSA Structures")
    print("=" * 50)
    
    # Test HashMap
    print("\n--- HashMap Test ---")
    hm = HashMap()
    hm.put("192.168.1.1", 5)
    hm.put("192.168.1.2", 3)
    hm.increment("192.168.1.1", 2)
    print(f"192.168.1.1 count: {hm.get('192.168.1.1')}")
    print(f"All items: {hm.items()}")
    
    # Test Trie
    print("\n--- Trie Test ---")
    trie = Trie()
    trie.insert("/usr/admin")
    trie.insert("/usr/admin/developer")
    trie.insert("/usr/login")
    trie.insert("/usr/../../../etc/passwd")  # Suspicious
    print(f"Search /usr/admin: {trie.search('/usr/admin')}")
    print(f"Starts with /usr: {trie.starts_with('/usr')}")
    print(f"All paths: {trie.get_all_paths()}")
    print(f"Suspicious: {trie.find_suspicious_patterns()}")
    
    # Test Graph
    print("\n--- Graph Test ---")
    graph = Graph()
    graph.add_edge("192.168.1.1", "/usr/admin")
    graph.add_edge("192.168.1.1", "/usr/login")
    graph.add_edge("192.168.1.1", "/usr/admin")  # Repeated access
    graph.add_edge("192.168.1.2", "/usr/login")
    print(f"Graph stats: {graph.get_statistics()}")
    print(f"Neighbors of 192.168.1.1: {graph.get_neighbors('192.168.1.1')}")
    print(f"Edge weight (192.168.1.1 -> /usr/admin): {graph.get_edge_weight('192.168.1.1', '/usr/admin')}")


if __name__ == '__main__':
    main()
