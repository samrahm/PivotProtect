"""
Performance Benchmark for DSA Structures
Measures HashMap, Trie, and Graph operations
Evaluates Big-O complexity on N = 10³, 10⁴, 10⁵ input sizes
Reports average over ≥3 runs with standard deviation
"""

import os
import sys
import time
import statistics
import random
from typing import Callable, List, Tuple, Dict, Any

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from static_analysis.dsa_structures import HashMap, Trie, Graph


class PerformanceBenchmark:
    """Benchmark DSA operations with timing and complexity analysis"""
    
    def __init__(self, num_runs: int = 5):
        self.num_runs = num_runs
        self.results: Dict[str, Dict[str, Any]] = {}
        random.seed(42)
    
    def time_operation(self, operation: Callable, *args) -> float:
        """Time a single operation in seconds"""
        start = time.perf_counter()
        operation(*args)
        return time.perf_counter() - start
    
    def benchmark_operation(self, name: str, setup: Callable, operation: Callable, sizes: List[int]) -> Dict:
        """Benchmark an operation across different input sizes"""
        results = {
            'name': name,
            'sizes': sizes,
            'avg_times': [],
            'std_devs': [],
            'complexity': None
        }
        
        for size in sizes:
            times = []
            for _ in range(self.num_runs):
                # Setup fresh data structure
                ds, test_data = setup(size)
                
                # Time the operation
                elapsed = self.time_operation(operation, ds, test_data)
                times.append(elapsed)
            
            avg_time = statistics.mean(times)
            std_dev = statistics.stdev(times) if len(times) > 1 else 0
            results['avg_times'].append(avg_time)
            results['std_devs'].append(std_dev)
        
        # Estimate complexity
        results['complexity'] = self._estimate_complexity(sizes, results['avg_times'])
        return results
    
    def _estimate_complexity(self, sizes: List[int], times: List[float]) -> str:
        """Estimate Big-O complexity based on timing data"""
        if len(sizes) < 2 or len(times) < 2:
            return "Unknown"
        
        # Calculate growth ratios
        ratios = []
        for i in range(1, len(sizes)):
            if times[i-1] > 0 and times[i] > 0:
                size_ratio = sizes[i] / sizes[i-1]
                time_ratio = times[i] / times[i-1]
                ratios.append(time_ratio / size_ratio)
        
        if not ratios:
            return "Unknown"
        
        avg_ratio = statistics.mean(ratios)
        
        # Classify complexity
        if avg_ratio < 0.2:
            return "O(1) - Constant"
        elif avg_ratio < 0.8:
            return "O(log n) - Logarithmic"
        elif avg_ratio < 1.5:
            return "O(n) - Linear"
        elif avg_ratio < 3.0:
            return "O(n log n) - Linearithmic"
        else:
            return "O(n²) - Quadratic"


class DSABenchmarks:
    """Specific benchmarks for HashMap, Trie, and Graph"""
    
    def __init__(self, benchmark: PerformanceBenchmark):
        self.benchmark = benchmark
        self.sizes = [1000, 10000, 100000]  # N = 10³, 10⁴, 10⁵
    
    # ==================== HASHMAP BENCHMARKS ====================
    
    def hashmap_insert_setup(self, size: int) -> Tuple[HashMap, List]:
        """Setup for HashMap insert benchmark"""
        hm = HashMap()
        keys = [f"ip_{i}_{random.randint(1,255)}.{random.randint(1,255)}" for i in range(size)]
        return hm, keys
    
    def hashmap_insert_operation(self, hm: HashMap, keys: List[str]):
        """Insert all keys into HashMap"""
        for key in keys:
            hm.put(key, 1)
    
    def hashmap_lookup_setup(self, size: int) -> Tuple[HashMap, List]:
        """Setup for HashMap lookup benchmark - pre-populated map"""
        hm = HashMap()
        keys = [f"ip_{i}_{random.randint(1,255)}.{random.randint(1,255)}" for i in range(size)]
        for key in keys:
            hm.put(key, 1)
        # Use same keys for lookup
        return hm, keys
    
    def hashmap_lookup_operation(self, hm: HashMap, keys: List[str]):
        """Lookup all keys in HashMap"""
        for key in keys:
            hm.get(key)
    
    def hashmap_increment_setup(self, size: int) -> Tuple[HashMap, List]:
        """Setup for HashMap increment benchmark"""
        hm = HashMap()
        keys = [f"ip_{i % 100}" for i in range(size)]  # Many collisions
        for key in keys:
            hm.put(key, 0)
        return hm, keys
    
    def hashmap_increment_operation(self, hm: HashMap, keys: List[str]):
        """Increment values for all keys"""
        for key in keys:
            current = hm.get(key) or 0
            hm.put(key, current + 1)
    
    # ==================== TRIE BENCHMARKS ====================
    
    def trie_insert_setup(self, size: int) -> Tuple[Trie, List]:
        """Setup for Trie insert benchmark"""
        trie = Trie()
        paths = []
        base_paths = ["/api", "/admin", "/users", "/products", "/static"]
        for i in range(size):
            base = random.choice(base_paths)
            path = f"{base}/v{i % 10}/item{i}"
            paths.append(path)
        return trie, paths
    
    def trie_insert_operation(self, trie: Trie, paths: List[str]):
        """Insert all paths into Trie"""
        for path in paths:
            trie.insert(path)
    
    def trie_search_setup(self, size: int) -> Tuple[Trie, List]:
        """Setup for Trie search benchmark - pre-populated trie"""
        trie = Trie()
        paths = []
        base_paths = ["/api", "/admin", "/users", "/products", "/static"]
        for i in range(size):
            base = random.choice(base_paths)
            path = f"{base}/v{i % 10}/item{i}"
            paths.append(path)
            trie.insert(path)
        return trie, paths
    
    def trie_search_operation(self, trie: Trie, paths: List[str]):
        """Search all paths in Trie"""
        for path in paths:
            trie.search(path)
    
    def trie_prefix_search_setup(self, size: int) -> Tuple[Trie, List]:
        """Setup for Trie prefix search benchmark"""
        trie = Trie()
        base_paths = ["/api", "/admin", "/users", "/products", "/static"]
        for i in range(size):
            base = random.choice(base_paths)
            path = f"{base}/v{i % 10}/item{i}"
            trie.insert(path)
        return trie, base_paths
    
    def trie_prefix_operation(self, trie: Trie, prefixes: List[str]):
        """Find all paths starting with each prefix"""
        for prefix in prefixes:
            trie.starts_with(prefix)
    
    # ==================== GRAPH BENCHMARKS ====================
    
    def graph_add_edge_setup(self, size: int) -> Tuple[Graph, List]:
        """Setup for Graph add edge benchmark"""
        graph = Graph()
        edges = []
        for i in range(size):
            src = f"192.168.1.{i % 255}"
            dst = f"10.0.0.{i % 255}"
            edges.append((src, dst))
        return graph, edges
    
    def graph_add_edge_operation(self, graph: Graph, edges: List[Tuple]):
        """Add all edges to Graph"""
        for src, dst in edges:
            graph.add_edge(src, dst)
    
    def graph_get_neighbors_setup(self, size: int) -> Tuple[Graph, List]:
        """Setup for Graph get neighbors benchmark"""
        graph = Graph()
        nodes = [f"192.168.1.{i % 255}" for i in range(min(size // 10, 1000))]
        for i in range(size):
            src = nodes[i % len(nodes)]
            dst = f"10.0.0.{i % 255}"
            graph.add_edge(src, dst)
        return graph, nodes
    
    def graph_get_neighbors_operation(self, graph: Graph, nodes: List[str]):
        """Get neighbors for all source nodes"""
        for node in nodes:
            graph.get_neighbors(node)
    
    def graph_degree_setup(self, size: int) -> Tuple[Graph, List]:
        """Setup for Graph high degree benchmark"""
        graph = Graph()
        nodes = [f"192.168.1.{i % 255}" for i in range(min(size // 10, 1000))]
        for i in range(size):
            src = nodes[i % len(nodes)]
            dst = f"10.0.0.{i % 255}"
            graph.add_edge(src, dst)
        return graph, [5]  # threshold
    
    def graph_degree_operation(self, graph: Graph, thresholds: List[int]):
        """Find high degree nodes"""
        for threshold in thresholds:
            graph.get_high_degree_nodes(threshold)
    
    def run_all_benchmarks(self) -> Dict[str, Dict]:
        """Run all DSA benchmarks"""
        all_results = {}
        
        print("\n" + "=" * 70)
        print("HASHMAP BENCHMARKS")
        print("=" * 70)
        
        result = self.benchmark.benchmark_operation(
            "HashMap Insert",
            self.hashmap_insert_setup,
            self.hashmap_insert_operation,
            self.sizes
        )
        all_results['hashmap_insert'] = result
        self._print_result(result)
        
        result = self.benchmark.benchmark_operation(
            "HashMap Lookup",
            self.hashmap_lookup_setup,
            self.hashmap_lookup_operation,
            self.sizes
        )
        all_results['hashmap_lookup'] = result
        self._print_result(result)
        
        result = self.benchmark.benchmark_operation(
            "HashMap Increment",
            self.hashmap_increment_setup,
            self.hashmap_increment_operation,
            self.sizes
        )
        all_results['hashmap_increment'] = result
        self._print_result(result)
        
        print("\n" + "=" * 70)
        print("TRIE BENCHMARKS")
        print("=" * 70)
        
        result = self.benchmark.benchmark_operation(
            "Trie Insert",
            self.trie_insert_setup,
            self.trie_insert_operation,
            self.sizes
        )
        all_results['trie_insert'] = result
        self._print_result(result)
        
        result = self.benchmark.benchmark_operation(
            "Trie Search",
            self.trie_search_setup,
            self.trie_search_operation,
            self.sizes
        )
        all_results['trie_search'] = result
        self._print_result(result)
        
        result = self.benchmark.benchmark_operation(
            "Trie Prefix Search",
            self.trie_prefix_search_setup,
            self.trie_prefix_operation,
            self.sizes
        )
        all_results['trie_prefix'] = result
        self._print_result(result)
        
        print("\n" + "=" * 70)
        print("GRAPH BENCHMARKS")
        print("=" * 70)
        
        result = self.benchmark.benchmark_operation(
            "Graph Add Edge",
            self.graph_add_edge_setup,
            self.graph_add_edge_operation,
            self.sizes
        )
        all_results['graph_add_edge'] = result
        self._print_result(result)
        
        result = self.benchmark.benchmark_operation(
            "Graph Get Neighbors",
            self.graph_get_neighbors_setup,
            self.graph_get_neighbors_operation,
            self.sizes
        )
        all_results['graph_neighbors'] = result
        self._print_result(result)
        
        result = self.benchmark.benchmark_operation(
            "Graph High Degree Nodes",
            self.graph_degree_setup,
            self.graph_degree_operation,
            self.sizes
        )
        all_results['graph_degree'] = result
        self._print_result(result)
        
        return all_results
    
    def _print_result(self, result: Dict):
        """Pretty print benchmark result"""
        print(f"\n📊 {result['name']}")
        print("-" * 50)
        print(f"{'Size':<12} {'Avg Time (s)':<15} {'Std Dev':<12}")
        print("-" * 50)
        
        for i, size in enumerate(result['sizes']):
            avg = result['avg_times'][i]
            std = result['std_devs'][i]
            print(f"{size:<12,} {avg:<15.6f} {std:<12.6f}")
        
        print("-" * 50)
        print(f"📈 Estimated Complexity: {result['complexity']}")


def print_summary(results: Dict[str, Dict]):
    """Print a summary table of all results"""
    print("\n" + "=" * 70)
    print("PERFORMANCE SUMMARY")
    print("=" * 70)
    print(f"\n{'Operation':<25} {'Complexity':<20} {'N=10³ (s)':<12} {'N=10⁵ (s)':<12}")
    print("-" * 70)
    
    for key, result in results.items():
        name = result['name'][:24]
        complexity = result['complexity'].split(' - ')[0]
        time_small = result['avg_times'][0]
        time_large = result['avg_times'][2]
        print(f"{name:<25} {complexity:<20} {time_small:<12.6f} {time_large:<12.6f}")
    
    print("-" * 70)
    print("\nExpected Big-O Complexities:")
    print("  • HashMap Operations: O(1) average case")
    print("  • Trie Insert/Search: O(m) where m = key length")
    print("  • Trie Prefix Search: O(m + k) where k = matching entries")
    print("  • Graph Add Edge: O(1)")
    print("  • Graph Neighbors: O(1)")
    print("  • Graph High Degree: O(V) where V = number of vertices")


def main():
    print("=" * 70)
    print("PivotProtect DSA Performance Benchmark")
    print("Evaluating HashMap, Trie, and Graph on N = 10³, 10⁴, 10⁵")
    print("=" * 70)
    
    benchmark = PerformanceBenchmark(num_runs=5)
    dsa_benchmarks = DSABenchmarks(benchmark)
    
    results = dsa_benchmarks.run_all_benchmarks()
    print_summary(results)
    
    print("\n✅ Benchmark complete!")
    print("=" * 70)


if __name__ == "__main__":
    main()
