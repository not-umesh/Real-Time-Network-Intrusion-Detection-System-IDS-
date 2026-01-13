"""
Benchmark tests for model inference performance.
Target: <1ms inference on Apple Silicon M1.
"""
import time
import numpy as np
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.absolute()
sys.path.insert(0, str(PROJECT_ROOT))


def test_inference_latency(num_iterations: int = 1000, target_ms: float = 1.0):
    """
    Test ML model inference latency.
    
    Args:
        num_iterations: Number of inference runs
        target_ms: Target latency in milliseconds
        
    Returns:
        True if target met, False otherwise
    """
    from models.coreml_wrapper import CoreMLModel
    
    print(f"\n{'='*60}")
    print("Model Inference Latency Benchmark")
    print(f"{'='*60}")
    
    # Initialize model
    print("\nLoading model...")
    model = CoreMLModel(use_coreml=True)
    
    # Generate test data
    print(f"Running {num_iterations} iterations...")
    test_data = np.random.randn(num_iterations, 115).astype(np.float32)
    
    # Warm-up runs
    for i in range(10):
        model.predict(test_data[i])
    
    # Benchmark runs
    latencies = []
    for i in range(num_iterations):
        start = time.perf_counter()
        model.predict(test_data[i])
        elapsed = (time.perf_counter() - start) * 1000
        latencies.append(elapsed)
    
    latencies = np.array(latencies)
    
    # Report results
    print(f"\nResults ({num_iterations} iterations):")
    print(f"  {'Mean:':<12} {np.mean(latencies):>8.3f} ms")
    print(f"  {'Median:':<12} {np.median(latencies):>8.3f} ms")
    print(f"  {'Min:':<12} {np.min(latencies):>8.3f} ms")
    print(f"  {'Max:':<12} {np.max(latencies):>8.3f} ms")
    print(f"  {'Std Dev:':<12} {np.std(latencies):>8.3f} ms")
    print(f"  {'P95:':<12} {np.percentile(latencies, 95):>8.3f} ms")
    print(f"  {'P99:':<12} {np.percentile(latencies, 99):>8.3f} ms")
    
    # Check target
    median_latency = np.median(latencies)
    target_met = median_latency < target_ms
    
    print(f"\n{'='*60}")
    if target_met:
        print(f"✅ TARGET MET: Median {median_latency:.3f}ms < {target_ms}ms target")
    else:
        print(f"❌ TARGET MISSED: Median {median_latency:.3f}ms >= {target_ms}ms target")
    print(f"{'='*60}")
    
    return target_met


def test_throughput(duration_sec: float = 5.0):
    """
    Test maximum inference throughput.
    
    Args:
        duration_sec: Duration to run throughput test
        
    Returns:
        Inferences per second achieved
    """
    from models.coreml_wrapper import CoreMLModel
    
    print(f"\n{'='*60}")
    print("Model Throughput Benchmark")
    print(f"{'='*60}")
    
    # Initialize model
    model = CoreMLModel(use_coreml=True)
    
    # Generate batch of test data
    batch_size = 100
    test_data = np.random.randn(batch_size, 115).astype(np.float32)
    
    # Warm-up
    for i in range(10):
        model.predict(test_data[i % batch_size])
    
    # Run throughput test
    print(f"\nRunning for {duration_sec} seconds...")
    start_time = time.time()
    count = 0
    
    while time.time() - start_time < duration_sec:
        model.predict(test_data[count % batch_size])
        count += 1
    
    elapsed = time.time() - start_time
    throughput = count / elapsed
    
    print(f"\nResults:")
    print(f"  Total inferences: {count:,}")
    print(f"  Duration: {elapsed:.2f}s")
    print(f"  Throughput: {throughput:,.0f} inferences/sec")
    
    return throughput


def test_batch_inference(batch_sizes: list = None):
    """
    Test batch inference performance.
    
    Args:
        batch_sizes: List of batch sizes to test
    """
    from models.coreml_wrapper import CoreMLModel
    
    if batch_sizes is None:
        batch_sizes = [1, 8, 16, 32, 64, 128]
    
    print(f"\n{'='*60}")
    print("Batch Inference Benchmark")
    print(f"{'='*60}")
    
    model = CoreMLModel(use_coreml=True)
    
    print(f"\n{'Batch Size':<12} {'Latency (ms)':<15} {'Per Sample (ms)':<15}")
    print("-" * 45)
    
    for batch_size in batch_sizes:
        test_data = np.random.randn(batch_size, 115).astype(np.float32)
        
        # Warm-up
        for _ in range(5):
            model.predict(test_data)
        
        # Benchmark
        latencies = []
        for _ in range(100):
            start = time.perf_counter()
            model.predict(test_data)
            elapsed = (time.perf_counter() - start) * 1000
            latencies.append(elapsed)
        
        avg_latency = np.mean(latencies)
        per_sample = avg_latency / batch_size
        
        print(f"{batch_size:<12} {avg_latency:<15.3f} {per_sample:<15.4f}")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Model Benchmark Tests")
    parser.add_argument("--latency", action="store_true", help="Run latency test")
    parser.add_argument("--throughput", action="store_true", help="Run throughput test")
    parser.add_argument("--batch", action="store_true", help="Run batch test")
    parser.add_argument("--all", action="store_true", help="Run all tests")
    parser.add_argument("-n", type=int, default=1000, help="Number of iterations")
    
    args = parser.parse_args()
    
    if args.all or (not args.latency and not args.throughput and not args.batch):
        test_inference_latency(args.n)
        test_throughput()
        test_batch_inference()
    else:
        if args.latency:
            test_inference_latency(args.n)
        if args.throughput:
            test_throughput()
        if args.batch:
            test_batch_inference()
