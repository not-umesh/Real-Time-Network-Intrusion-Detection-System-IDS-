"""
Core ML Wrapper for KitNET Model
Provides <1ms inference on Apple Silicon using Neural Engine acceleration.
"""
import numpy as np
import torch
from pathlib import Path
from typing import Tuple, Optional, Union
import time
import os

# Optional Core ML support (only on macOS)
try:
    import coremltools as ct
    COREML_AVAILABLE = True
except ImportError:
    COREML_AVAILABLE = False
    ct = None


class CoreMLModel:
    """
    Wrapper for KitNET model with Core ML acceleration.
    
    Falls back to PyTorch if Core ML is not available or model isn't converted.
    Designed for <1ms inference on Apple Silicon M1/M2/M3.
    """
    
    def __init__(
        self,
        model_path: Optional[Path] = None,
        pytorch_path: Optional[Path] = None,
        use_coreml: bool = True
    ):
        self.use_coreml = use_coreml and COREML_AVAILABLE
        self.coreml_model = None
        self.pytorch_model = None
        self.scaler = None
        self._inference_times = []
        
        # Default paths
        project_root = Path(__file__).parent.parent
        self.model_path = model_path or project_root / "models" / "pretrained" / "kitnet_cicids2018.mlmodel"
        self.pytorch_path = pytorch_path or project_root / "models" / "pretrained" / "kitnet_cicids2018.pt"
        self.scaler_path = project_root / "models" / "pretrained" / "scaler.pkl"
        
        self._load_model()
    
    def _load_model(self):
        """Load the appropriate model (Core ML or PyTorch)"""
        # Try loading Core ML model first
        if self.use_coreml and self.model_path.exists():
            try:
                self.coreml_model = ct.models.MLModel(str(self.model_path))
                print(f"✓ Loaded Core ML model from {self.model_path}")
                return
            except Exception as e:
                print(f"⚠ Could not load Core ML model: {e}")
        
        # Fall back to PyTorch
        self._load_pytorch_model()
    
    def _load_pytorch_model(self):
        """Load PyTorch model"""
        from .kitnet import KitNET, create_pretrained_model
        
        if self.pytorch_path.exists():
            try:
                self.pytorch_model = KitNET.load_model(self.pytorch_path)
                self.pytorch_model.eval()
                print(f"✓ Loaded PyTorch model from {self.pytorch_path}")
            except Exception as e:
                print(f"⚠ Could not load PyTorch checkpoint: {e}")
                self.pytorch_model = create_pretrained_model()
                self.pytorch_model.eval()
                print("✓ Created new PyTorch model with default weights")
        else:
            self.pytorch_model = create_pretrained_model()
            self.pytorch_model.eval()
            print("✓ Created new PyTorch model with default weights")
    
    def _load_scaler(self):
        """Load feature scaler if available"""
        if self.scaler_path.exists():
            import pickle
            with open(self.scaler_path, 'rb') as f:
                self.scaler = pickle.load(f)
    
    def predict(
        self,
        features: Union[np.ndarray, torch.Tensor],
        return_confidence: bool = True
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        Predict anomalies from feature vectors.
        
        Args:
            features: Input features, shape [batch_size, 115] or [115]
            return_confidence: Whether to return confidence scores
            
        Returns:
            is_anomaly: Boolean array of anomaly predictions
            confidence: Confidence scores (0-1)
        """
        start_time = time.perf_counter()
        
        # Ensure correct shape
        if isinstance(features, torch.Tensor):
            features = features.numpy()
        
        if features.ndim == 1:
            features = features.reshape(1, -1)
        
        # Apply scaling if available
        if self.scaler is not None:
            features = self.scaler.transform(features)
        
        # Run inference
        if self.coreml_model is not None:
            is_anomaly, confidence = self._predict_coreml(features)
        else:
            is_anomaly, confidence = self._predict_pytorch(features)
        
        # Track inference time
        inference_time = (time.perf_counter() - start_time) * 1000  # ms
        self._inference_times.append(inference_time)
        if len(self._inference_times) > 1000:
            self._inference_times = self._inference_times[-1000:]
        
        return is_anomaly, confidence
    
    def _predict_coreml(self, features: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Run inference using Core ML"""
        # Core ML expects specific input format
        input_dict = {"features": features.astype(np.float32)}
        
        predictions = self.coreml_model.predict(input_dict)
        
        # Extract outputs (adjust based on actual model output names)
        if "is_anomaly" in predictions:
            is_anomaly = predictions["is_anomaly"]
            confidence = predictions.get("confidence", np.ones_like(is_anomaly) * 0.5)
        else:
            # Assume first output is anomaly score
            anomaly_score = list(predictions.values())[0]
            threshold = 0.5
            is_anomaly = anomaly_score > threshold
            confidence = 1 / (1 + np.exp(-(anomaly_score - threshold) * 10))
        
        return np.asarray(is_anomaly, dtype=bool), np.asarray(confidence, dtype=np.float32)
    
    def _predict_pytorch(self, features: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Run inference using PyTorch"""
        with torch.no_grad():
            tensor_input = torch.from_numpy(features.astype(np.float32))
            is_anomaly, confidence = self.pytorch_model.predict(tensor_input)
        
        return is_anomaly.numpy(), confidence.numpy()
    
    def get_anomaly_score(self, features: Union[np.ndarray, torch.Tensor]) -> np.ndarray:
        """Get raw anomaly scores (RMSE values)"""
        if isinstance(features, torch.Tensor):
            features = features.numpy()
        
        if features.ndim == 1:
            features = features.reshape(1, -1)
        
        if self.pytorch_model is not None:
            with torch.no_grad():
                tensor_input = torch.from_numpy(features.astype(np.float32))
                scores, _ = self.pytorch_model(tensor_input)
            return scores.numpy()
        else:
            # For Core ML, use predict and extract score
            _, confidence = self.predict(features)
            return confidence
    
    def get_inference_stats(self) -> dict:
        """Get inference performance statistics"""
        if not self._inference_times:
            return {"avg_ms": 0, "min_ms": 0, "max_ms": 0, "count": 0}
        
        return {
            "avg_ms": np.mean(self._inference_times),
            "min_ms": np.min(self._inference_times),
            "max_ms": np.max(self._inference_times),
            "count": len(self._inference_times)
        }
    
    @staticmethod
    def convert_pytorch_to_coreml(
        pytorch_model,
        output_path: Path,
        input_shape: Tuple[int, int] = (1, 115)
    ) -> bool:
        """
        Convert PyTorch KitNET model to Core ML format.
        
        Args:
            pytorch_model: PyTorch KitNET model
            output_path: Path to save .mlmodel file
            input_shape: Expected input shape (batch_size, features)
            
        Returns:
            True if conversion successful, False otherwise
        """
        if not COREML_AVAILABLE:
            print("⚠ coremltools not installed. Install with: pip install coremltools")
            return False
        
        try:
            pytorch_model.eval()
            
            # Create traced model
            example_input = torch.randn(*input_shape)
            traced_model = torch.jit.trace(pytorch_model, example_input)
            
            # Convert to Core ML
            coreml_model = ct.convert(
                traced_model,
                inputs=[ct.TensorType(name="features", shape=input_shape)],
                outputs=[
                    ct.TensorType(name="anomaly_score"),
                    ct.TensorType(name="ensemble_output")
                ],
                compute_units=ct.ComputeUnit.ALL,  # Use Neural Engine when available
                minimum_deployment_target=ct.target.macOS13
            )
            
            # Add metadata
            coreml_model.author = "Real-Time IDS"
            coreml_model.short_description = "KitNET Anomaly Detection Model"
            coreml_model.version = "1.0"
            
            # Save model
            output_path.parent.mkdir(parents=True, exist_ok=True)
            coreml_model.save(str(output_path))
            
            print(f"✓ Saved Core ML model to {output_path}")
            return True
            
        except Exception as e:
            print(f"✗ Core ML conversion failed: {e}")
            return False


def benchmark_inference(num_iterations: int = 1000):
    """Benchmark inference performance"""
    print("\n" + "="*50)
    print("Benchmarking Model Inference")
    print("="*50)
    
    model = CoreMLModel(use_coreml=True)
    
    # Generate random test data
    test_data = np.random.randn(num_iterations, 115).astype(np.float32)
    
    # Warm-up
    for i in range(10):
        model.predict(test_data[i])
    
    # Benchmark
    times = []
    for i in range(num_iterations):
        start = time.perf_counter()
        model.predict(test_data[i])
        elapsed = (time.perf_counter() - start) * 1000
        times.append(elapsed)
    
    times = np.array(times)
    
    print(f"\nResults ({num_iterations} iterations):")
    print(f"  Average: {np.mean(times):.3f} ms")
    print(f"  Median:  {np.median(times):.3f} ms")
    print(f"  Min:     {np.min(times):.3f} ms")
    print(f"  Max:     {np.max(times):.3f} ms")
    print(f"  Std:     {np.std(times):.3f} ms")
    print(f"  P99:     {np.percentile(times, 99):.3f} ms")
    
    target_met = np.median(times) < 1.0
    print(f"\n{'✓' if target_met else '✗'} Target <1ms: {'MET' if target_met else 'NOT MET'}")
    
    return times


if __name__ == "__main__":
    # Test the model wrapper
    print("Testing Core ML Wrapper...")
    
    # Create model instance
    model = CoreMLModel(use_coreml=True)
    
    # Test prediction
    test_features = np.random.randn(5, 115).astype(np.float32)
    is_anomaly, confidence = model.predict(test_features)
    
    print(f"\nTest predictions:")
    print(f"  Input shape: {test_features.shape}")
    print(f"  Is anomaly: {is_anomaly}")
    print(f"  Confidence: {confidence}")
    
    # Get inference stats
    stats = model.get_inference_stats()
    print(f"\nInference stats: {stats}")
    
    # Run benchmark
    benchmark_inference(100)
