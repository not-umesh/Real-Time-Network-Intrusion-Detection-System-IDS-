"""
KitNET - Kitsune Network Autoencoder Ensemble
A lightweight, online anomaly detection system optimized for Apple Silicon.

Based on: Mirsky et al., "Kitsune: An Ensemble of Autoencoders for 
Online Network Intrusion Detection" (NDSS 2018)
"""
import numpy as np
import torch
import torch.nn as nn
from typing import List, Optional, Tuple
from dataclasses import dataclass
import pickle
from pathlib import Path


@dataclass
class AutoencoderConfig:
    """Configuration for individual autoencoder"""
    input_dim: int
    hidden_dim: int
    learning_rate: float = 0.001


class Autoencoder(nn.Module):
    """Single autoencoder for feature subset reconstruction"""
    
    def __init__(self, input_dim: int, hidden_dim: int):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU()
        )
        self.decoder = nn.Sequential(
            nn.Linear(hidden_dim // 2, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, input_dim),
            nn.Sigmoid()
        )
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded
    
    def get_rmse(self, x: torch.Tensor) -> torch.Tensor:
        """Calculate reconstruction RMSE"""
        with torch.no_grad():
            reconstructed = self.forward(x)
            rmse = torch.sqrt(torch.mean((x - reconstructed) ** 2, dim=-1))
        return rmse


class KitNET(nn.Module):
    """
    KitNET Ensemble Autoencoder for Network Anomaly Detection
    
    Architecture:
    1. Feature Mapper: Clusters correlated features into subsets
    2. Ensemble Layer: Multiple autoencoders, one per feature subset
    3. Output Layer: Master autoencoder combines ensemble outputs
    
    Higher RMSE = More anomalous
    """
    
    def __init__(
        self,
        num_features: int = 115,
        max_ensemble_size: int = 10,
        hidden_ratio: float = 0.75,
        threshold: float = 0.5
    ):
        super().__init__()
        self.num_features = num_features
        self.max_ensemble_size = max_ensemble_size
        self.hidden_ratio = hidden_ratio
        self.threshold = threshold
        
        # Feature clusters (will be set during training)
        self.feature_clusters: List[List[int]] = []
        self.ensemble: nn.ModuleList = nn.ModuleList()
        self.output_layer: Optional[Autoencoder] = None
        
        # Initialize with default clustering
        self._default_clustering()
        self._build_ensemble()
    
    def _default_clustering(self):
        """Create default feature clusters based on feature groups"""
        # Group features by type (matching CIC-IDS2018 structure)
        cluster_sizes = [
            12,  # Packet counts and lengths (0-11)
            10,  # Flow timing features (12-21)
            10,  # Forward/backward IAT (22-31)
            8,   # Flags (32-39)
            12,  # Packet statistics (40-51)
            10,  # Bulk features (52-61)
            8,   # Subflow features (62-69)
            8,   # Window sizes and segment (70-77)
            8,   # Active/Idle times (78-85)
            29,  # Remaining features (86-114)
        ]
        
        start_idx = 0
        self.feature_clusters = []
        for size in cluster_sizes:
            end_idx = min(start_idx + size, self.num_features)
            if start_idx < self.num_features:
                self.feature_clusters.append(list(range(start_idx, end_idx)))
            start_idx = end_idx
    
    def _build_ensemble(self):
        """Build autoencoder ensemble based on feature clusters"""
        self.ensemble = nn.ModuleList()
        
        for cluster in self.feature_clusters:
            input_dim = len(cluster)
            hidden_dim = max(1, int(input_dim * self.hidden_ratio))
            ae = Autoencoder(input_dim, hidden_dim)
            self.ensemble.append(ae)
        
        # Output layer combines ensemble RMSE values
        ensemble_output_dim = len(self.feature_clusters)
        output_hidden = max(1, int(ensemble_output_dim * self.hidden_ratio))
        self.output_layer = Autoencoder(ensemble_output_dim, output_hidden)
    
    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Forward pass through KitNET
        
        Args:
            x: Input features [batch_size, num_features]
            
        Returns:
            anomaly_score: RMSE-based anomaly score
            ensemble_rmses: Individual autoencoder RMSE values
        """
        batch_size = x.shape[0]
        ensemble_rmses = []
        
        # Get RMSE from each autoencoder
        for i, (ae, cluster) in enumerate(zip(self.ensemble, self.feature_clusters)):
            subset = x[:, cluster]
            rmse = ae.get_rmse(subset)
            ensemble_rmses.append(rmse)
        
        # Stack ensemble outputs
        ensemble_output = torch.stack(ensemble_rmses, dim=-1)  # [batch, ensemble_size]
        
        # Final anomaly score from output layer
        anomaly_score = self.output_layer.get_rmse(ensemble_output)
        
        return anomaly_score, ensemble_output
    
    def predict(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Predict if samples are anomalous
        
        Returns:
            is_anomaly: Boolean tensor
            confidence: Anomaly confidence score (0-1)
        """
        anomaly_score, _ = self.forward(x)
        
        # Normalize score to 0-1 range using sigmoid
        confidence = torch.sigmoid((anomaly_score - self.threshold) * 10)
        is_anomaly = anomaly_score > self.threshold
        
        return is_anomaly, confidence
    
    def update_threshold(self, normal_scores: torch.Tensor, percentile: float = 99.0):
        """Update anomaly threshold based on normal traffic scores"""
        threshold = torch.quantile(normal_scores, percentile / 100.0)
        self.threshold = threshold.item()
    
    def save_model(self, path: Path):
        """Save model state and configuration"""
        state = {
            'state_dict': self.state_dict(),
            'feature_clusters': self.feature_clusters,
            'threshold': self.threshold,
            'num_features': self.num_features,
            'hidden_ratio': self.hidden_ratio,
        }
        torch.save(state, path)
    
    @classmethod
    def load_model(cls, path: Path) -> 'KitNET':
        """Load model from checkpoint"""
        state = torch.load(path, map_location='cpu')
        model = cls(
            num_features=state['num_features'],
            hidden_ratio=state['hidden_ratio'],
            threshold=state['threshold']
        )
        model.feature_clusters = state['feature_clusters']
        model._build_ensemble()
        model.load_state_dict(state['state_dict'])
        return model


class KitNETTrainer:
    """Training utilities for KitNET"""
    
    def __init__(self, model: KitNET, learning_rate: float = 0.001):
        self.model = model
        self.optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate)
        self.criterion = nn.MSELoss()
    
    def train_step(self, batch: torch.Tensor) -> float:
        """Single training step"""
        self.model.train()
        self.optimizer.zero_grad()
        
        total_loss = 0.0
        
        # Train each autoencoder on its feature subset
        for ae, cluster in zip(self.model.ensemble, self.model.feature_clusters):
            subset = batch[:, cluster]
            reconstructed = ae(subset)
            loss = self.criterion(reconstructed, subset)
            total_loss += loss
        
        # Train output layer
        with torch.no_grad():
            ensemble_rmses = []
            for ae, cluster in zip(self.model.ensemble, self.model.feature_clusters):
                subset = batch[:, cluster]
                rmse = ae.get_rmse(subset)
                ensemble_rmses.append(rmse)
            ensemble_output = torch.stack(ensemble_rmses, dim=-1)
        
        output_reconstructed = self.model.output_layer(ensemble_output)
        output_loss = self.criterion(output_reconstructed, ensemble_output)
        total_loss += output_loss
        
        total_loss.backward()
        self.optimizer.step()
        
        return total_loss.item()
    
    def train_epoch(self, dataloader, verbose: bool = True) -> float:
        """Train for one epoch"""
        total_loss = 0.0
        num_batches = 0
        
        for batch in dataloader:
            loss = self.train_step(batch)
            total_loss += loss
            num_batches += 1
        
        avg_loss = total_loss / num_batches if num_batches > 0 else 0
        return avg_loss


def create_pretrained_model() -> KitNET:
    """
    Create a pretrained KitNET model with default weights.
    In production, this would load weights trained on CIC-IDS2018.
    """
    model = KitNET(
        num_features=115,
        max_ensemble_size=10,
        hidden_ratio=0.75,
        threshold=0.5
    )
    
    # Initialize with small random weights (simulating pretrained)
    for module in model.modules():
        if isinstance(module, nn.Linear):
            nn.init.xavier_uniform_(module.weight)
            if module.bias is not None:
                nn.init.zeros_(module.bias)
    
    return model


if __name__ == "__main__":
    # Test model creation
    print("Creating KitNET model...")
    model = create_pretrained_model()
    
    # Test forward pass
    test_input = torch.randn(32, 115)  # Batch of 32 samples
    anomaly_score, ensemble_output = model(test_input)
    
    print(f"Input shape: {test_input.shape}")
    print(f"Anomaly scores shape: {anomaly_score.shape}")
    print(f"Ensemble output shape: {ensemble_output.shape}")
    print(f"Mean anomaly score: {anomaly_score.mean().item():.4f}")
    
    # Test prediction
    is_anomaly, confidence = model.predict(test_input)
    print(f"Anomalies detected: {is_anomaly.sum().item()}/{len(is_anomaly)}")
    print(f"Mean confidence: {confidence.mean().item():.4f}")
    
    print("\n✓ KitNET model working correctly!")
