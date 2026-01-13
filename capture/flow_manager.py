"""
Flow Manager for Network Traffic
Aggregates packets into flows and manages flow lifecycle.
"""
import asyncio
import time
from typing import Dict, List, Optional, Tuple, Callable
from collections import defaultdict
from dataclasses import dataclass
import threading

from models.feature_extractor import (
    FeatureExtractor, PacketInfo, FlowKey, FeatureScaler
)
import numpy as np


@dataclass
class FlowManagerConfig:
    """Configuration for flow manager"""
    flow_timeout: float = 120.0  # Seconds before flow expires
    cleanup_interval: float = 10.0  # Seconds between cleanup runs
    max_flows: int = 100000  # Maximum concurrent flows
    feature_dim: int = 115  # Number of features per flow


class FlowManager:
    """
    Manages network flows and feature extraction.
    
    Responsibilities:
    - Aggregate packets into bidirectional flows
    - Track flow statistics and timing
    - Extract features when flows complete
    - Clean up expired flows
    """
    
    def __init__(self, config: FlowManagerConfig = None):
        self.config = config or FlowManagerConfig()
        self.extractor = FeatureExtractor(flow_timeout=self.config.flow_timeout)
        self.scaler = FeatureScaler()
        
        # Flow completion callbacks
        self._flow_callbacks: List[Callable[[FlowKey, np.ndarray], None]] = []
        
        # Statistics
        self._stats = defaultdict(int)
        self._lock = threading.Lock()
        
        # Cleanup task
        self._cleanup_running = False
        self._cleanup_thread: Optional[threading.Thread] = None
    
    def start_cleanup(self):
        """Start background flow cleanup"""
        if self._cleanup_running:
            return
        
        self._cleanup_running = True
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            daemon=True
        )
        self._cleanup_thread.start()
    
    def stop_cleanup(self):
        """Stop background cleanup"""
        self._cleanup_running = False
        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=2.0)
    
    def _cleanup_loop(self):
        """Background cleanup loop"""
        while self._cleanup_running:
            time.sleep(self.config.cleanup_interval)
            self._cleanup_expired_flows()
    
    def _cleanup_expired_flows(self):
        """Remove expired flows and extract their features"""
        current_time = time.time()
        
        with self._lock:
            expired = self.extractor.cleanup_expired_flows(current_time)
        
        for flow_key, features in expired:
            self._stats['flows_expired'] += 1
            self._handle_completed_flow(flow_key, features)
    
    def add_packet(self, packet: PacketInfo) -> Optional[Tuple[FlowKey, np.ndarray]]:
        """
        Add packet to flow manager.
        
        Returns (flow_key, features) if flow completed, None otherwise.
        """
        with self._lock:
            self._stats['packets_processed'] += 1
            
            completed_flow = self.extractor.add_packet(packet)
            
            if completed_flow:
                features = self.extractor.get_flow_and_remove(completed_flow)
                if features is not None:
                    self._stats['flows_completed'] += 1
                    self._handle_completed_flow(completed_flow, features)
                    return (completed_flow, features)
        
        return None
    
    def _handle_completed_flow(self, flow_key: FlowKey, features: np.ndarray):
        """Handle completed flow: scale features and notify callbacks"""
        # Scale features if scaler is fitted
        if self.scaler.fitted:
            features = self.scaler.transform(features.reshape(1, -1)).flatten()
        
        # Notify callbacks
        for callback in self._flow_callbacks:
            try:
                callback(flow_key, features)
            except Exception as e:
                print(f"Flow callback error: {e}")
    
    def add_flow_callback(self, callback: Callable[[FlowKey, np.ndarray], None]):
        """Register callback for completed flows"""
        self._flow_callbacks.append(callback)
    
    def get_active_flow_count(self) -> int:
        """Get number of active flows"""
        with self._lock:
            return len(self.extractor.flows)
    
    def get_flow_features(self, flow_key: FlowKey) -> Optional[np.ndarray]:
        """Get features for specific flow (without removing it)"""
        with self._lock:
            return self.extractor.extract_features(flow_key)
    
    def get_stats(self) -> Dict:
        """Get flow manager statistics"""
        with self._lock:
            return {
                'packets_processed': self._stats['packets_processed'],
                'flows_completed': self._stats['flows_completed'],
                'flows_expired': self._stats['flows_expired'],
                'active_flows': len(self.extractor.flows),
                'cleanup_running': self._cleanup_running
            }
    
    def reset_stats(self):
        """Reset statistics"""
        with self._lock:
            self._stats.clear()
    
    def fit_scaler(self, training_features: np.ndarray):
        """Fit feature scaler on training data"""
        self.scaler.fit(training_features)
        print(f"✓ Scaler fitted on {len(training_features)} samples")
    
    def load_scaler(self, path: str):
        """Load scaler from file"""
        self.scaler.load(path)
        print(f"✓ Scaler loaded from {path}")


class AsyncFlowManager:
    """
    Async wrapper for FlowManager.
    Provides asyncio-compatible interface for flow management.
    """
    
    def __init__(self, config: FlowManagerConfig = None):
        self.manager = FlowManager(config)
        self._detection_callback: Optional[Callable] = None
    
    def set_detection_callback(self, callback: Callable[[FlowKey, np.ndarray, bool, float], None]):
        """
        Set callback for detection results.
        
        Callback signature: (flow_key, features, is_anomaly, confidence)
        """
        self._detection_callback = callback
    
    async def start(self):
        """Start async flow manager"""
        self.manager.start_cleanup()
    
    async def stop(self):
        """Stop async flow manager"""
        self.manager.stop_cleanup()
    
    async def process_packet(self, packet: PacketInfo) -> Optional[Tuple[FlowKey, np.ndarray]]:
        """Process packet asynchronously"""
        # Run in thread pool to avoid blocking
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.manager.add_packet, packet)
    
    def add_packet_sync(self, packet: PacketInfo) -> Optional[Tuple[FlowKey, np.ndarray]]:
        """Process packet synchronously (for use in callbacks)"""
        return self.manager.add_packet(packet)


def get_flow_summary(flow_key: FlowKey, features: np.ndarray) -> str:
    """Get human-readable flow summary"""
    duration_us = features[0]
    fwd_packets = int(features[1])
    bwd_packets = int(features[2])
    fwd_bytes = int(features[3])
    bwd_bytes = int(features[4])
    
    return (
        f"{flow_key.src_ip}:{flow_key.src_port} <-> "
        f"{flow_key.dst_ip}:{flow_key.dst_port} | "
        f"Duration: {duration_us/1000:.1f}ms | "
        f"Packets: {fwd_packets}↑ {bwd_packets}↓ | "
        f"Bytes: {fwd_bytes}↑ {bwd_bytes}↓"
    )


if __name__ == "__main__":
    # Test flow manager
    print("Testing Flow Manager...")
    
    manager = FlowManager()
    manager.start_cleanup()
    
    # Simulate packets
    base_time = time.time()
    
    test_packets = [
        PacketInfo(base_time, "10.0.0.1", "10.0.0.2", 12345, 80, 6, 100, 50, 0x02, 20, 65535),
        PacketInfo(base_time + 0.01, "10.0.0.2", "10.0.0.1", 80, 12345, 6, 60, 0, 0x12, 20, 65535),
        PacketInfo(base_time + 0.02, "10.0.0.1", "10.0.0.2", 12345, 80, 6, 54, 0, 0x10, 20, 65535),
        PacketInfo(base_time + 0.1, "10.0.0.1", "10.0.0.2", 12345, 80, 6, 500, 450, 0x18, 20, 65535),
        PacketInfo(base_time + 0.2, "10.0.0.2", "10.0.0.1", 80, 12345, 6, 1500, 1450, 0x18, 20, 65535),
        PacketInfo(base_time + 0.3, "10.0.0.1", "10.0.0.2", 12345, 80, 6, 54, 0, 0x11, 20, 65535),  # FIN
    ]
    
    for pkt in test_packets:
        result = manager.add_packet(pkt)
        if result:
            flow_key, features = result
            print(f"\n✓ Flow completed!")
            print(f"  {get_flow_summary(flow_key, features)}")
    
    stats = manager.get_stats()
    print(f"\nStatistics:")
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    manager.stop_cleanup()
    print("\n✓ Flow manager test complete!")
