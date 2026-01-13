"""
Tests for feature extraction module.
"""
import pytest
import numpy as np
import time
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.absolute()
sys.path.insert(0, str(PROJECT_ROOT))

from models.feature_extractor import (
    FeatureExtractor, PacketInfo, FlowKey, TCPFlags, FeatureScaler
)


class TestPacketInfo:
    """Test PacketInfo dataclass"""
    
    def test_create_packet_info(self):
        """Test creating a PacketInfo object"""
        pkt = PacketInfo(
            timestamp=time.time(),
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=12345,
            dst_port=80,
            protocol=6,
            length=100,
            payload_length=50,
            tcp_flags=TCPFlags.SYN,
            header_length=20,
            window_size=65535
        )
        
        assert pkt.src_ip == "192.168.1.1"
        assert pkt.dst_ip == "192.168.1.2"
        assert pkt.protocol == 6


class TestFlowKey:
    """Test FlowKey dataclass"""
    
    def test_flow_key_hash(self):
        """Test FlowKey hashing"""
        key1 = FlowKey("1.1.1.1", "2.2.2.2", 100, 200, 6)
        key2 = FlowKey("1.1.1.1", "2.2.2.2", 100, 200, 6)
        
        assert hash(key1) == hash(key2)
        assert key1 == key2
    
    def test_flow_key_reversed(self):
        """Test FlowKey reversal"""
        key = FlowKey("1.1.1.1", "2.2.2.2", 100, 200, 6)
        reversed_key = key.reversed()
        
        assert reversed_key.src_ip == "2.2.2.2"
        assert reversed_key.dst_ip == "1.1.1.1"
        assert reversed_key.src_port == 200
        assert reversed_key.dst_port == 100


class TestFeatureExtractor:
    """Test FeatureExtractor class"""
    
    def test_create_extractor(self):
        """Test creating a FeatureExtractor"""
        extractor = FeatureExtractor(flow_timeout=60.0)
        assert extractor.flow_timeout == 60.0
        assert len(extractor.flows) == 0
    
    def test_add_packet_new_flow(self):
        """Test adding packet to new flow"""
        extractor = FeatureExtractor()
        
        pkt = PacketInfo(
            timestamp=time.time(),
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=1234,
            dst_port=80,
            protocol=6,
            length=100,
            payload_length=50,
            tcp_flags=TCPFlags.SYN
        )
        
        result = extractor.add_packet(pkt)
        
        # First packet shouldn't complete flow
        assert result is None
        assert len(extractor.flows) == 1
    
    def test_add_packet_completes_flow(self):
        """Test that FIN flag completes flow"""
        extractor = FeatureExtractor()
        base_time = time.time()
        
        packets = [
            PacketInfo(base_time, "10.0.0.1", "10.0.0.2", 1234, 80, 6, 100, 50, TCPFlags.SYN, 20, 65535),
            PacketInfo(base_time + 0.01, "10.0.0.2", "10.0.0.1", 80, 1234, 6, 60, 0, TCPFlags.SYN | TCPFlags.ACK, 20, 65535),
            PacketInfo(base_time + 0.02, "10.0.0.1", "10.0.0.2", 1234, 80, 6, 54, 0, TCPFlags.FIN | TCPFlags.ACK, 20, 65535),
        ]
        
        result = None
        for pkt in packets:
            result = extractor.add_packet(pkt)
        
        # FIN should complete the flow
        assert result is not None
    
    def test_extract_features_shape(self):
        """Test that extracted features have correct shape"""
        extractor = FeatureExtractor()
        base_time = time.time()
        
        # Add some packets
        packets = [
            PacketInfo(base_time, "10.0.0.1", "10.0.0.2", 1234, 80, 6, 100, 50, TCPFlags.SYN, 20, 65535),
            PacketInfo(base_time + 0.01, "10.0.0.2", "10.0.0.1", 80, 1234, 6, 60, 0, TCPFlags.SYN | TCPFlags.ACK, 20, 65535),
            PacketInfo(base_time + 0.02, "10.0.0.1", "10.0.0.2", 1234, 80, 6, 500, 450, TCPFlags.PSH | TCPFlags.ACK, 20, 65535),
        ]
        
        for pkt in packets:
            extractor.add_packet(pkt)
        
        # Extract features for active flow
        for flow_key in list(extractor.flows.keys()):
            features = extractor.extract_features(flow_key)
            
            assert features is not None
            assert features.shape == (115,)
            assert features.dtype == np.float32
    
    def test_flow_bidirectional_matching(self):
        """Test that reverse packets are matched to same flow"""
        extractor = FeatureExtractor()
        base_time = time.time()
        
        # Forward packet
        pkt1 = PacketInfo(base_time, "10.0.0.1", "10.0.0.2", 1234, 80, 6, 100, 50, TCPFlags.SYN, 20, 65535)
        extractor.add_packet(pkt1)
        
        # Reverse packet (same flow, opposite direction)
        pkt2 = PacketInfo(base_time + 0.01, "10.0.0.2", "10.0.0.1", 80, 1234, 6, 60, 0, TCPFlags.SYN | TCPFlags.ACK, 20, 65535)
        extractor.add_packet(pkt2)
        
        # Should still be one flow
        assert len(extractor.flows) == 1


class TestFeatureScaler:
    """Test FeatureScaler class"""
    
    def test_fit_transform(self):
        """Test fitting and transforming features"""
        scaler = FeatureScaler()
        
        # Create sample data
        data = np.random.randn(100, 115).astype(np.float32)
        data = np.abs(data) * 1000  # Make values positive and scaled
        
        # Fit
        scaler.fit(data)
        assert scaler.fitted
        
        # Transform
        scaled = scaler.transform(data)
        
        assert scaled.shape == data.shape
        assert np.all(scaled >= 0)
        assert np.all(scaled <= 1)
    
    def test_transform_without_fit_raises(self):
        """Test that transform without fit raises error"""
        scaler = FeatureScaler()
        data = np.random.randn(10, 115).astype(np.float32)
        
        with pytest.raises(ValueError):
            scaler.transform(data)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
