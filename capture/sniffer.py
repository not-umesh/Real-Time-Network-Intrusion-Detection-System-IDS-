"""
Real-Time Packet Sniffer using Scapy
Optimized for macOS and Apple Silicon.
"""
import asyncio
import queue
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional, Dict, Any
from collections import defaultdict

try:
    from scapy.all import sniff, IP, TCP, UDP, Ether, conf
    from scapy.layers.inet import ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from models.feature_extractor import PacketInfo, TCPFlags


@dataclass
class SnifferConfig:
    """Packet sniffer configuration"""
    interface: str = "en0"
    filter: str = "ip"  # BPF filter
    promisc: bool = True
    buffer_size: int = 10000
    timeout: float = 0.1


class PacketSniffer:
    """
    Asynchronous packet sniffer using scapy.
    
    Captures packets from network interface and converts them
    to PacketInfo objects for feature extraction.
    """
    
    def __init__(self, config: SnifferConfig = None):
        if not SCAPY_AVAILABLE:
            raise ImportError("scapy is required. Install with: pip install scapy")
        
        self.config = config or SnifferConfig()
        self.packet_queue: queue.Queue = queue.Queue(maxsize=self.config.buffer_size)
        self._running = False
        self._sniff_thread: Optional[threading.Thread] = None
        self._stats = defaultdict(int)
        self._start_time = 0.0
        
        # Suppress scapy warnings
        conf.verb = 0
    
    def start(self):
        """Start packet capture in background thread"""
        if self._running:
            return
        
        self._running = True
        self._start_time = time.time()
        self._sniff_thread = threading.Thread(
            target=self._sniff_loop,
            daemon=True
        )
        self._sniff_thread.start()
        print(f"✓ Packet sniffer started on {self.config.interface}")
    
    def stop(self):
        """Stop packet capture"""
        self._running = False
        if self._sniff_thread:
            self._sniff_thread.join(timeout=2.0)
        print("✓ Packet sniffer stopped")
    
    def _sniff_loop(self):
        """Background sniffing loop"""
        try:
            sniff(
                iface=self.config.interface,
                filter=self.config.filter,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda _: not self._running,
                timeout=self.config.timeout if not self._running else None
            )
        except Exception as e:
            print(f"Sniffer error: {e}")
            self._running = False
    
    def _process_packet(self, packet):
        """Process captured packet and add to queue"""
        try:
            # Extract IP layer
            if not packet.haslayer(IP):
                return
            
            ip_layer = packet[IP]
            
            # Determine protocol and ports
            src_port = 0
            dst_port = 0
            tcp_flags = 0
            header_length = 0
            window_size = 0
            
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                tcp_flags = int(tcp_layer.flags)
                header_length = tcp_layer.dataofs * 4 if tcp_layer.dataofs else 20
                window_size = tcp_layer.window
                protocol = 6
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                src_port = udp_layer.sport
                dst_port = udp_layer.dport
                header_length = 8
                protocol = 17
            else:
                protocol = ip_layer.proto
            
            # Calculate lengths
            total_length = len(packet)
            ip_header_length = ip_layer.ihl * 4 if ip_layer.ihl else 20
            payload_length = max(0, total_length - ip_header_length - header_length)
            
            # Create PacketInfo
            pkt_info = PacketInfo(
                timestamp=float(packet.time),
                src_ip=ip_layer.src,
                dst_ip=ip_layer.dst,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                length=total_length,
                payload_length=payload_length,
                tcp_flags=tcp_flags,
                header_length=header_length,
                window_size=window_size
            )
            
            # Add to queue (non-blocking)
            try:
                self.packet_queue.put_nowait(pkt_info)
                self._stats['captured'] += 1
            except queue.Full:
                self._stats['dropped'] += 1
                
        except Exception as e:
            self._stats['errors'] += 1
    
    def get_packet(self, timeout: float = 0.1) -> Optional[PacketInfo]:
        """Get next packet from queue"""
        try:
            return self.packet_queue.get(timeout=timeout)
        except queue.Empty:
            return None
    
    def get_packets(self, max_count: int = 100) -> list:
        """Get multiple packets from queue"""
        packets = []
        for _ in range(max_count):
            try:
                pkt = self.packet_queue.get_nowait()
                packets.append(pkt)
            except queue.Empty:
                break
        return packets
    
    def get_stats(self) -> Dict[str, Any]:
        """Get capture statistics"""
        runtime = time.time() - self._start_time if self._start_time else 0
        return {
            'captured': self._stats['captured'],
            'dropped': self._stats['dropped'],
            'errors': self._stats['errors'],
            'queue_size': self.packet_queue.qsize(),
            'runtime_sec': runtime,
            'packets_per_sec': self._stats['captured'] / max(1, runtime),
            'interface': self.config.interface,
            'running': self._running
        }
    
    @property
    def is_running(self) -> bool:
        return self._running


class AsyncPacketSniffer:
    """
    Async wrapper for packet sniffer.
    Provides asyncio-compatible interface for packet capture.
    """
    
    def __init__(self, config: SnifferConfig = None):
        self.sniffer = PacketSniffer(config)
        self._callbacks = []
    
    def add_callback(self, callback: Callable[[PacketInfo], None]):
        """Add packet processing callback"""
        self._callbacks.append(callback)
    
    async def start(self):
        """Start async packet capture"""
        self.sniffer.start()
    
    async def stop(self):
        """Stop async packet capture"""
        self.sniffer.stop()
    
    async def process_packets(self, batch_size: int = 100, interval: float = 0.01):
        """
        Async generator yielding packets.
        
        Usage:
            async for packet in sniffer.process_packets():
                process(packet)
        """
        while self.sniffer.is_running:
            packets = self.sniffer.get_packets(batch_size)
            
            for pkt in packets:
                # Call registered callbacks
                for callback in self._callbacks:
                    try:
                        callback(pkt)
                    except Exception as e:
                        print(f"Callback error: {e}")
                
                yield pkt
            
            if not packets:
                await asyncio.sleep(interval)


def test_capture(interface: str = "en0", duration: float = 10):
    """Test packet capture on specified interface"""
    print(f"\n{'='*50}")
    print(f"Testing packet capture on {interface}")
    print(f"Duration: {duration} seconds")
    print(f"{'='*50}\n")
    
    config = SnifferConfig(interface=interface)
    sniffer = PacketSniffer(config)
    
    try:
        sniffer.start()
        
        start_time = time.time()
        packet_count = 0
        
        while time.time() - start_time < duration:
            packets = sniffer.get_packets(100)
            for pkt in packets:
                packet_count += 1
                if packet_count <= 10:  # Show first 10 packets
                    print(f"  [{packet_count}] {pkt.src_ip}:{pkt.src_port} -> "
                          f"{pkt.dst_ip}:{pkt.dst_port} | "
                          f"Proto: {'TCP' if pkt.protocol == 6 else 'UDP' if pkt.protocol == 17 else pkt.protocol} | "
                          f"Len: {pkt.length}")
            
            time.sleep(0.01)
        
        stats = sniffer.get_stats()
        print(f"\n{'='*50}")
        print(f"Capture Statistics:")
        print(f"  Packets captured: {stats['captured']}")
        print(f"  Packets dropped:  {stats['dropped']}")
        print(f"  Queue size:       {stats['queue_size']}")
        print(f"  Packets/sec:      {stats['packets_per_sec']:.2f}")
        print(f"{'='*50}")
        
    finally:
        sniffer.stop()


if __name__ == "__main__":
    import sys
    interface = sys.argv[1] if len(sys.argv) > 1 else "en0"
    duration = float(sys.argv[2]) if len(sys.argv) > 2 else 10
    test_capture(interface, duration)
