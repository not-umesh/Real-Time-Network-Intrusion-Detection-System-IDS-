#!/usr/bin/env python3
"""
Real-Time Network Intrusion Detection System
============================================

A complete, ready-to-run ML-based IDS optimized for MacBook Air M1.

Usage:
    sudo python main.py --interface en0 --telegram --dashboard

Author: Real-Time IDS Project
License: MIT

# ═══════════════════════════════════════════════
#         </> Crafted with bugs & coffee by UV
# ═══════════════════════════════════════════════
"""

import argparse
import asyncio
import signal
import sys
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Optional
import threading

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.absolute()
sys.path.insert(0, str(PROJECT_ROOT))

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv(PROJECT_ROOT / ".env")
except ImportError:
    pass

from rich.console import Console
from rich.panel import Panel
from rich.live import Live
from rich.table import Table
from rich.text import Text
from rich import box

from config import Config, load_config_from_env, ATTACK_LABELS
from models import CoreMLModel, FeatureExtractor, PacketInfo, FlowKey
from capture import PacketSniffer, FlowManager, SnifferConfig, FlowManagerConfig
from alerts import TelegramAlertBot, TelegramConfig, create_alert_from_detection

# Security module - OWASP compliant
from security import (
    RateLimiter, RateLimitConfig,
    InputValidator, ValidationRule, IDS_CONFIG_SCHEMA,
    SecureKeyManager
)

# Console for rich output
console = Console()

# Initialize security components
_rate_limiter = RateLimiter()
_key_manager = SecureKeyManager()
_config_validator = InputValidator(IDS_CONFIG_SCHEMA, reject_unknown=True)


class NetworkIDS:
    """
    Main Network Intrusion Detection System class.
    
    Coordinates packet capture, feature extraction, ML inference,
    and alert dispatching in a real-time pipeline.
    """
    
    def __init__(
        self,
        interface: str = "en0",
        enable_telegram: bool = True,
        enable_dashboard: bool = False,
        threshold: float = 0.5,
        verbose: bool = True
    ):
        self.interface = interface
        self.enable_telegram = enable_telegram
        self.enable_dashboard = enable_dashboard
        self.threshold = threshold
        self.verbose = verbose
        
        # Components
        self.sniffer: Optional[PacketSniffer] = None
        self.flow_manager: Optional[FlowManager] = None
        self.model: Optional[CoreMLModel] = None
        self.alert_bot: Optional[TelegramAlertBot] = None
        
        # State
        self._running = False
        self._start_time = None
        self._stats = {
            'packets_captured': 0,
            'flows_completed': 0,
            'anomalies_detected': 0,
            'alerts_sent': 0,
            'avg_inference_ms': 0.0
        }
        
        # Dashboard process
        self._dashboard_process = None
    
    async def start(self):
        """Start the IDS system"""
        console.print(Panel.fit(
            "[bold blue]🛡️ Real-Time Network IDS[/bold blue]\n"
            "[dim]Powered by KitNET + Core ML[/dim]\n"
            "[dim italic]</> by UV[/dim italic]",
            border_style="blue"
        ))
        
        try:
            await self._initialize_components()
            self._running = True
            self._start_time = datetime.now()
            
            console.print("\n[bold green]✓ System started successfully![/bold green]\n")
            console.print(f"  📡 Interface: [cyan]{self.interface}[/cyan]")
            console.print(f"  🧠 Model: [cyan]KitNET Ensemble[/cyan]")
            console.print(f"  📱 Telegram: [cyan]{'Enabled' if self.enable_telegram else 'Disabled'}[/cyan]")
            console.print(f"  📊 Dashboard: [cyan]{'Enabled' if self.enable_dashboard else 'Disabled'}[/cyan]")
            console.print(f"  ⚡ Threshold: [cyan]{self.threshold}[/cyan]")
            console.print("\n[dim]Press Ctrl+C to stop...[/dim]\n")
            
            # Start main processing loop
            await self._main_loop()
            
        except KeyboardInterrupt:
            console.print("\n[yellow]Received interrupt signal...[/yellow]")
        except Exception as e:
            console.print(f"\n[red]Error: {e}[/red]")
            raise
        finally:
            await self.stop()
    
    async def _initialize_components(self):
        """Initialize all IDS components"""
        console.print("[bold]Initializing components...[/bold]\n")
        
        # 1. Initialize ML Model
        with console.status("[bold blue]Loading ML model..."):
            self.model = CoreMLModel(use_coreml=True)
            console.print("  [green]✓[/green] ML model loaded")
        
        # 2. Initialize Packet Sniffer
        with console.status("[bold blue]Starting packet sniffer..."):
            sniffer_config = SnifferConfig(
                interface=self.interface,
                filter="ip",
                buffer_size=10000
            )
            self.sniffer = PacketSniffer(sniffer_config)
            self.sniffer.start()
            console.print(f"  [green]✓[/green] Packet sniffer started on {self.interface}")
        
        # 3. Initialize Flow Manager
        with console.status("[bold blue]Initializing flow manager..."):
            flow_config = FlowManagerConfig(
                flow_timeout=120.0,
                cleanup_interval=10.0
            )
            self.flow_manager = FlowManager(flow_config)
            self.flow_manager.start_cleanup()
            console.print("  [green]✓[/green] Flow manager initialized")
        
        # 4. Initialize Telegram Bot
        if self.enable_telegram:
            with console.status("[bold blue]Connecting to Telegram..."):
                telegram_config = TelegramConfig.from_env()
                self.alert_bot = TelegramAlertBot(telegram_config)
                
                if self.alert_bot.is_configured:
                    await self.alert_bot.start()
                    console.print("  [green]✓[/green] Telegram bot connected")
                else:
                    console.print("  [yellow]⚠[/yellow] Telegram not configured (set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID)")
        
        # 5. Start Dashboard (in separate process)
        if self.enable_dashboard:
            with console.status("[bold blue]Starting dashboard..."):
                self._start_dashboard()
                console.print("  [green]✓[/green] Dashboard started at http://localhost:8501")
    
    def _start_dashboard(self):
        """Start Streamlit dashboard in background"""
        import subprocess
        dashboard_path = PROJECT_ROOT / "dashboard" / "app.py"
        
        self._dashboard_process = subprocess.Popen(
            ["streamlit", "run", str(dashboard_path), "--server.headless", "true"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
    
    async def _main_loop(self):
        """Main processing loop"""
        last_stats_time = time.time()
        
        with Live(self._create_status_table(), refresh_per_second=2, console=console) as live:
            while self._running:
                # Get packets from queue
                packets = self.sniffer.get_packets(100)
                
                for pkt in packets:
                    self._stats['packets_captured'] += 1
                    
                    # Add to flow manager
                    result = self.flow_manager.add_packet(pkt)
                    
                    if result:
                        flow_key, features = result
                        self._stats['flows_completed'] += 1
                        
                        # Run ML inference
                        await self._process_flow(flow_key, features)
                
                # Update display periodically
                if time.time() - last_stats_time > 0.5:
                    live.update(self._create_status_table())
                    last_stats_time = time.time()
                
                # Small sleep to prevent busy waiting
                await asyncio.sleep(0.01)
    
    async def _process_flow(self, flow_key: FlowKey, features):
        """Process a completed flow through ML model"""
        import numpy as np
        
        # Run inference
        is_anomaly, confidence = self.model.predict(features.reshape(1, -1))
        
        is_anomaly = is_anomaly[0]
        confidence = confidence[0]
        
        # Update inference stats
        stats = self.model.get_inference_stats()
        self._stats['avg_inference_ms'] = stats['avg_ms']
        
        # Check if anomaly detected
        if is_anomaly and confidence > self.threshold:
            self._stats['anomalies_detected'] += 1
            
            # Determine attack type (simplified - in production, use classifier)
            attack_type_id = self._classify_attack(features)
            
            if self.verbose:
                attack_name = ATTACK_LABELS.get(attack_type_id, "Unknown")
                console.print(
                    f"[red]🚨 ALERT:[/red] {attack_name} detected! "
                    f"{flow_key.src_ip}:{flow_key.src_port} → "
                    f"{flow_key.dst_ip}:{flow_key.dst_port} "
                    f"[dim](confidence: {confidence:.1%})[/dim]"
                )
            
            # Send Telegram alert
            if self.alert_bot and self.alert_bot.is_configured:
                alert = create_alert_from_detection(
                    flow_key=flow_key,
                    confidence=float(confidence),
                    attack_type_id=attack_type_id,
                    details={
                        'flow_duration_ms': features[0] / 1000,
                        'packets_fwd': int(features[1]),
                        'packets_bwd': int(features[2])
                    }
                )
                await self.alert_bot.send_alert(alert)
                self._stats['alerts_sent'] += 1
    
    def _classify_attack(self, features) -> int:
        """
        Classify attack type based on features.
        In production, this would use a trained classifier.
        """
        import numpy as np
        
        # Simple heuristic classification based on flow characteristics
        fwd_packets = features[1]
        bwd_packets = features[2]
        syn_flags = features[43]
        flow_duration = features[0]
        
        # Port scan detection (many SYN, few responses, short flows)
        if syn_flags > 5 and bwd_packets < 2 and flow_duration < 1000000:
            return 11  # PortScan
        
        # DDoS detection (high packet rate)
        if fwd_packets + bwd_packets > 100 and flow_duration < 1000000:
            return 3  # DDoS
        
        # Brute force (many flows to same port)
        if fwd_packets > 10 and bwd_packets > 10:
            return 2  # Brute Force
        
        # Default: generic intrusion
        return 10  # Infiltration
    
    def _create_status_table(self) -> Table:
        """Create status display table"""
        table = Table(
            title="📊 IDS Status",
            box=box.ROUNDED,
            border_style="blue"
        )
        
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green", justify="right")
        
        uptime = ""
        if self._start_time:
            delta = datetime.now() - self._start_time
            hours, remainder = divmod(int(delta.total_seconds()), 3600)
            minutes, seconds = divmod(remainder, 60)
            uptime = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
        
        table.add_row("Uptime", uptime or "Starting...")
        table.add_row("Packets Captured", f"{self._stats['packets_captured']:,}")
        table.add_row("Flows Completed", f"{self._stats['flows_completed']:,}")
        table.add_row("Anomalies Detected", f"[red]{self._stats['anomalies_detected']}[/red]" if self._stats['anomalies_detected'] else "0")
        table.add_row("Alerts Sent", f"{self._stats['alerts_sent']}")
        table.add_row("Avg Inference", f"{self._stats['avg_inference_ms']:.2f} ms")
        table.add_row("Active Flows", f"{self.flow_manager.get_active_flow_count() if self.flow_manager else 0}")
        
        return table
    
    async def stop(self):
        """Stop the IDS system gracefully"""
        console.print("\n[bold yellow]Shutting down...[/bold yellow]")
        self._running = False
        
        if self.sniffer:
            self.sniffer.stop()
            console.print("  [green]✓[/green] Packet sniffer stopped")
        
        if self.flow_manager:
            self.flow_manager.stop_cleanup()
            console.print("  [green]✓[/green] Flow manager stopped")
        
        if self.alert_bot:
            await self.alert_bot.stop()
            console.print("  [green]✓[/green] Telegram bot disconnected")
        
        if self._dashboard_process:
            self._dashboard_process.terminate()
            console.print("  [green]✓[/green] Dashboard stopped")
        
        # Print final stats
        console.print("\n[bold]Final Statistics:[/bold]")
        console.print(f"  📦 Packets captured: {self._stats['packets_captured']:,}")
        console.print(f"  🔀 Flows analyzed: {self._stats['flows_completed']:,}")
        console.print(f"  ⚠️  Anomalies detected: {self._stats['anomalies_detected']}")
        console.print(f"  📱 Alerts sent: {self._stats['alerts_sent']}")
        
        console.print("\n[bold green]✓ Shutdown complete[/bold green]")
        console.print("[dim]</> UV[/dim]")


def setup_signal_handlers(ids_instance: NetworkIDS):
    """Setup graceful shutdown handlers"""
    def signal_handler(sig, frame):
        asyncio.create_task(ids_instance.stop())
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)


def check_permissions():
    """Check if running with required permissions"""
    if os.geteuid() != 0:
        console.print(Panel(
            "[bold yellow]⚠️ Elevated Permissions Required[/bold yellow]\n\n"
            "Packet capture requires root/sudo access.\n"
            "Please run with: [bold]sudo python main.py[/bold]",
            border_style="yellow"
        ))
        sys.exit(1)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Real-Time Network Intrusion Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python main.py --interface en0
  sudo python main.py --interface en0 --telegram --dashboard
  sudo python main.py -i en0 -t 0.7 -v
        """
    )
    
    parser.add_argument(
        "-i", "--interface",
        default="en0",
        help="Network interface to monitor (default: en0)"
    )
    
    parser.add_argument(
        "-t", "--threshold",
        type=float,
        default=0.5,
        help="Anomaly detection threshold 0.0-1.0 (default: 0.5)"
    )
    
    parser.add_argument(
        "--telegram",
        action="store_true",
        help="Enable Telegram alerts"
    )
    
    parser.add_argument(
        "--dashboard",
        action="store_true",
        help="Launch Streamlit dashboard"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        default=True,
        help="Verbose output"
    )
    
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Quiet mode (suppress verbose output)"
    )
    
    parser.add_argument(
        "--test-telegram",
        action="store_true",
        help="Send test Telegram alert and exit"
    )
    
    parser.add_argument(
        "--test-capture",
        type=int,
        metavar="SECONDS",
        help="Test packet capture for N seconds and exit"
    )
    
    args = parser.parse_args()
    
    # Handle test modes
    if args.test_telegram:
        from alerts import send_test_alert
        asyncio.run(send_test_alert())
        return
    
    if args.test_capture:
        check_permissions()
        from capture import test_capture
        test_capture(args.interface, args.test_capture)
        return
    
    # Check permissions for normal operation
    check_permissions()
    
    # Create and run IDS
    ids = NetworkIDS(
        interface=args.interface,
        enable_telegram=args.telegram,
        enable_dashboard=args.dashboard,
        threshold=args.threshold,
        verbose=not args.quiet
    )
    
    # Run
    asyncio.run(ids.start())


if __name__ == "__main__":
    main()
