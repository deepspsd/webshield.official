#!/usr/bin/env python3
"""
WebShield Performance Monitor & Auto-Restart Script
Monitors server performance and automatically restarts if needed
"""

import logging
import os
import subprocess
import sys
import time
from pathlib import Path

import psutil
import requests

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("watchdog.log", mode="a", encoding="utf-8"), logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


class WebShieldMonitor:
    def __init__(self):
        self.server_process = None
        self.server_port = 8000
        self.max_memory_mb = 1024  # Increased to 1GB to prevent false positives
        self.max_cpu_percent = 90  # Increased to 90% to prevent unnecessary restarts
        self.check_interval = 60  # Check every 60 seconds (reduced frequency)
        self.restart_count = 0
        self.max_restarts = 3  # Reduced to prevent infinite restart loops
        self.last_restart_time = 0

    def check_system_resources(self):
        """Check system resource usage"""
        try:
            # Get CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)

            # Get memory usage
            memory = psutil.virtual_memory()
            memory_mb = memory.used / (1024 * 1024)

            # Get disk usage
            disk = psutil.disk_usage("/")
            disk_percent = disk.percent

            logger.info(
                f"System Status - CPU: {cpu_percent:.1f}%, Memory: {memory_mb:.1f}MB, Disk: {disk_percent:.1f}%"
            )

            # Check if resources are over limits
            if cpu_percent > self.max_cpu_percent:
                logger.warning(f"High CPU usage: {cpu_percent:.1f}%")
                return False

            if memory_mb > self.max_memory_mb:
                logger.warning(f"High memory usage: {memory_mb:.1f}MB")
                return False

            if disk_percent > 90:
                logger.warning(f"High disk usage: {disk_percent:.1f}%")
                return False

            return True

        except Exception as e:
            logger.error(f"Error checking system resources: {e}")
            return False

    def check_server_health(self):
        """Check if the server is responding"""
        try:
            response = requests.get(f"http://localhost:{self.server_port}/health", timeout=5)
            if response.status_code == 200:
                logger.info("Server health check passed")
                return True
            else:
                logger.warning(f"Server health check failed with status: {response.status_code}")
                return False
        except requests.exceptions.RequestException as e:
            logger.warning(f"Server health check failed: {e}")
            return False

    def find_server_process(self):
        """Find the WebShield server process"""
        try:
            for proc in psutil.process_iter(["pid", "name", "cmdline"]):
                try:
                    cmdline = " ".join(proc.info["cmdline"])
                    if "webshield" in cmdline.lower() or "server.py" in cmdline:
                        return proc
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            return None
        except Exception as e:
            logger.error(f"Error finding server process: {e}")
            return None

    def restart_server(self):
        """Restart the WebShield server"""
        current_time = time.time()

        # Rate limiting for restarts
        if current_time - self.last_restart_time < 60:  # Wait at least 1 minute between restarts
            logger.warning("Restart rate limited, waiting...")
            return False

        if self.restart_count >= self.max_restarts:
            logger.error(f"Maximum restart attempts ({self.max_restarts}) reached")
            return False

        try:
            logger.info(f"Restarting server (attempt {self.restart_count + 1}/{self.max_restarts})")

            # Kill existing server process
            server_proc = self.find_server_process()
            if server_proc:
                logger.info(f"Terminating existing server process (PID: {server_proc.pid})")
                server_proc.terminate()
                server_proc.wait(timeout=10)

            # Start new server
            logger.info("Starting new server process...")
            subprocess.Popen([sys.executable, "start_server.py"], cwd=os.getcwd())

            self.restart_count += 1
            self.last_restart_time = current_time

            # Wait for server to start
            time.sleep(10)

            # Check if server started successfully
            if self.check_server_health():
                logger.info("Server restarted successfully")
                return True
            else:
                logger.error("Server restart failed")
                return False

        except Exception as e:
            logger.error(f"Error restarting server: {e}")
            return False

    def cleanup_old_logs(self):
        """Clean up old log files to prevent disk space issues"""
        try:
            log_dir = Path(".")
            current_time = time.time()
            max_age = 7 * 24 * 3600  # 7 days

            for log_file in log_dir.glob("*.log"):
                if log_file.stat().st_mtime < current_time - max_age:
                    log_file.unlink()
                    logger.info(f"Deleted old log file: {log_file}")

        except Exception as e:
            logger.error(f"Error cleaning up logs: {e}")

    def run(self):
        """Main monitoring loop"""
        logger.info("Starting WebShield Performance Monitor...")

        while True:
            try:
                # Clean up old logs periodically
                if int(time.time()) % 3600 == 0:  # Every hour
                    self.cleanup_old_logs()

                # Check system resources
                if not self.check_system_resources():
                    logger.warning("System resources are over limits")
                    if not self.restart_server():
                        logger.error("Failed to restart server, waiting...")
                        time.sleep(60)
                        continue

                # Check server health
                if not self.check_server_health():
                    logger.warning("Server health check failed")
                    if not self.restart_server():
                        logger.error("Failed to restart server, waiting...")
                        time.sleep(60)
                        continue

                # Reset restart count if server is healthy
                if self.restart_count > 0:
                    logger.info("Server is healthy, resetting restart count")
                    self.restart_count = 0

                # Wait before next check
                time.sleep(self.check_interval)

            except KeyboardInterrupt:
                logger.info("Monitor stopped by user")
                break
            except Exception as e:
                logger.error(f"Monitor error: {e}")
                time.sleep(10)


if __name__ == "__main__":
    monitor = WebShieldMonitor()
    monitor.run()
