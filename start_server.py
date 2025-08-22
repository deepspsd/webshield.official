#!/usr/bin/env python3
"""
WebShield Server Startup Script
Automatically starts the FastAPI server with crash recovery
"""

import subprocess
import sys
import time
import signal
import os
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def find_available_port(start_port=8000, max_attempts=100):
    """Find an available port starting from start_port"""
    import socket
    
    for port in range(start_port, start_port + max_attempts):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('127.0.0.1', port))
                return port
        except OSError:
            continue
    raise RuntimeError(f"No available ports found in range {start_port}-{start_port + max_attempts - 1}")

def kill_process_on_port(port):
    """Kill any process using the specified port"""
    try:
        if os.name == 'nt':  # Windows
            # Find process using the port
            result = subprocess.run(['netstat', '-ano'], capture_output=True, text=True, shell=True)
            for line in result.stdout.split('\n'):
                if f':{port}' in line and 'LISTENING' in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        pid = parts[-1]
                        # Kill the process
                        subprocess.run(['taskkill', '/PID', pid, '/F'], 
                                     capture_output=True, check=False, shell=True)
                        return True
        else:
            # For Unix-like systems
            result = subprocess.run(['lsof', '-ti', f':{port}'], 
                                 capture_output=True, text=True)
            if result.stdout.strip():
                pids = result.stdout.strip().split('\n')
                for pid in pids:
                    subprocess.run(['kill', '-9', pid], 
                                 capture_output=True, check=False)
                return True
    except Exception as e:
        logger.warning(f"Could not kill process on port {port}: {e}")
    return False

def start_server_with_monitoring(port, max_restarts=10):
    """Start server with automatic restart on crash"""
    restart_count = 0
    last_restart_time = 0
    
    while restart_count < max_restarts:
        try:
            current_time = time.time()
            
            # Rate limiting for restarts
            if current_time - last_restart_time < 5:  # Wait at least 5 seconds between restarts
                time.sleep(5)
            
            logger.info(f"🚀 Starting WebShield Server (attempt {restart_count + 1}/{max_restarts})...")
            
            # Check if port is available
            try:
                available_port = find_available_port(port)
                if available_port != port:
                    logger.info(f"Port {port} is busy, using port {available_port}")
                    port = available_port
                else:
                    logger.info(f"✅ Using preferred port {port}")
            except RuntimeError as e:
                logger.error(f"Port allocation failed: {e}")
                restart_count += 1
                continue
            
            # Kill any existing process on the port
            if kill_process_on_port(port):
                logger.info(f"Killed existing process on port {port}")
                time.sleep(2)  # Wait for port to be freed
            
            # Start the server
            logger.info(f"🎯 Starting server on port {port}...")
            
            # Set environment variables for the subprocess
            env = os.environ.copy()
            # Add project root, backend, and top-level ml_models to PYTHONPATH
            project_root = str(Path(__file__).parent)
            backend_path = str(Path(__file__).parent / 'backend')
            top_ml_path = str(Path(__file__).parent / 'ml_models')
            env['PYTHONPATH'] = f"{project_root}{os.pathsep}{backend_path}{os.pathsep}{top_ml_path}"
            env['PYTHONUNBUFFERED'] = '1'
            # Default disable MySQL pooling on Windows to avoid C extension issues
            if os.name == 'nt' and 'DB_DISABLE_POOL' not in env:
                env['DB_DISABLE_POOL'] = '1'
            
            # Build the command
            cmd = [
                sys.executable, "-m", "uvicorn", 
                "backend.server:app",
                "--host", "0.0.0.0",
                "--port", str(port),
                "--http", "h11",  # Force pure Python HTTP implementation for Windows stability
                "--log-level", "warning",
                "--no-access-log",
                "--no-use-colors"
            ]
            
            logger.info(f"🔧 Command: {' '.join(cmd)}")
            
            # Start the server process
            process = subprocess.Popen(
                cmd,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Wait a bit for the server to start
            time.sleep(3)
            
            # Check if process is still running
            if process.poll() is None:
                logger.info(f"✅ Server started successfully on http://localhost:{port}")
                logger.info(f"📊 Dashboard available at: http://localhost:{port}/dashboard.html")
                logger.info(f"🔍 Health check: http://localhost:{port}/health")
                logger.info("Press Ctrl+C to stop the server...")
                
                # Monitor the process
                try:
                    # Stream output in real-time
                    while True:
                        output = process.stdout.readline()
                        if output:
                            print(output.strip())
                        
                        error_output = process.stderr.readline()
                        if error_output:
                            print(f"ERROR: {error_output.strip()}")
                        
                        # Check if process is still running
                        if process.poll() is not None:
                            break
                        
                        time.sleep(0.1)
                    
                    # Get the exit code
                    exit_code = process.poll()
                    if exit_code == 0:
                        logger.info("Server stopped normally")
                        break
                    else:
                        logger.warning(f"Server process exited with code {exit_code}")
                        
                except KeyboardInterrupt:
                    logger.info("Received interrupt signal, stopping server...")
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                    break
                    
            else:
                # Process failed to start
                stdout, stderr = process.communicate()
                logger.error(f"❌ Server failed to start: Command {' '.join(cmd)} returned non-zero exit status {process.returncode}")
                if stdout:
                    logger.error(f"STDOUT: {stdout}")
                if stderr:
                    logger.error(f"STDERR: {stderr}")
                
        except Exception as e:
            logger.error(f"❌ Server startup error: {e}")
        
        # Increment restart count and wait before retrying
        restart_count += 1
        last_restart_time = time.time()
        
        if restart_count < max_restarts:
            logger.warning(f"🔄 Restarting server in 5 seconds... (attempt {restart_count + 1}/{max_restarts})")
            time.sleep(5)
        else:
            logger.critical(f"💥 Server crashed {max_restarts} times. Stopping to prevent infinite restarts.")
            break
    
    return False

def main():
    """Main entry point"""
    try:
        # Find available port
        preferred_port = 8000
        try:
            available_port = find_available_port(preferred_port)
            if available_port != preferred_port:
                logger.info(f"Port {preferred_port} is busy, using port {available_port}")
                preferred_port = available_port
            else:
                logger.info(f"Using preferred port {preferred_port}")
        except RuntimeError as e:
            logger.error(f"Port allocation failed: {e}")
            sys.exit(1)
        
        # Start server with monitoring
        success = start_server_with_monitoring(preferred_port)
        
        if not success:
            logger.error("Server failed to start after multiple attempts")
            sys.exit(1)
            
    except KeyboardInterrupt:
        logger.info("Startup interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Critical startup error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 