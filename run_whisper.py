#!/usr/bin/env python3
"""
WHISPER Launcher
================
Starts all 4 WHISPER processes from one terminal with health checks.

Usage:
    python run_whisper.py

Press Ctrl+C to stop all processes.
"""

import subprocess
import sys
import time
import os
import signal

# Process definitions: (name, script_path)
PROCESSES = [
    ("Metrics Simulator",      "simulator/generate_metrics.py"),
    ("Security Simulator",     "simulator/generate_security_events.py"),
    ("Observability Simulator","simulator/observability_upgrade.py"),
    ("WHISPER Agent",          "agent/whisper_agent.py"),
]

procs = []

def start_all():
    print("=" * 60)
    print("  WHISPER — Predictive Incident Prevention Agent")
    print("  Starting all components...")
    print("=" * 60)

    for name, path in PROCESSES:
        if not os.path.exists(path):
            print(f"  [SKIP] {name} — file not found: {path}")
            continue
        print(f"  [START] {name} ({path})")
        p = subprocess.Popen(
            [sys.executable, path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        procs.append((name, p))
        time.sleep(1.5)  # stagger startup

    print("\n" + "=" * 60)
    print("  All components starting. Waiting 5 seconds for warm-up...")
    print("=" * 60 + "\n")
    time.sleep(5)

    print_status()

def print_status():
    print("\n" + "-" * 60)
    print("  STATUS")
    print("-" * 60)
    for name, p in procs:
        alive = p.poll() is None
        status = "RUNNING" if alive else f"EXITED (code {p.returncode})"
        print(f"  {name:28s} : {status}")
    print("-" * 60)
    print("\n  Dashboard: http://localhost:8001")
    print("  CLI:       python whisper_cli.py status")
    print("  Press Ctrl+C to stop all components\n")

def stream_output():
    """Print output from all processes, prefixed with their name."""
    try:
        while True:
            for name, p in procs:
                if p.poll() is not None:
                    continue
                # Make read non-blocking or just read a line if available.
                # In Windows, we use simple readline (could block if no output, but sleep helps).
                # To prevent blocking, we can use a small delay or check poll.
                line = p.stdout.readline()
                if line:
                    print(f"[{name}] {line.rstrip()}")
            time.sleep(0.1)

            # Check if any critical process died
            agent_proc = next((p for n, p in procs if n == "WHISPER Agent"), None)
            if agent_proc and agent_proc.poll() is not None:
                print("\n  [ERROR] WHISPER Agent has stopped unexpectedly!")
                print(f"  Exit code: {agent_proc.returncode}")
                break
    except KeyboardInterrupt:
        pass

def stop_all():
    print("\n\nStopping all WHISPER components...")
    for name, p in procs:
        if p.poll() is None:
            print(f"  [STOP] {name}")
            p.terminate()
    time.sleep(2)
    for name, p in procs:
        if p.poll() is None:
            p.kill()
    print("All components stopped.")

if __name__ == "__main__":
    try:
        start_all()
        stream_output()
    except KeyboardInterrupt:
        pass
    finally:
        stop_all()
