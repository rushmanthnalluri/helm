"""helm_supervisor_daemon.py - Out-of-Process Policy Supervisor Daemon for Helm.

Runs as a dedicated, isolated process owning:
- Cryptographic INTENT V2 HMAC signing keys (never exposed to UI or worker address space)
- Privileged SupervisorActuator & complete mediation gates
- HMAC-SHA256 audit ledger custody
- Taint tracking state & out-of-band step-up verification
- Windows Named Pipe Server (\\\\.\\pipe\\helm_supervisor) with kernel-attested client validation
"""

import os
import sys
import time
import signal
import argparse
import logging

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import helm_supervisor

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [SupervisorDaemon] %(message)s"
)
logger = logging.getLogger("helm.supervisor_daemon")


class SupervisorDaemon:
    def __init__(self, pipe_name: str = r"\\.\pipe\helm_supervisor"):
        self.pipe_name = pipe_name
        self.supervisor = helm_supervisor.PolicySupervisor()
        if self.supervisor.state != helm_supervisor.STATE_LOCKED:
            self.supervisor.state = helm_supervisor.STATE_ARMED
        self.server = helm_supervisor.NamedPipeSupervisorServer(
            self.supervisor, pipe_name=self.pipe_name
        )
        self._running = False

    def start(self):
        logger.info("Starting out-of-process PolicySupervisor daemon on pipe %s (PID: %d)", self.pipe_name, os.getpid())
        self.server.start()
        self._running = True

    def stop(self):
        logger.info("Stopping PolicySupervisor daemon...")
        self._running = False
        self.server.stop()
        self.supervisor.clean_shutdown()
        logger.info("PolicySupervisor daemon stopped cleanly.")

    def run_forever(self):
        self.start()
        try:
            while self._running:
                time.sleep(0.5)
        except KeyboardInterrupt:
            self.stop()


def main():
    parser = argparse.ArgumentParser(description="Helm Policy Supervisor Daemon")
    parser.add_argument("--pipe", default=r"\\.\pipe\helm_supervisor", help="Named pipe name")
    parsed = parser.parse_args()

    daemon = SupervisorDaemon(pipe_name=parsed.pipe)

    def _sig_handler(sig, frame):
        logger.info("Signal %s received; shutting down.", sig)
        daemon.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, _sig_handler)
    signal.signal(signal.SIGTERM, _sig_handler)

    daemon.run_forever()


if __name__ == "__main__":
    main()
