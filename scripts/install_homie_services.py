"""scripts/install_homie_services.py - Windows Service and Background Task Installer for Homie.

Installs Homie runtime components under a standard-user posture:
- Supervisor & Complete Mediation Actuator
- Hardware Watchdog
- Phone & Remote Gateway
Uses Windows Task Scheduler (schtasks) with /RL LIMITED (non-elevated standard user).
Zero UAC prompts required. Runs automatically on user logon.
"""

import os
import sys
import subprocess
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PYTHON_EXE = sys.executable

SERVICES = [
    {
        "name": "Homie_Supervisor",
        "script": "homie_supervisor.py",
        "description": "Homie Out-of-Process Policy Supervisor and Actuator"
    },
    {
        "name": "Homie_Watchdog",
        "script": "homie_watchdog.py",
        "description": "Homie Low-Integrity Watchdog and Synthetic Keystroke Filter"
    },
    {
        "name": "Homie_PhoneGateway",
        "script": "phone_gateway.py",
        "description": "Homie Phone and Duplex Voice Gateway"
    }
]


def install_scheduled_tasks():
    logging.info("Installing Homie background services as non-elevated user tasks...")

    for svc in SERVICES:
        task_name = svc["name"]
        script_path = os.path.join(BASE_DIR, svc["script"])
        cmd = f'"{PYTHON_EXE}" "{script_path}"'

        # Create scheduled task running on user logon with LIMITED rights (standard user)
        create_args = [
            "schtasks", "/Create",
            "/TN", task_name,
            "/TR", cmd,
            "/SC", "ONLOGON",
            "/RL", "LIMITED",
            "/F"  # Force overwrite if exists
        ]

        logging.info("Registering task: %s -> %s", task_name, svc["description"])
        try:
            res = subprocess.run(create_args, capture_output=True, text=True, check=True)
            logging.info("Task '%s' successfully registered: %s", task_name, res.stdout.strip())
        except subprocess.CalledProcessError as e:
            logging.error("Failed to register task '%s': %s (Error: %s)", task_name, e.stderr.strip(), e)


def uninstall_scheduled_tasks():
    logging.info("Uninstalling Homie background user tasks...")
    for svc in SERVICES:
        task_name = svc["name"]
        delete_args = ["schtasks", "/Delete", "/TN", task_name, "/F"]
        try:
            res = subprocess.run(delete_args, capture_output=True, text=True)
            logging.info("Task '%s' removed: %s", task_name, res.stdout.strip())
        except Exception as e:
            logging.warning("Error deleting task '%s': %s", task_name, e)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--uninstall":
        uninstall_scheduled_tasks()
    else:
        install_scheduled_tasks()
