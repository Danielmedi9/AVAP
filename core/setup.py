import subprocess
import sys


def start_environment() -> None:
    print("[SETUP] Checking that Docker is running...")

    result = subprocess.run(
        ["docker", "info"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    if result.returncode != 0:
        print("[ERROR] Docker is not running. Start Docker and try again.")
        sys.exit(1)

    print("[SETUP] Docker is running")
    print("[SETUP] Starting services with docker compose...")

    result = subprocess.run(["docker", "compose", "up", "-d"])

    if result.returncode != 0:
        print("[ERROR] Failed to start services with 'docker compose up'. Check docker-compose.yml.")
        sys.exit(1)

    print("[SETUP] Services started")
