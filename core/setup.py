import subprocess
import sys


def start_environment() -> None:
    print("[SETUP] Comprobando que Docker está activo...")

    result = subprocess.run(
        ["docker", "info"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    if result.returncode != 0:
        print("[ERROR] Docker no está activo. Arráncalo e inténtalo de nuevo.")
        sys.exit(1)

    print("[SETUP] Docker activo")
    print("[SETUP] Levantando servicios con docker compose...")

    result = subprocess.run(["docker", "compose", "up", "-d"])

    if result.returncode != 0:
        print("[ERROR] Falló 'docker compose up'. Revisa el docker-compose.yml.")
        sys.exit(1)

    print("[SETUP] Servicios levantados")
