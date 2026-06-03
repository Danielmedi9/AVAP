import subprocess
import json

DOCKER_NETWORK = "vuln-lab_default"
DEFAULT_TARGET_CONTAINER = "juice-shop"
DEFAULT_TARGET_URL = "http://localhost:3000"
DEFAULT_TARGET_IMAGE = "bkimminich/juice-shop"
WAIT_RETRIES = 20
WAIT_INTERVAL = 3
REQUEST_TIMEOUT = 2


def get_docker_network(container_name: str = DEFAULT_TARGET_CONTAINER) -> str:
    try:
        result = subprocess.run(
            ["docker", "inspect", container_name,
             "--format", "{{json .NetworkSettings.Networks}}"],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode != 0 or not result.stdout.strip():
            return DOCKER_NETWORK

        networks = json.loads(result.stdout.strip())

        if not networks:
            return DOCKER_NETWORK

        return list(networks.keys())[0]

    except Exception:
        return DOCKER_NETWORK
