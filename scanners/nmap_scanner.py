import os
import subprocess
from urllib.parse import urlparse

from utils.logger import log, log_ok, log_error
from core.config import DOCKER_NETWORK, get_docker_network


def run_nmap(report_dir: str, target: str = "juice-shop") -> bool:
    log("NMAP", f"Starting port scan on '{target}'...")

    network = get_docker_network()

    parsed = urlparse(target) 
    host = parsed.hostname or target

    if host in ("localhost", "127.0.0.1"):
        network = "host"
    log("NMAP", f"Using Docker network: {network}")

    output_path = os.path.join(report_dir, "nmap.txt")

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            result = subprocess.run(
                [
                    "docker", "run", "--rm",
                    "--network", network,
                    "instrumentisto/nmap",
                    "-sV",
                    "-p-",
                    "--open",
                    host,
                ],
                stdout=f,
                stderr=subprocess.STDOUT,
            )

        if result.returncode != 0:
            log_error("NMAP", f"Scan finished with error code {result.returncode}")
            return False

        log_ok("NMAP", f"Scan completed - {output_path}")
        return True

    except FileNotFoundError:
        log_error("NMAP", "Command 'docker' not found")
        return False
    except Exception as e:
        log_error("NMAP", f"Unexpected error: {e}")
        return False
