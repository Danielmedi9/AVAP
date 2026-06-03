import os
import subprocess

from utils.logger import log, log_ok, log_error
from core.config import DOCKER_NETWORK, get_docker_network


def run_nmap(report_dir: str, target: str = "juice-shop") -> bool:
    log("NMAP", f"Iniciando escaneo de puertos en '{target}'...")

    network = get_docker_network()
    log("NMAP", f"Usando red Docker: {network}")

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
                    target,
                ],
                stdout=f,
                stderr=subprocess.STDOUT,
            )

        if result.returncode != 0:
            log_error("NMAP", f"El escaneo terminó con código de error {result.returncode}")
            return False

        log_ok("NMAP", f"Escaneo completado → {output_path}")
        return True

    except FileNotFoundError:
        log_error("NMAP", "No se encontró el comando 'docker'. ¿Está instalado?")
        return False
    except Exception as e:
        log_error("NMAP", f"Error inesperado: {e}")
        return False
