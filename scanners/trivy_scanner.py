import os
import subprocess

from utils.logger import log, log_ok, log_error
from core.config import DEFAULT_TARGET_IMAGE


def run_trivy(report_dir: str, image: str = DEFAULT_TARGET_IMAGE) -> bool:
    log("TRIVY", f"Analizando imagen Docker: '{image}'...")

    json_output = os.path.join(report_dir, "trivy.json")
    txt_output  = os.path.join(report_dir, "trivy.txt")

    success_json = _run_trivy_scan(image, json_output, output_format="json")
    _run_trivy_scan(image, txt_output, output_format="table")

    if success_json:
        log_ok("TRIVY", f"Resultados guardados en {report_dir}/trivy.json")

    return success_json


def _run_trivy_scan(image: str, output_path: str, output_format: str) -> bool:
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            result = subprocess.run(
                [
                    "docker", "run", "--rm",
                    "-v", "/var/run/docker.sock:/var/run/docker.sock",
                    "ghcr.io/aquasecurity/trivy:latest",
                    "image",
                    "--format", output_format,
                    "--no-progress",
                    image,
                ],
                stdout=f,
                stderr=subprocess.PIPE,
            )

        return result.returncode == 0

    except FileNotFoundError:
        log_error("TRIVY", "No se encontró el comando 'docker'. ¿Está instalado?")
        return False
    except Exception as e:
        log_error("TRIVY", f"Error inesperado: {e}")
        return False
