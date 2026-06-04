import os
import json
import subprocess
import platform

from utils.logger import log, log_ok, log_error, log_warning
from core.config import DOCKER_NETWORK, get_docker_network


def run_zap(report_dir: str, target_url: str = "http://juice-shop:3000") -> bool:
    log("ZAP", f"Iniciando escaneo web en '{target_url}'...")

    network = get_docker_network()
    log("ZAP", f"Usando red Docker: {network}")

    abs_report_dir = os.path.abspath(report_dir)
    docker_path = _normalize_path_for_docker(abs_report_dir)

    log("ZAP", f"Montando volumen: {docker_path}:/zap/wrk")

    try:
        result = subprocess.run(
            [
                "docker", "run", "--rm",
                "--network", network,
                "-v", f"{docker_path}:/zap/wrk",
                "--user", "root",
                "ghcr.io/zaproxy/zaproxy:stable",
                "zap-baseline.py",
                "-t", target_url,
                "-j",
                "-m", "5",
                "-T", "60",
                "-r", "zap.html",
                "-w", "zap.md",
                "-x", "zap.xml",
                "-J", "zap.json",
            ]
        )

        if result.returncode not in (0, 2):
            log_error("ZAP", f"Terminó con código inesperado: {result.returncode}")
            _ensure_zap_json(report_dir)
            return False

        if result.returncode == 2:
            log_warning("ZAP", "Escaneo completado con alertas encontradas (normal)")
        else:
            log_ok("ZAP", "Escaneo completado sin alertas")

        log_ok("ZAP", f"Reportes guardados en {report_dir}/")
        return True

    except FileNotFoundError:
        log_error("ZAP", "No se encontró el comando 'docker'")
        _ensure_zap_json(report_dir)
        return False
    except Exception as e:
        log_error("ZAP", f"Error inesperado: {e}")
        _ensure_zap_json(report_dir)
        return False


def _ensure_zap_json(report_dir: str) -> None:
    zap_json_path = os.path.join(report_dir, "zap.json")
    if not os.path.exists(zap_json_path):
        empty = {"site": []}
        with open(zap_json_path, "w", encoding="utf-8") as f:
            json.dump(empty, f)
        log_warning("ZAP", "zap.json vacío creado (ZAP no completó el escaneo)")


def _normalize_path_for_docker(path: str) -> str:
    if platform.system() == "Windows":
        path = path.replace("\\", "/")
        if len(path) >= 2 and path[1] == ":":
            drive_letter = path[0].lower()
            path = f"/{drive_letter}{path[2:]}"
    return path
