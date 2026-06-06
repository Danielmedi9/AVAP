import os
import sys
import json
import argparse
import webbrowser
from datetime import datetime

from core.setup   import start_environment
from core.config  import DEFAULT_TARGET_URL, DEFAULT_TARGET_CONTAINER, DEFAULT_TARGET_IMAGE
from utils.waiter import wait_for_service
from utils.logger import log, log_ok, log_error, log_section
from scanners.nmap_scanner  import run_nmap
from scanners.zap_scanner   import run_zap
from scanners.trivy_scanner import run_trivy
from parsers.nmap_parser  import parse_nmap
from parsers.trivy_parser import parse_trivy
from parsers.zap_parser   import parse_zap
from dashboard.generator import generate_dashboard


def main():
    args = parse_arguments()

    if args.juice_shop:
        use_juice_shop = True
        target_url  = DEFAULT_TARGET_URL
        nmap_target = DEFAULT_TARGET_CONTAINER
        zap_target  = "http://juice-shop:3000"
        trivy_image = DEFAULT_TARGET_IMAGE

    elif args.target:
        use_juice_shop = False
        target_url  = args.target
        nmap_target = args.target
        zap_target  = args.target
        trivy_image = None

    else:
        print("\n" + "═" * 56)
        print("     ERROR: You must specify a target to scan")
        print("═" * 56)
        print()
        print("  1) Scan OWASP Juice Shop (test environment):")
        print("     python main.py --juice-shop")
        print()
        print("  2) Scan an external target:")
        print("     python main.py --target http://mi-app.com")
        print()
        print("     python main.py --help")
        print("═" * 56 + "\n")
        sys.exit(1)

    print_banner(args, target_url, use_juice_shop)

    if use_juice_shop:
        log_section("SETUP — Starting OWASP Juice Shop")
        start_environment()
    else:
        log("MAIN", "External target mode — no Docker Compose")

    log_section("Checking availability of the target")

    if not wait_for_service(target_url, label="Target"):
        log_error("MAIN", f"El objetivo '{target_url}' no está disponible. Abortando.")
        sys.exit(1)

    report_dir = create_report_dir()
    log("MAIN", f"Guardando reportes en: {report_dir}")

    log_section("Ejecutando escáneres de seguridad")

    run_nmap(report_dir, target=nmap_target)
    run_zap(report_dir, target_url=zap_target)

    if trivy_image:
        run_trivy(report_dir, image=trivy_image)
    else:
        log("MAIN", "Trivy omitido — modo target externo")
        _create_empty_trivy_report(report_dir)

    log_section("Procesando resultados")

    data = {
        "nmap":  parse_nmap(os.path.join(report_dir, "nmap.txt")),
        "trivy": parse_trivy(os.path.join(report_dir, "trivy.json")),
        "zap":   parse_zap(os.path.join(report_dir, "zap.json")),
    }

    log_section("Generando reporte")

    dashboard_path = os.path.join(report_dir, "dashboard.html")
    success = generate_dashboard(data, dashboard_path)

    if not success:
        log_error("MAIN", "No se pudo generar el dashboard.")
        sys.exit(1)

    print_summary(data, report_dir)

    if not args.no_browser:
        abs_path = os.path.abspath(dashboard_path)
        webbrowser.open(f"file://{abs_path}")
        log_ok("MAIN", "Dashboard abierto en el navegador")

    log_section("PIPELINE COMPLETADO")


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Automated Vulnerability Analysis Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python main.py --juice-shop
  python main.py --juice-shop --no-browser
  python main.py --target http://localhost:8080
  python main.py --target http://mi-app.com --no-browser
        """
    )

    group = parser.add_mutually_exclusive_group()

    group.add_argument(
        "--juice-shop",
        action="store_true",
        help="Levantar OWASP Juice Shop con Docker y usarlo como objetivo"
    )

    group.add_argument(
        "--target",
        default=None,
        metavar="URL",
        help="URL del objetivo externo a escanear (ej: http://localhost:8080)"
    )

    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="No abrir el dashboard en el navegador al finalizar"
    )

    return parser.parse_args()


def create_report_dir() -> str:
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    path = os.path.join("reports", timestamp)
    os.makedirs(path, exist_ok=True)
    return path


def _create_empty_trivy_report(report_dir: str):
    empty = {"Results": []}
    path = os.path.join(report_dir, "trivy.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(empty, f)
    log("MAIN", "trivy.json vacío creado")


def print_banner(args, target_url: str, use_juice_shop: bool):
    mode = "Juice Shop (Docker)" if use_juice_shop else "External target"
    print("\n" + "═" * 56)
    print("      AVAP - VULNERABILITY ANALYSIS")
    print("═" * 56)
    print(f"  Mode   : {mode}")
    print(f"  Target : {target_url}")
    print(f"  Trivy  : {'Docker image' if use_juice_shop else 'skipped (not applicable)'}")
    print(f"  Browser: {'disabled' if args.no_browser else 'enabled'}")
    print("═" * 56 + "\n")


def print_summary(data: dict, report_dir: str):
    trivy = data["trivy"]["counts"]
    zap   = data["zap"]["counts"]
    nmap  = data["nmap"]["count"]

    print("\n" + "═" * 56)
    print("      SUMMARY OF FINDINGS")
    print("═" * 56)
    print(f"  Open ports        : {nmap}")
    print(f"  CVEs Critical     : {trivy.get('CRITICAL', 0)}")
    print(f"  CVEs High         : {trivy.get('HIGH', 0)}")
    print(f"  CVEs Medium       : {trivy.get('MEDIUM', 0)}")
    print(f"  CVEs Low          : {trivy.get('LOW', 0)}")
    print(f"  Web Alerts High   : {zap.get('High', 0)}")
    print(f"  Web Alerts Medium : {zap.get('Medium', 0)}")
    print(f"  Reports in        : {report_dir}/")
    print("═" * 56 + "\n")


if __name__ == "__main__":
    main()
