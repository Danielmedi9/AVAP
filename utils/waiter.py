import time
import requests

from core.config import WAIT_RETRIES, WAIT_INTERVAL, REQUEST_TIMEOUT


def wait_for_service(url: str, label: str = "servicio") -> bool:
    print(f"[WAIT] Esperando a que {label} esté disponible en {url}...")

    for attempt in range(1, WAIT_RETRIES + 1):
        try:
            response = requests.get(url, timeout=REQUEST_TIMEOUT)
            if response.status_code == 200:
                print(f"[WAIT] {label} listo ✓")
                return True
        except requests.exceptions.ConnectionError:
            pass
        except requests.exceptions.Timeout:
            pass
        except requests.exceptions.RequestException as e:
            print(f"[WAIT] Error inesperado en intento {attempt}: {e}")

        print(f"[WAIT] Intento {attempt}/{WAIT_RETRIES} — esperando {WAIT_INTERVAL}s...")
        time.sleep(WAIT_INTERVAL)

    print(f"[ERROR] {label} no disponible tras {WAIT_RETRIES} intentos.")
    return False
