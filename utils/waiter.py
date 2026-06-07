import time
import requests

from core.config import WAIT_RETRIES, WAIT_INTERVAL, REQUEST_TIMEOUT


def wait_for_service(url: str, label: str = "service") -> bool:
    print(f"[WAIT] Waiting for {label} to become available at {url}...")

    for attempt in range(1, WAIT_RETRIES + 1):
        try:
            response = requests.get(url, timeout=REQUEST_TIMEOUT)
            if response.status_code == 200:
                print(f"[WAIT] {label} ready ✓")
                return True
        except requests.exceptions.ConnectionError:
            pass
        except requests.exceptions.Timeout:
            pass
        except requests.exceptions.RequestException as e:
            print(f"[WAIT] Unexpected error on attempt {attempt}: {e}")

        print(f"[WAIT] Attempt {attempt}/{WAIT_RETRIES} — waiting {WAIT_INTERVAL}s...")
        time.sleep(WAIT_INTERVAL)

    print(f"[ERROR] {label} is not available after {WAIT_RETRIES} attempts.")
    return False
