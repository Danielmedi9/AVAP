import json
import re

from utils.logger import log_ok, log_error


def parse_zap(path: str) -> dict:
    counts = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
    alerts = []

    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)

        sites = data.get("site", [])

        for site in sites:
            site_alerts = site.get("alerts", [])

            for alert in site_alerts:
                risk = alert.get("risk", "Info")

                if risk in counts:
                    counts[risk] += 1
                else:
                    counts["Info"] += 1

                description = _strip_html(alert.get("desc", ""))
                solution    = _strip_html(alert.get("solution", ""))

                alert_entry = {
                    "name":        alert.get("name", "Unknown"),
                    "risk":        risk,
                    "confidence":  alert.get("confidence", "Unknown"),
                    "description": description[:400],
                    "solution":    solution[:400],
                    "count":       int(alert.get("count", 1)),
                }
                alerts.append(alert_entry)

        risk_order = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}
        alerts.sort(key=lambda a: risk_order.get(a["risk"], 4))

        total = sum(counts.values())
        log_ok("PARSER", f"ZAP: {total} alertas ({counts['High']} altas, {counts['Medium']} medias)")

        return {"counts": counts, "alerts": alerts, "total": total}

    except FileNotFoundError:
        log_error("PARSER", f"Archivo ZAP no encontrado: {path}")
        return {"counts": counts, "alerts": [], "total": 0}

    except json.JSONDecodeError as e:
        log_error("PARSER", f"Error al leer JSON de ZAP: {e}")
        return {"counts": counts, "alerts": [], "total": 0}

    except Exception as e:
        log_error("PARSER", f"Error inesperado parseando ZAP: {e}")
        return {"counts": counts, "alerts": [], "total": 0}


def _strip_html(text: str) -> str:
    if not text:
        return ""
    clean = re.sub(r'<[^>]+>', '', text)
    clean = ' '.join(clean.split())
    return clean.strip()
