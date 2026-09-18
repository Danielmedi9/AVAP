import json
import re

from utils.logger import log_ok, log_error


def parse_zap(path: str) -> dict:
    counts = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
    alerts = []

    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, dict) or not isinstance(data.get("site"), list):
            raise ValueError("ZAP report must contain a site list")
        sites = data["site"]

        for site in sites:
            site_alerts = site.get("alerts", [])

            for alert in site_alerts:
                risk = _risk_name(alert)

                if risk in counts:
                    counts[risk] += 1
                else:
                    counts["Info"] += 1

                description = _strip_html(alert.get("desc", ""))
                solution    = _strip_html(alert.get("solution", ""))

                alert_entry = {
                    "name":        alert.get("name", "Unknown"),
                    "risk":        risk,
                    "confidence":  _confidence_name(alert.get("confidence", "Unknown")),
                    "description": description[:400],
                    "solution":    solution[:400],
                    "count":       int(alert.get("count", 1)),
                }
                alerts.append(alert_entry)

        risk_order = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}
        alerts.sort(key=lambda a: risk_order.get(a["risk"], 4))

        total = sum(counts.values())
        log_ok("PARSER", f"ZAP: {total} alerts ({counts['High']} high, {counts['Medium']} medium)")

        return {"counts": counts, "alerts": alerts, "total": total}

    except FileNotFoundError:
        log_error("PARSER", f"ZAP file not found: {path}")
        return {"error": "Report missing or invalid", "counts": counts, "alerts": [], "total": 0}

    except json.JSONDecodeError as e:
        log_error("PARSER", f"Error reading ZAP JSON: {e}")
        return {"error": "Report missing or invalid", "counts": counts, "alerts": [], "total": 0}

    except Exception as e:
        log_error("PARSER", f"Unexpected error parsing ZAP: {e}")
        return {"error": "Report missing or invalid", "counts": counts, "alerts": [], "total": 0}


def _strip_html(text: str) -> str:
    if not text:
        return ""
    clean = re.sub(r'<[^>]+>', '', text)
    clean = ' '.join(clean.split())
    return clean.strip()


def _risk_name(alert: dict) -> str:
    codes = {"0": "Info", "1": "Low", "2": "Medium", "3": "High"}
    code = str(alert.get("riskcode", ""))
    if code in codes:
        return codes[code]
    name = str(alert.get("risk") or alert.get("riskdesc") or "Info").split(" (", 1)[0]
    names = {
        "informational": "Info",
        "info": "Info",
        "low": "Low",
        "medium": "Medium",
        "high": "High",
    }
    return names.get(name.lower(), "Info")


def _confidence_name(value) -> str:
    names = {"0": "False Positive", "1": "Low", "2": "Medium", "3": "High", "4": "Confirmed"}
    return names.get(str(value), str(value))
