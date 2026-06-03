import json

from utils.logger import log_ok, log_error


def parse_trivy(path: str) -> dict:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    vulnerabilities = []

    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)

        results = data.get("Results", [])

        for result in results:
            vulns = result.get("Vulnerabilities") or []

            for vuln in vulns:
                severity = vuln.get("Severity", "UNKNOWN").upper()

                if severity in counts:
                    counts[severity] += 1

                cvss_score, cvss_vector = _extract_cvss(vuln.get("CVSS", {}))
                references = vuln.get("References", [])[:3]

                vuln_entry = {
                    "id":                vuln.get("VulnerabilityID", "N/A"),
                    "package":           vuln.get("PkgName", "N/A"),
                    "severity":          severity,
                    "cvss_score":        cvss_score,
                    "cvss_vector":       cvss_vector,
                    "installed_version": vuln.get("InstalledVersion", "N/A"),
                    "fixed_version":     vuln.get("FixedVersion", "No fix available"),
                    "title":             vuln.get("Title", "No title"),
                    "description":       vuln.get("Description", "")[:400],
                    "references":        references,
                }
                vulnerabilities.append(vuln_entry)

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
        vulnerabilities.sort(
            key=lambda v: (
                severity_order.get(v["severity"], 4),
                -(v["cvss_score"] or 0)
            )
        )

        total = sum(counts.values())
        top_critical = vulnerabilities[:5]
        packages_affected = len(set(v["package"] for v in vulnerabilities))

        log_ok("PARSER", f"Trivy: {total} vulnerabilidades ({counts['CRITICAL']} críticas, {packages_affected} paquetes afectados)")

        return {
            "counts":            counts,
            "vulnerabilities":   vulnerabilities,
            "total":             total,
            "top_critical":      top_critical,
            "packages_affected": packages_affected,
        }

    except FileNotFoundError:
        log_error("PARSER", f"Archivo Trivy no encontrado: {path}")
        return {"counts": counts, "vulnerabilities": [], "total": 0, "top_critical": [], "packages_affected": 0}

    except json.JSONDecodeError as e:
        log_error("PARSER", f"Error al leer JSON de Trivy: {e}")
        return {"counts": counts, "vulnerabilities": [], "total": 0, "top_critical": [], "packages_affected": 0}

    except Exception as e:
        log_error("PARSER", f"Error inesperado parseando Trivy: {e}")
        return {"counts": counts, "vulnerabilities": [], "total": 0, "top_critical": [], "packages_affected": 0}


def _extract_cvss(cvss_dict: dict) -> tuple:
    if not cvss_dict:
        return None, ""

    preferred_sources = ["nvd", "ghsa", "redhat", "oracle", "amazon", "photon"]

    for source in preferred_sources:
        if source in cvss_dict:
            source_data = cvss_dict[source]
            score = source_data.get("V3Score") or source_data.get("V2Score")
            vector = source_data.get("V3Vector") or source_data.get("V2Vector", "")
            if score is not None:
                return round(float(score), 1), vector

    for source_data in cvss_dict.values():
        if isinstance(source_data, dict):
            score = source_data.get("V3Score") or source_data.get("V2Score")
            vector = source_data.get("V3Vector") or source_data.get("V2Vector", "")
            if score is not None:
                return round(float(score), 1), vector

    return None, ""
