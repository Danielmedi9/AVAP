from datetime import datetime
from utils.logger import log_ok, log_error


def generate_dashboard(data: dict, output_path: str) -> bool:

    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        scoring = _calculate_scoring(data)
        chart_data = _prepare_chart_data(data)

        nmap_rows  = _build_nmap_rows(data["nmap"])
        trivy_rows = _build_trivy_rows(data["trivy"])
        zap_rows   = _build_zap_rows(data["zap"])

        top_findings_html = _build_top_findings(data["trivy"], data["zap"])

        html = _build_html(
            timestamp=timestamp,
            scoring=scoring,
            data=data,
            chart_data=chart_data,
            nmap_rows=nmap_rows,
            trivy_rows=trivy_rows,
            zap_rows=zap_rows,
            top_findings_html=top_findings_html,
        )

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

        log_ok("DASHBOARD", f"Dashboard profesional generado → {output_path}")
        return True

    except Exception as e:
        log_error("DASHBOARD", f"Error generando dashboard: {e}")
        return False


def _calculate_scoring(data: dict) -> dict:
    trivy = data["trivy"]["counts"]
    zap   = data["zap"]["counts"]
    nmap  = data["nmap"]["count"]

    score_trivy_critical = trivy.get("CRITICAL", 0) * 10
    score_trivy_high     = trivy.get("HIGH", 0) * 4
    score_trivy_medium   = trivy.get("MEDIUM", 0) * 1
    score_zap_high       = zap.get("High", 0) * 8
    score_zap_medium     = zap.get("Medium", 0) * 3
    score_zap_low        = zap.get("Low", 0) * 1
    score_nmap           = nmap * 2

    raw_score = (
        score_trivy_critical + score_trivy_high + score_trivy_medium +
        score_zap_high + score_zap_medium + score_zap_low +
        score_nmap
    )

    total_score = min(raw_score, 100)

    if total_score >= 75:
        level, color, bg_color = "CRITICAL", "#ef4444", "rgba(239,68,68,0.1)"
        description = "Immediate action required. Critical vulnerabilities detected."
    elif total_score >= 50:
        level, color, bg_color = "HIGH", "#f97316", "rgba(249,115,22,0.1)"
        description = "High risk environment. Prioritize remediation of critical findings."
    elif total_score >= 25:
        level, color, bg_color = "MEDIUM", "#eab308", "rgba(234,179,8,0.1)"
        description = "Moderate risk. Address high severity findings promptly."
    else:
        level, color, bg_color = "LOW", "#22c55e", "rgba(34,197,94,0.1)"
        description = "Low risk environment. Continue monitoring."

    return {
        "total":       total_score,
        "level":       level,
        "color":       color,
        "bg_color":    bg_color,
        "description": description,
        "breakdown": {
            "Critical CVEs":  score_trivy_critical,
            "High CVEs":      score_trivy_high,
            "Medium CVEs":    score_trivy_medium,
            "Web High":       score_zap_high,
            "Web Medium":     score_zap_medium,
            "Open Ports":     score_nmap,
        }
    }


def _prepare_chart_data(data: dict) -> dict:
    trivy = data["trivy"]
    zap   = data["zap"]

    trivy_counts = trivy["counts"]
    trivy_donut = {
        "labels": ["Critical", "High", "Medium", "Low"],
        "values": [
            trivy_counts.get("CRITICAL", 0),
            trivy_counts.get("HIGH", 0),
            trivy_counts.get("MEDIUM", 0),
            trivy_counts.get("LOW", 0),
        ],
        "colors": ["#ef4444", "#f97316", "#eab308", "#22c55e"],
    }

    zap_counts = zap["counts"]
    zap_donut = {
        "labels": ["High", "Medium", "Low", "Info"],
        "values": [
            zap_counts.get("High", 0),
            zap_counts.get("Medium", 0),
            zap_counts.get("Low", 0),
            zap_counts.get("Info", 0),
        ],
        "colors": ["#f97316", "#eab308", "#22c55e", "#94a3b8"],
    }

    package_counts = {}
    for vuln in trivy.get("vulnerabilities", []):
        pkg = vuln["package"]
        package_counts[pkg] = package_counts.get(pkg, 0) + 1

    top_packages = sorted(package_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    packages_chart = {
        "labels": [p[0] for p in top_packages],
        "values": [p[1] for p in top_packages],
    }

    return {
        "trivy_donut":    trivy_donut,
        "zap_donut":      zap_donut,
        "packages_chart": packages_chart,
    }


def _build_nmap_rows(nmap_data: dict) -> str:
    if not nmap_data["ports"]:
        return '<tr><td colspan="4" class="empty-row">No open ports found</td></tr>'

    rows = []
    for p in nmap_data["ports"]:
        rows.append(
            f'<tr>'
            f'<td><code class="port-code">{p["port"]}</code></td>'
            f'<td><span class="badge open">OPEN</span></td>'
            f'<td>{p["service"]}</td>'
            f'<td class="version-cell">{p["version"] or "—"}</td>'
            f'</tr>'
        )
    return "\n".join(rows)


def _build_trivy_rows(trivy_data: dict) -> str:
    vulns = trivy_data.get("vulnerabilities", [])

    if not vulns:
        return '<tr><td colspan="7" class="empty-row">No vulnerabilities found</td></tr>'

    rows = []
    for v in vulns[:100]:
        sev_class  = v["severity"].lower()
        cvss_score = v.get("cvss_score")

        if cvss_score is not None:
            if cvss_score >= 9.0:
                cvss_html = f'<span class="cvss-score cvss-critical">{cvss_score}</span>'
            elif cvss_score >= 7.0:
                cvss_html = f'<span class="cvss-score cvss-high">{cvss_score}</span>'
            elif cvss_score >= 4.0:
                cvss_html = f'<span class="cvss-score cvss-medium">{cvss_score}</span>'
            else:
                cvss_html = f'<span class="cvss-score cvss-low">{cvss_score}</span>'
        else:
            cvss_html = '<span class="cvss-score cvss-na">N/A</span>'

        cve_id = v["id"]
        if cve_id.startswith("CVE-"):
            cve_link = f'<a href="https://nvd.nist.gov/vuln/detail/{cve_id}" target="_blank" class="cve-link">{cve_id}</a>'
        else:
            cve_link = f'<code class="cve">{cve_id}</code>'

        rows.append(
            f'<tr>'
            f'<td>{cve_link}</td>'
            f'<td><span class="badge {sev_class}">{v["severity"]}</span></td>'
            f'<td>{cvss_html}</td>'
            f'<td><code class="pkg">{v["package"]}</code></td>'
            f'<td><code class="version-installed">{v["installed_version"]}</code></td>'
            f'<td><code class="version-fixed">{v["fixed_version"]}</code></td>'
            f'<td class="title-cell" title="{v["description"][:200]}">{v["title"][:80]}{"..." if len(v["title"]) > 80 else ""}</td>'
            f'</tr>'
        )

    if len(vulns) > 100:
        rows.append(
            f'<tr><td colspan="7" class="more-row">'
            f'⋯ and {len(vulns) - 100} more vulnerabilities — see trivy.json for complete list'
            f'</td></tr>'
        )

    return "\n".join(rows)


def _build_zap_rows(zap_data: dict) -> str:
    alerts = zap_data.get("alerts", [])

    if not alerts:
        return '<tr><td colspan="5" class="empty-row">No alerts found</td></tr>'

    rows = []
    for a in alerts:
        risk_class = a["risk"].lower()
        rows.append(
            f'<tr>'
            f'<td class="alert-name">{a["name"]}</td>'
            f'<td><span class="badge {risk_class}">{a["risk"].upper()}</span></td>'
            f'<td><span class="confidence-badge">{a["confidence"]}</span></td>'
            f'<td class="count-cell">{a["count"]}</td>'
            f'<td class="desc-cell">{a["description"][:250]}</td>'
            f'</tr>'
        )
    return "\n".join(rows)


def _build_top_findings(trivy_data: dict, zap_data: dict) -> str:
    html_parts = []

    top_vulns = trivy_data.get("top_critical", [])[:3]
    for v in top_vulns:
        sev_class  = v["severity"].lower()
        cvss_score = v.get("cvss_score")
        cvss_str   = f"CVSS {cvss_score}" if cvss_score else v["severity"]
        html_parts.append(f"""
        <div class="finding-item finding-{sev_class}">
            <div class="finding-header">
                <span class="finding-id">{v['id']}</span>
                <span class="badge {sev_class}">{v['severity']}</span>
                <span class="finding-cvss">{cvss_str}</span>
            </div>
            <div class="finding-title">{v['title'][:100]}</div>
            <div class="finding-meta">Package: <code>{v['package']}</code> {v['installed_version']} → fix: <code class="fix">{v['fixed_version']}</code></div>
        </div>""")

    top_alerts = zap_data.get("alerts", [])[:3]
    for a in top_alerts:
        risk_class = a["risk"].lower()
        html_parts.append(f"""
        <div class="finding-item finding-{risk_class}">
            <div class="finding-header">
                <span class="finding-id">ZAP</span>
                <span class="badge {risk_class}">{a['risk'].upper()}</span>
                <span class="finding-cvss">Confidence: {a['confidence']}</span>
            </div>
            <div class="finding-title">{a['name']}</div>
            <div class="finding-meta">{a['description'][:120]}</div>
        </div>""")

    if not html_parts:
        return '<div class="no-findings">✓ No critical findings detected</div>'

    return "\n".join(html_parts)


def _build_html(timestamp, scoring, data, chart_data,
                nmap_rows, trivy_rows, zap_rows, top_findings_html) -> str:

    trivy_counts = data["trivy"]["counts"]
    zap_counts   = data["zap"]["counts"]
    nmap_count   = data["nmap"]["count"]
    risk_color   = scoring["color"]
    risk_score   = scoring["total"]
    risk_level   = scoring["level"]

    import json as _json

    trivy_labels = _json.dumps(chart_data["trivy_donut"]["labels"])
    trivy_values = _json.dumps(chart_data["trivy_donut"]["values"])
    trivy_colors = _json.dumps(chart_data["trivy_donut"]["colors"])

    zap_labels = _json.dumps(chart_data["zap_donut"]["labels"])
    zap_values = _json.dumps(chart_data["zap_donut"]["values"])
    zap_colors = _json.dumps(chart_data["zap_donut"]["colors"])

    pkg_labels = _json.dumps(chart_data["packages_chart"]["labels"])
    pkg_values = _json.dumps(chart_data["packages_chart"]["values"])

    gauge_rotation = int(risk_score * 1.8)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Analysis Report — {timestamp}</title>

    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>

    <style>
        *, *::before, *::after {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        :root {{
            --bg-primary:    #0a0f1e;
            --bg-secondary:  #0f172a;
            --bg-card:       #1e293b;
            --bg-card-hover: #263348;
            --border:        #1e3a5f;
            --border-light:  #334155;
            --text-primary:  #f1f5f9;
            --text-secondary:#94a3b8;
            --text-muted:    #475569;

            --critical: #ef4444;
            --high:     #f97316;
            --medium:   #eab308;
            --low:      #22c55e;
            --info:     #94a3b8;
            --blue:     #3b82f6;
            --purple:   #a855f7;
        }}

        body {{
            background: var(--bg-primary);
            color: var(--text-primary);
            font-family: 'Segoe UI', system-ui, -apple-system, Arial, sans-serif;
            font-size: 14px;
            line-height: 1.6;
            min-height: 100vh;
        }}

        .header {{
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #0f172a 100%);
            border-bottom: 1px solid var(--border);
            padding: 20px 40px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            z-index: 100;
            backdrop-filter: blur(10px);
        }}

        .header-left h1 {{
            font-size: 20px;
            font-weight: 700;
            color: var(--text-primary);
            letter-spacing: 0.5px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}

        .header-left .subtitle {{
            font-size: 12px;
            color: var(--text-muted);
            margin-top: 3px;
            letter-spacing: 0.3px;
        }}

        .header-right {{
            text-align: right;
        }}

        .header-right .timestamp {{
            font-size: 12px;
            color: var(--text-muted);
        }}

        .header-right .tools-badges {{
            display: flex;
            gap: 6px;
            margin-top: 6px;
            justify-content: flex-end;
        }}

        .tool-badge {{
            font-size: 10px;
            padding: 2px 8px;
            border-radius: 4px;
            font-weight: 600;
            letter-spacing: 0.5px;
        }}

        .tool-badge.nmap  {{ background: rgba(59,130,246,0.2);  color: #3b82f6; border: 1px solid rgba(59,130,246,0.4); }}
        .tool-badge.trivy {{ background: rgba(168,85,247,0.2);  color: #a855f7; border: 1px solid rgba(168,85,247,0.4); }}
        .tool-badge.zap   {{ background: rgba(249,115,22,0.2);  color: #f97316; border: 1px solid rgba(249,115,22,0.4); }}

        .main {{
            max-width: 1600px;
            margin: 0 auto;
            padding: 32px 40px;
        }}

        .section {{
            margin-bottom: 40px;
        }}

        .section-title {{
            font-size: 11px;
            font-weight: 700;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 2px;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            gap: 8px;
        }}

        .section-title::before {{
            content: '';
            display: inline-block;
            width: 3px;
            height: 14px;
            background: var(--blue);
            border-radius: 2px;
        }}

        .exec-grid {{
            display: grid;
            grid-template-columns: 280px 1fr 1fr;
            grid-template-rows: auto auto;
            gap: 20px;
            margin-bottom: 20px;
        }}

        .risk-score-card {{
            grid-row: span 2;
            background: var(--bg-card);
            border: 2px solid {risk_color};
            border-radius: 16px;
            padding: 28px 24px;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            text-align: center;
            position: relative;
            overflow: hidden;
        }}

        .risk-score-card::before {{
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0; bottom: 0;
            background: {scoring["bg_color"]};
            pointer-events: none;
        }}

        .risk-label-top {{
            font-size: 10px;
            font-weight: 700;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 2px;
            margin-bottom: 16px;
        }}

        .gauge-container {{
            position: relative;
            width: 180px;
            height: 100px;
            margin: 0 auto 16px;
        }}

        .gauge-bg {{
            width: 180px;
            height: 90px;
            border-radius: 90px 90px 0 0;
            background: conic-gradient(
                from 180deg,
            );
            position: relative;
            overflow: hidden;
        }}

        .gauge-bg::after {{
            content: '';
            position: absolute;
            bottom: 0; left: 20px; right: 20px;
            height: 70px;
            background: var(--bg-card);
            border-radius: 50px 50px 0 0;
        }}

        .gauge-needle {{
            position: absolute;
            bottom: 0;
            left: 50%;
            width: 3px;
            height: 75px;
            background: {risk_color};
            transform-origin: bottom center;
            transform: translateX(-50%) rotate({gauge_rotation - 90}deg);
            border-radius: 3px 3px 0 0;
            box-shadow: 0 0 8px {risk_color};
            transition: transform 1s ease;
        }}

        .gauge-center {{
            position: absolute;
            bottom: -8px;
            left: 50%;
            transform: translateX(-50%);
            width: 16px;
            height: 16px;
            background: {risk_color};
            border-radius: 50%;
            box-shadow: 0 0 12px {risk_color};
        }}

        .risk-score-number {{
            font-size: 56px;
            font-weight: 800;
            color: {risk_color};
            line-height: 1;
            text-shadow: 0 0 20px {risk_color}40;
        }}

        .risk-score-level {{
            font-size: 16px;
            font-weight: 700;
            color: {risk_color};
            letter-spacing: 2px;
            margin-top: 6px;
        }}

        .risk-score-desc {{
            font-size: 11px;
            color: var(--text-muted);
            margin-top: 12px;
            line-height: 1.5;
            max-width: 200px;
        }}

        .metrics-row {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 12px;
        }}

        .metric-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-light);
            border-radius: 12px;
            padding: 16px;
            text-align: center;
            transition: border-color 0.2s, transform 0.2s;
        }}

        .metric-card:hover {{
            border-color: var(--blue);
            transform: translateY(-2px);
        }}

        .metric-card .m-label {{
            font-size: 10px;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 8px;
        }}

        .metric-card .m-value {{
            font-size: 32px;
            font-weight: 800;
            line-height: 1;
        }}

        .metric-card .m-sub {{
            font-size: 10px;
            color: var(--text-muted);
            margin-top: 4px;
        }}

        .findings-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-light);
            border-radius: 12px;
            padding: 20px;
        }}

        .findings-card h3 {{
            font-size: 12px;
            font-weight: 700;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 14px;
        }}

        .finding-item {{
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 10px;
            border-left: 3px solid transparent;
        }}

        .finding-critical {{ background: rgba(239,68,68,0.08);  border-left-color: #ef4444; }}
        .finding-high     {{ background: rgba(249,115,22,0.08); border-left-color: #f97316; }}
        .finding-medium   {{ background: rgba(234,179,8,0.08);  border-left-color: #eab308; }}
        .finding-low      {{ background: rgba(34,197,94,0.08);  border-left-color: #22c55e; }}

        .finding-header {{
            display: flex;
            align-items: center;
            gap: 8px;
            margin-bottom: 4px;
        }}

        .finding-id {{
            font-family: 'Consolas', monospace;
            font-size: 11px;
            color: #c084fc;
        }}

        .finding-cvss {{
            font-size: 10px;
            color: var(--text-muted);
            margin-left: auto;
        }}

        .finding-title {{
            font-size: 12px;
            color: var(--text-primary);
            margin-bottom: 4px;
        }}

        .finding-meta {{
            font-size: 11px;
            color: var(--text-muted);
        }}

        .no-findings {{
            color: var(--low);
            font-size: 13px;
            padding: 12px;
        }}

        .charts-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr 2fr;
            gap: 20px;
        }}

        .chart-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-light);
            border-radius: 12px;
            padding: 20px;
        }}

        .chart-card h3 {{
            font-size: 12px;
            font-weight: 700;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 16px;
        }}

        .chart-container {{
            position: relative;
            height: 200px;
        }}

        .chart-container-bar {{
            position: relative;
            height: 220px;
        }}

        .tabs-container {{
            background: var(--bg-card);
            border: 1px solid var(--border-light);
            border-radius: 12px;
            overflow: hidden;
        }}

        .tabs-header {{
            display: flex;
            border-bottom: 1px solid var(--border-light);
            background: var(--bg-secondary);
        }}

        .tab-btn {{
            padding: 14px 24px;
            font-size: 13px;
            font-weight: 600;
            color: var(--text-muted);
            background: none;
            border: none;
            cursor: pointer;
            border-bottom: 2px solid transparent;
            transition: all 0.2s;
            display: flex;
            align-items: center;
            gap: 8px;
        }}

        .tab-btn:hover {{
            color: var(--text-primary);
            background: rgba(255,255,255,0.03);
        }}

        .tab-btn.active {{
            color: var(--blue);
            border-bottom-color: var(--blue);
            background: rgba(59,130,246,0.05);
        }}

        .tab-count {{
            font-size: 10px;
            padding: 2px 7px;
            border-radius: 10px;
            background: var(--bg-primary);
            color: var(--text-muted);
        }}

        .tab-btn.active .tab-count {{
            background: rgba(59,130,246,0.2);
            color: var(--blue);
        }}

        .tab-panel {{
            display: none;
        }}

        .tab-panel.active {{
            display: block;
        }}

        .table-toolbar {{
            padding: 12px 20px;
            border-bottom: 1px solid var(--border-light);
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 12px;
        }}

        .search-input {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-light);
            border-radius: 6px;
            padding: 6px 12px;
            color: var(--text-primary);
            font-size: 12px;
            width: 220px;
            outline: none;
            transition: border-color 0.2s;
        }}

        .search-input:focus {{
            border-color: var(--blue);
        }}

        .search-input::placeholder {{
            color: var(--text-muted);
        }}

        .filter-btns {{
            display: flex;
            gap: 6px;
        }}

        .filter-btn {{
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
            cursor: pointer;
            border: 1px solid var(--border-light);
            background: none;
            color: var(--text-muted);
            transition: all 0.2s;
        }}

        .filter-btn:hover, .filter-btn.active {{
            background: rgba(59,130,246,0.15);
            border-color: var(--blue);
            color: var(--blue);
        }}

        .filter-btn.f-critical.active {{ background: rgba(239,68,68,0.15);  border-color: var(--critical); color: var(--critical); }}
        .filter-btn.f-high.active     {{ background: rgba(249,115,22,0.15); border-color: var(--high);     color: var(--high); }}
        .filter-btn.f-medium.active   {{ background: rgba(234,179,8,0.15);  border-color: var(--medium);   color: var(--medium); }}
        .filter-btn.f-low.active      {{ background: rgba(34,197,94,0.15);  border-color: var(--low);      color: var(--low); }}

        .table-wrapper {{
            overflow-x: auto;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
        }}

        thead th {{
            background: var(--bg-secondary);
            padding: 10px 16px;
            text-align: left;
            font-size: 10px;
            font-weight: 700;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 1px;
            white-space: nowrap;
            position: sticky;
            top: 0;
        }}

        tbody tr {{
            border-top: 1px solid rgba(30,58,95,0.5);
            transition: background 0.15s;
        }}

        tbody tr:hover {{
            background: var(--bg-card-hover);
        }}

        tbody td {{
            padding: 10px 16px;
            vertical-align: middle;
            color: #cbd5e1;
            font-size: 13px;
        }}

        .title-cell {{
            font-size: 12px;
            color: var(--text-secondary);
            max-width: 280px;
            cursor: help;
        }}

        .desc-cell {{
            font-size: 12px;
            color: var(--text-secondary);
            max-width: 320px;
        }}

        .alert-name {{
            font-weight: 500;
            color: var(--text-primary);
        }}

        .version-cell {{
            font-size: 12px;
            color: var(--text-muted);
        }}

        .count-cell {{
            text-align: center;
            font-weight: 600;
            color: var(--text-secondary);
        }}

        .empty-row, .more-row {{
            text-align: center;
            color: var(--text-muted);
            font-style: italic;
            padding: 20px;
        }}

        .badge {{
            display: inline-block;
            padding: 2px 9px;
            border-radius: 20px;
            font-size: 10px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            white-space: nowrap;
        }}

        .badge.critical {{ background: rgba(239,68,68,0.15);  color: #ef4444; border: 1px solid rgba(239,68,68,0.4); }}
        .badge.high     {{ background: rgba(249,115,22,0.15); color: #f97316; border: 1px solid rgba(249,115,22,0.4); }}
        .badge.medium   {{ background: rgba(234,179,8,0.15);  color: #eab308; border: 1px solid rgba(234,179,8,0.4); }}
        .badge.low      {{ background: rgba(34,197,94,0.15);  color: #22c55e; border: 1px solid rgba(34,197,94,0.4); }}
        .badge.info     {{ background: rgba(148,163,184,0.15);color: #94a3b8; border: 1px solid rgba(148,163,184,0.4); }}
        .badge.open     {{ background: rgba(59,130,246,0.15); color: #3b82f6; border: 1px solid rgba(59,130,246,0.4); }}
        .badge.unknown  {{ background: rgba(100,116,139,0.15);color: #64748b; border: 1px solid rgba(100,116,139,0.4); }}

        .confidence-badge {{
            font-size: 10px;
            color: var(--text-muted);
            background: var(--bg-secondary);
            padding: 2px 8px;
            border-radius: 4px;
        }}

        .cvss-score {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 700;
            font-family: 'Consolas', monospace;
        }}

        .cvss-critical {{ background: rgba(239,68,68,0.2);  color: #ef4444; }}
        .cvss-high     {{ background: rgba(249,115,22,0.2); color: #f97316; }}
        .cvss-medium   {{ background: rgba(234,179,8,0.2);  color: #eab308; }}
        .cvss-low      {{ background: rgba(34,197,94,0.2);  color: #22c55e; }}
        .cvss-na       {{ background: rgba(100,116,139,0.2);color: #64748b; }}

        code {{
            font-family: 'Consolas', 'Courier New', monospace;
            font-size: 12px;
            background: var(--bg-secondary);
            padding: 2px 6px;
            border-radius: 4px;
        }}

        code.cve              {{ color: #c084fc; }}
        code.pkg              {{ color: #7dd3fc; }}
        code.version-installed{{ color: #94a3b8; }}
        code.version-fixed    {{ color: #4ade80; }}
        code.fix              {{ color: #4ade80; }}
        code.port-code        {{ color: #3b82f6; }}

        .cve-link {{
            font-family: 'Consolas', 'Courier New', monospace;
            font-size: 12px;
            color: #c084fc;
            text-decoration: none;
            background: rgba(192,132,252,0.1);
            padding: 2px 6px;
            border-radius: 4px;
            border: 1px solid rgba(192,132,252,0.2);
            transition: all 0.2s;
        }}

        .cve-link:hover {{
            background: rgba(192,132,252,0.2);
            border-color: rgba(192,132,252,0.5);
        }}

        .c-critical {{ color: var(--critical); }}
        .c-high     {{ color: var(--high); }}
        .c-medium   {{ color: var(--medium); }}
        .c-low      {{ color: var(--low); }}
        .c-info     {{ color: var(--info); }}
        .c-blue     {{ color: var(--blue); }}
        .c-purple   {{ color: var(--purple); }}

        .footer {{
            text-align: center;
            padding: 24px 40px;
            color: var(--text-muted);
            font-size: 11px;
            border-top: 1px solid var(--border);
            margin-top: 40px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}

        .footer-links {{
            display: flex;
            gap: 16px;
        }}

        .footer-links a {{
            color: var(--text-muted);
            text-decoration: none;
            font-size: 11px;
            transition: color 0.2s;
        }}

        .footer-links a:hover {{
            color: var(--blue);
        }}

        @media (max-width: 1200px) {{
            .exec-grid    {{ grid-template-columns: 1fr 1fr; }}
            .risk-score-card {{ grid-row: span 1; }}
            .charts-grid  {{ grid-template-columns: 1fr 1fr; }}
        }}

        @media (max-width: 768px) {{
            .main         {{ padding: 16px; }}
            .header       {{ padding: 16px; flex-direction: column; gap: 12px; }}
            .exec-grid    {{ grid-template-columns: 1fr; }}
            .charts-grid  {{ grid-template-columns: 1fr; }}
            .metrics-row  {{ grid-template-columns: repeat(2, 1fr); }}
        }}
    </style>
</head>
<body>

<div class="header">
    <div class="header-left">
        <h1>Vulnerability Analysis Report</h1>
        <div class="subtitle">Automated Security Pipeline · DevSecOps</div>
    </div>
    <div class="header-right">
        <div class="timestamp">Generated: {timestamp}</div>
        <div class="tools-badges">
            <span class="tool-badge nmap">NMAP</span>
            <span class="tool-badge trivy">TRIVY</span>
            <span class="tool-badge zap">OWASP ZAP</span>
        </div>
    </div>
</div>

<div class="main">

    <div class="exec-grid">

        <div class="risk-score-card">
            <div class="risk-label-top">Overall Risk Score</div>

            <div class="gauge-container">
                <div class="gauge-bg"></div>
                <div class="gauge-needle"></div>
                <div class="gauge-center"></div>
            </div>

            <div class="risk-score-number">{risk_score}</div>
            <div class="risk-score-level">{risk_level}</div>
            <div class="risk-score-desc">{scoring["description"]}</div>
        </div>

        <div class="metrics-row">
            <div class="metric-card">
                <div class="m-label">Open Ports</div>
                <div class="m-value c-blue">{nmap_count}</div>
                <div class="m-sub">Attack surface</div>
            </div>
            <div class="metric-card">
                <div class="m-label">Critical CVEs</div>
                <div class="m-value c-critical">{trivy_counts.get('CRITICAL', 0)}</div>
                <div class="m-sub">Immediate action</div>
            </div>
            <div class="metric-card">
                <div class="m-label">High CVEs</div>
                <div class="m-value c-high">{trivy_counts.get('HIGH', 0)}</div>
                <div class="m-sub">High priority</div>
            </div>
            <div class="metric-card">
                <div class="m-label">Packages Affected</div>
                <div class="m-value c-purple">{data["trivy"].get("packages_affected", 0)}</div>
                <div class="m-sub">Unique packages</div>
            </div>
        </div>

        <div class="metrics-row">
            <div class="metric-card">
                <div class="m-label">Total CVEs</div>
                <div class="m-value c-medium">{data["trivy"]["total"]}</div>
                <div class="m-sub">All severities</div>
            </div>
            <div class="metric-card">
                <div class="m-label">Web Alerts High</div>
                <div class="m-value c-high">{zap_counts.get('High', 0)}</div>
                <div class="m-sub">OWASP ZAP</div>
            </div>
            <div class="metric-card">
                <div class="m-label">Web Alerts Med</div>
                <div class="m-value c-medium">{zap_counts.get('Medium', 0)}</div>
                <div class="m-sub">OWASP ZAP</div>
            </div>
            <div class="metric-card">
                <div class="m-label">Total Web Alerts</div>
                <div class="m-value c-info">{data["zap"]["total"]}</div>
                <div class="m-sub">All risk levels</div>
            </div>
        </div>

        <div class="findings-card" style="grid-column: span 2;">
            <h3>Critical Findings</h3>
            {top_findings_html}
        </div>

    </div>
</div>

<div class="section">
    <div class="section-title">Security Metrics — Visualizations</div>

    <div class="charts-grid">

        <div class="chart-card">
            <h3>CVE Distribution (Trivy)</h3>
            <div class="chart-container">
                <canvas id="trivyDonut"></canvas>
            </div>
        </div>

        <div class="chart-card">
            <h3>Web Alerts Distribution (ZAP)</h3>
            <div class="chart-container">
                <canvas id="zapDonut"></canvas>
            </div>
        </div>

        <div class="chart-card">
            <h3>Top Vulnerable Packages</h3>
            <div class="chart-container-bar">
                <canvas id="packagesBar"></canvas>
            </div>
        </div>

    </div>
</div>

<div class="section">
    <div class="section-title">Detailed Findings</div>

    <div class="tabs-container">

        <div class="tabs-header">
            <button class="tab-btn active" onclick="switchTab('nmap', this)">
                Open Ports
                <span class="tab-count">{nmap_count}</span>
            </button>
            <button class="tab-btn" onclick="switchTab('trivy', this)">
                CVE Details
                <span class="tab-count">{data["trivy"]["total"]}</span>
            </button>
            <button class="tab-btn" onclick="switchTab('zap', this)">
                Web Alerts
                <span class="tab-count">{data["zap"]["total"]}</span>
            </button>
        </div>

        <div id="panel-nmap" class="tab-panel active">
            <div class="table-toolbar">
                <input type="text" class="search-input"
                       oninput="filterTable('nmap-table', this.value)">
                <span style="font-size:11px; color:var(--text-muted);">{nmap_count} open ports found</span>
            </div>
            <div class="table-wrapper">
                <table id="nmap-table">
                    <thead>
                        <tr>
                            <th>Port</th>
                            <th>State</th>
                            <th>Service</th>
                            <th>Version / Banner</th>
                        </tr>
                    </thead>
                    <tbody>
                        {nmap_rows}
                    </tbody>
                </table>
            </div>
        </div>

        <div id="panel-trivy" class="tab-panel">
            <div class="table-toolbar">
                <input type="text" class="search-input"
                       oninput="filterTable('trivy-table', this.value)">
                <div class="filter-btns">
                    <button class="filter-btn f-critical" onclick="filterBySeverity('trivy-table', 'CRITICAL', this)">CRITICAL</button>
                    <button class="filter-btn f-high"     onclick="filterBySeverity('trivy-table', 'HIGH', this)">HIGH</button>
                    <button class="filter-btn f-medium"   onclick="filterBySeverity('trivy-table', 'MEDIUM', this)">MEDIUM</button>
                    <button class="filter-btn f-low"      onclick="filterBySeverity('trivy-table', 'LOW', this)">LOW</button>
                </div>
            </div>
            <div class="table-wrapper">
                <table id="trivy-table">
                    <thead>
                        <tr>
                            <th>CVE ID</th>
                            <th>Severity</th>
                            <th>CVSS</th>
                            <th>Package</th>
                            <th>Installed</th>
                            <th>Fixed In</th>
                            <th>Title</th>
                        </tr>
                    </thead>
                    <tbody>
                        {trivy_rows}
                    </tbody>
                </table>
            </div>
        </div>

        <div id="panel-zap" class="tab-panel">
            <div class="table-toolbar">
                <input type="text" class="search-input"
                       oninput="filterTable('zap-table', this.value)">
                <div class="filter-btns">
                    <button class="filter-btn f-high"   onclick="filterBySeverity('zap-table', 'HIGH', this)">HIGH</button>
                    <button class="filter-btn f-medium" onclick="filterBySeverity('zap-table', 'MEDIUM', this)">MEDIUM</button>
                    <button class="filter-btn f-low"    onclick="filterBySeverity('zap-table', 'LOW', this)">LOW</button>
                </div>
            </div>
            <div class="table-wrapper">
                <table id="zap-table">
                    <thead>
                        <tr>
                            <th>Alert Name</th>
                            <th>Risk</th>
                            <th>Confidence</th>
                            <th>Instances</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody>
                        {zap_rows}
                    </tbody>
                </table>
            </div>
        </div>

    </div>
</div>

</div><!-- /main -->

<div class="footer">
    <span>Vulnerability Analysis Pipeline · {timestamp}</span>
    <div class="footer-links">
        <a href="https://nmap.org" target="_blank">Nmap</a>
        <a href="https://trivy.dev" target="_blank">Trivy</a>
        <a href="https://www.zaproxy.org" target="_blank">OWASP ZAP</a>
        <a href="https://owasp.org/www-project-top-ten/" target="_blank">OWASP Top 10</a>
    </div>
</div>

<script>
Chart.defaults.color = '#94a3b8';
Chart.defaults.borderColor = '#1e3a5f';
Chart.defaults.font.family = "'Segoe UI', system-ui, Arial, sans-serif";

const trivyLabels = {trivy_labels};
const trivyValues = {trivy_values};
const trivyColors = {trivy_colors};

const zapLabels = {zap_labels};
const zapValues = {zap_values};
const zapColors = {zap_colors};

const pkgLabels = {pkg_labels};
const pkgValues = {pkg_values};

new Chart(document.getElementById('trivyDonut'), {{
    type: 'doughnut',
    data: {{
        labels: trivyLabels,
        datasets: [{{
            data: trivyValues,
            backgroundColor: trivyColors.map(c => c + '33'),
            borderColor: trivyColors,
            borderWidth: 2,
            hoverBackgroundColor: trivyColors.map(c => c + '66'),
        }}]
    }},
    options: {{
        responsive: true,
        maintainAspectRatio: false,
        cutout: '65%',
        plugins: {{
            legend: {{
                position: 'bottom',
                labels: {{
                    padding: 12,
                    font: {{ size: 11 }},
                    usePointStyle: true,
                    pointStyleWidth: 8,
                }}
            }},
            tooltip: {{
                callbacks: {{
                    // Personalizamos el tooltip para mostrar el porcentaje.
                    label: function(ctx) {{
                        const total = ctx.dataset.data.reduce((a, b) => a + b, 0);
                        const pct = total > 0 ? Math.round(ctx.parsed / total * 100) : 0;
                        return ` ${{ctx.label}}: ${{ctx.parsed}} (${{pct}}%)`;
                    }}
                }}
            }}
        }}
    }}
}});

new Chart(document.getElementById('zapDonut'), {{
    type: 'doughnut',
    data: {{
        labels: zapLabels,
        datasets: [{{
            data: zapValues,
            backgroundColor: zapColors.map(c => c + '33'),
            borderColor: zapColors,
            borderWidth: 2,
            hoverBackgroundColor: zapColors.map(c => c + '66'),
        }}]
    }},
    options: {{
        responsive: true,
        maintainAspectRatio: false,
        cutout: '65%',
        plugins: {{
            legend: {{
                position: 'bottom',
                labels: {{
                    padding: 12,
                    font: {{ size: 11 }},
                    usePointStyle: true,
                    pointStyleWidth: 8,
                }}
            }},
            tooltip: {{
                callbacks: {{
                    label: function(ctx) {{
                        const total = ctx.dataset.data.reduce((a, b) => a + b, 0);
                        const pct = total > 0 ? Math.round(ctx.parsed / total * 100) : 0;
                        return ` ${{ctx.label}}: ${{ctx.parsed}} (${{pct}}%)`;
                    }}
                }}
            }}
        }}
    }}
}});

new Chart(document.getElementById('packagesBar'), {{
    type: 'bar',
    data: {{
        labels: pkgLabels,
        datasets: [{{
            label: 'Vulnerabilities',
            data: pkgValues,
            backgroundColor: pkgValues.map((v, i) => {{
                const ratio = i / Math.max(pkgValues.length - 1, 1);
                return `rgba(239, ${{Math.round(68 + ratio * 47)}}, ${{Math.round(68 - ratio * 46)}}, 0.7)`;
            }}),
            borderColor: '#ef4444',
            borderWidth: 1,
            borderRadius: 4,
        }}]
    }},
    options: {{
        indexAxis: 'y',
        responsive: true,
        maintainAspectRatio: false,
        plugins: {{
            legend: {{ display: false }},
            tooltip: {{
                callbacks: {{
                    label: function(ctx) {{
                        return ` ${{ctx.parsed.x}} vulnerabilities`;
                    }}
                }}
            }}
        }},
        scales: {{
            x: {{
                grid: {{ color: 'rgba(30,58,95,0.5)' }},
                ticks: {{ font: {{ size: 11 }} }},
            }},
            y: {{
                grid: {{ display: false }},
                ticks: {{
                    font: {{ size: 11, family: "'Consolas', monospace" }},
                    color: '#7dd3fc',
                }}
            }}
        }}
    }}
}});

function switchTab(panelName, btn) {{
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));

    document.getElementById('panel-' + panelName).classList.add('active');
    btn.classList.add('active');
}}

function filterTable(tableId, query) {{
    const table = document.getElementById(tableId);
    if (!table) return;

    const rows = table.querySelectorAll('tbody tr');
    const q = query.toLowerCase().trim();

    rows.forEach(row => {{
        const text = row.textContent.toLowerCase();
        row.style.display = (!q || text.includes(q)) ? '' : 'none';
    }});
}}

let activeFilters = {{}};  // Guardamos qué filtros están activos por tabla.

function filterBySeverity(tableId, severity, btn) {{
    const table = document.getElementById(tableId);
    if (!table) return;

    if (activeFilters[tableId] === severity) {{
        activeFilters[tableId] = null;
        btn.classList.remove('active');
    }} else {{
        const panel = table.closest('.tab-panel');
        panel.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        activeFilters[tableId] = severity;
    }}

    const rows = table.querySelectorAll('tbody tr');
    const activeSev = activeFilters[tableId];

    rows.forEach(row => {{
        if (!activeSev) {{
            row.style.display = '';
        }} else {{
            const text = row.textContent.toUpperCase();
            row.style.display = text.includes(activeSev) ? '' : 'none';
        }}
    }});
}}
</script>

</body>
</html>"""
