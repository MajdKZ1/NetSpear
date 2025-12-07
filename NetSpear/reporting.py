import html
import json
import re
import base64
from datetime import datetime
from pathlib import Path
import logging
from typing import Any, Dict, List, Optional

from config import REPORTS_DIR, ARCHIVE_DIR, ARCHIVE_GRACE_SECONDS
from utils import WHITE, RESET

class ReportGenerator:
    def __init__(self, base_dir: Optional[Path] = None):
        base_reports = (base_dir or REPORTS_DIR).resolve()
        self.report_dir = base_reports
        self.archive_dir = (base_reports / "Archive") if base_dir else ARCHIVE_DIR.resolve()
        self.report_data: Dict[str, Any] = {"scans": [], "payloads": [], "operations": [], "brute": [], "exploits": [], "recon": []}

    def _severity_from_text(self, text: str) -> str:
        t = (text or "").lower()
        if not t:
            return "unknown"
        if "critical" in t:
            return "critical"
        if "self-signed" in t or "expired" in t or "outdated" in t or "deprecated" in t or "no security headers" in t:
            return "high"
        if "tls" in t or "certificate" in t or "mismatch" in t:
            return "medium"
        if "open directory" in t or "directory listing" in t:
            return "medium"
        if "login" in t or "admin" in t:
            return "info"
        if "interesting" in t:
            return "info"
        return "unknown"

    def _risk_score_for_severity(self, severity: str) -> str:
        sev = severity.lower()
        if sev in {"critical", "high"}:
            return "8-10"
        if sev == "medium":
            return "4-6"
        if sev == "low":
            return "1-3"
        if sev == "info":
            return "1"
        return "-"

    def _extract_technologies(self, web_enum: Dict[str, Any]) -> List[str]:
        techs: set[str] = set()
        for entry in web_enum.get("fingerprint", []) or []:
            stdout = (entry.get("stdout") or "").strip()
            if not stdout:
                continue
            for raw_line in stdout.splitlines():
                line = raw_line.strip()
                if not line:
                    continue
                parts = [p.strip() for p in re.split(r"[,;]", line) if p.strip()]
                for part in parts:
                    if len(part) < 3:
                        continue
                    techs.add(part)
        return sorted(techs)

    def _extract_web_main_findings(self, web_enum: Dict[str, Any]) -> Dict[str, str]:
        findings: Dict[str, str] = {}
        fp = (web_enum or {}).get("fingerprint") or []
        if fp:
            stdout = (fp[0].get("stdout") or "").strip()
            if stdout:
                findings["whatweb"] = stdout.splitlines()[0].strip()
        waf = (web_enum or {}).get("waf") or []
        if waf:
            stdout = (waf[0].get("stdout") or "").strip()
            if stdout:
                findings["waf"] = stdout.splitlines()[0].strip()
        nuclei = (web_enum or {}).get("nuclei") or []
        if nuclei:
            stdout = (nuclei[0].get("stdout") or "").strip()
            if stdout:
                findings["nuclei"] = stdout.splitlines()[0].strip()
        return findings

    def _extract_tls_details(self, web_enum: Dict[str, Any]) -> List[Dict[str, str]]:
        details: List[Dict[str, str]] = []
        base_url = web_enum.get("base_url")
        for entry in web_enum.get("fingerprint", []) or []:
            stdout = (entry.get("stdout") or "").strip()
            if not stdout:
                continue
            tls_version = None
            cipher = None
            expiry = None
            san = None
            for line in stdout.splitlines():
                l = line.lower()
                if not tls_version and ("tls" in l or "ssl" in l):
                    tls_version = line.strip()
                if not cipher and "cipher" in l:
                    cipher = line.strip()
                if not expiry and ("expiry" in l or "expires" in l or "not after" in l):
                    expiry = line.strip()
                if not san and ("san" in l or "subject alt" in l):
                    san = line.strip()
            if tls_version or cipher or expiry or san:
                details.append({
                    "base_url": base_url or "-",
                    "tls": tls_version or "n/a",
                    "cipher": cipher or "n/a",
                    "expiry": expiry or "n/a",
                    "san": san or "n/a",
                })
        return details

    def _severity_badge(self, severity: str) -> str:
        sev = (severity or "unknown").lower()
        label = "Unknown" if sev == "unknown" else sev.title()
        return f"<span class='sev sev-{sev}'>{html.escape(label)}</span>"

    def _categorize_web_errors(self, errors: List[str]) -> Dict[str, List[str]]:
        categories: Dict[str, List[str]] = {"TLS Issues": [], "Directory Probing": [], "Login Probe": [], "Other": []}
        for err in errors:
            lower = err.lower()
            if any(k in lower for k in ["tls", "certificate", "ssl", "verify"]):
                categories["TLS Issues"].append(err)
            elif any(k in lower for k in ["gobuster", "feroxbuster", "directory"]):
                categories["Directory Probing"].append(err)
            elif any(k in lower for k in ["login", "auth", "admin", "panel"]):
                categories["Login Probe"].append(err)
            else:
                categories["Other"].append(err)
        return {k: v for k, v in categories.items() if v}

    def _web_enum_anomaly_count(self, web_enum: Dict[str, Any]) -> int:
        errors = len(web_enum.get("errors") or [])
        admin_hits = len(web_enum.get("admin_hits") or [])
        return errors + admin_hits

    def add_scan(
        self,
        target_ip: str,
        scan_label: str,
        scan_data: Dict[str, str],
        vulnerabilities: List[Dict[str, str]],
        suggestions: Optional[List[str]] = None,
        web_enum: Optional[Dict[str, any]] = None,
    ) -> None:
        if not scan_data:
            return
        ports = scan_data.get("ports", []) or []
        open_ports = [p for p in ports if p.get("state") == "open"]
        closed_ports = [p for p in ports if p.get("state") == "closed"]
        filtered_ports = [p for p in ports if p.get("state") == "filtered"]
        scan_entry = {
            "target": target_ip,
            "scan_type": scan_data.get("scan_type", scan_label),
            "label": scan_label,
            "host_state": scan_data.get("host_state", "unknown"),
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "ports": ports,
            "open_port_count": len(open_ports),
            "closed_port_count": len(closed_ports),
            "filtered_port_count": len(filtered_ports),
            "vulnerabilities": vulnerabilities or [],
            "suggestions": suggestions or [],
            "web_enum": web_enum or {},
            "notes": {k: v for k, v in scan_data.items() if k not in {"ports", "host_state", "scan_type"}}
        }
        self.report_data["scans"].append(scan_entry)

    def add_recon(self, recon_entry: Dict[str, Any]) -> None:
        recon_entry["timestamp"] = datetime.utcnow().isoformat() + "Z"
        self.report_data["recon"].append(recon_entry)

    def _build_summary(self) -> Dict[str, int]:
        total_scans = len(self.report_data["scans"])
        recon_entries = self.report_data.get("recon", [])
        unique_targets = len({scan["target"] for scan in self.report_data["scans"]})
        recon_targets = len({entry.get("resolved_ip") or entry.get("target") for entry in recon_entries if entry.get("resolved_ip") or entry.get("target")})
        total_vulns = sum(len(scan["vulnerabilities"]) for scan in self.report_data["scans"])
        total_vulns += sum(len(entry.get("vulnerabilities", [])) for entry in recon_entries)
        total_open_ports = sum(scan["open_port_count"] for scan in self.report_data["scans"])
        total_open_ports += sum(
            len([p for p in entry.get("scan", {}).get("ports", []) if p.get("state") == "open"])
            for entry in recon_entries
        )
        web_enum_anomalies = 0
        critical_findings = 0
        technologies: set[str] = set()
        main_findings: Dict[str, str] = {}
        for scan in self.report_data["scans"]:
            web_enum_anomalies += self._web_enum_anomaly_count(scan.get("web_enum") or {})
            technologies.update(self._extract_technologies(scan.get("web_enum") or {}))
            main_findings.update(self._extract_web_main_findings(scan.get("web_enum") or {}))
            for vuln in scan.get("vulnerabilities", []):
                if self._severity_from_text(vuln.get("description")) in {"high", "critical"}:
                    critical_findings += 1
            for err in (scan.get("web_enum") or {}).get("errors", []) or []:
                if self._severity_from_text(err) in {"high", "critical"}:
                    critical_findings += 1
        for recon in recon_entries:
            web_enum_anomalies += self._web_enum_anomaly_count(recon.get("web_enum") or {})
            technologies.update(self._extract_technologies(recon.get("web_enum") or {}))
            main_findings.update(self._extract_web_main_findings(recon.get("web_enum") or {}))
            for vuln in recon.get("vulnerabilities", []) or []:
                if self._severity_from_text(vuln.get("description")) in {"high", "critical"}:
                    critical_findings += 1
            for err in (recon.get("web_enum") or {}).get("errors", []) or []:
                if self._severity_from_text(err) in {"high", "critical"}:
                    critical_findings += 1

        recommendations = []
        if critical_findings:
            recommendations.append("Address high/critical findings first")
        if web_enum_anomalies:
            recommendations.append("Review web enum anomalies (TLS/login/dir)")
        if total_open_ports:
            recommendations.append("Tighten exposed services; re-scan after fixes")
        if not recommendations:
            recommendations.append("Surface scan and header audit recommended")
        score = 100.0
        score -= min(total_open_ports * 1.5, 20)  # reduce up to 20 for port exposure
        score -= min(total_vulns * 15, 45)        # each vuln hurts more, cap 45
        score -= min(critical_findings * 20, 40)  # criticals hurt most
        score -= min(web_enum_anomalies * 3, 25)  # anomalies add moderate risk
        if main_findings.get("nuclei"):
            score -= 15  # nuclei findings present
        if main_findings.get("waf"):
            score += 5   # WAF detected gives slight confidence
        score = max(0, min(100, score))
        if score >= 85:
            exposure = "Low Exposure"
        elif score >= 60:
            exposure = "Moderate Exposure"
        else:
            exposure = "High Exposure"
        if web_enum_anomalies == 0:
            anomalies_label = "None"
        elif web_enum_anomalies <= 5:
            anomalies_label = "Low"
        elif web_enum_anomalies <= 15:
            anomalies_label = "Moderate"
        else:
            anomalies_label = "Elevated"
        return {
            "total_scans": total_scans,
            "unique_targets": unique_targets,
            "total_vulnerabilities": total_vulns,
            "open_ports": total_open_ports,
            "recon_profiles": len(recon_entries),
            "unique_recon_targets": recon_targets,
            "web_enum_anomalies": web_enum_anomalies,
            "critical_findings": critical_findings,
            "recommendations": recommendations,
            "technologies": sorted(list(technologies))[:12],
            "security_score": score,
            "exposure": exposure,
            "anomalies_label": anomalies_label,
            "main_findings": main_findings,
        }

    def generate_report(self, format: str = "html") -> None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"network_report_{timestamp}.{format}"
        report_dir = self.report_dir
        report_dir.mkdir(parents=True, exist_ok=True)
        summary = self._build_summary()
        self.report_data["generated_at"] = datetime.utcnow().isoformat() + "Z"
        self.report_data["summary"] = summary
        filepath = report_dir / filename
        
        if format == "json":
            try:
                with open(filepath, "w") as f:
                    json.dump(self.report_data, f, indent=2)
            except OSError as exc:
                logging.error("Failed to write report %s: %s", filepath, exc)
                print(WHITE + f"Failed to write report: {exc}" + RESET)
                return
        elif format == "html":
            all_vulns = []
            recon_entries = self.report_data.get("recon", [])
            for scan in self.report_data["scans"]:
                for vuln in scan.get("vulnerabilities", []):
                    vuln_copy = vuln.copy()
                    vuln_copy["target"] = scan["target"]
                    vuln_copy["port"] = vuln.get("port", "n/a")
                    all_vulns.append(vuln_copy)
            for recon in recon_entries:
                for vuln in recon.get("vulnerabilities", []):
                    vuln_copy = vuln.copy()
                    vuln_copy["target"] = recon.get("resolved_ip") or recon.get("target") or recon.get("input", "n/a")
                    vuln_copy["port"] = vuln.get("port", "n/a")
                    all_vulns.append(vuln_copy)

            json_payload = json.dumps(self.report_data)

            banner_src = "../IMGS/NetSpea1r%20Banner.png"
            banner_file = Path(__file__).resolve().parent / "IMGS" / "NetSpea1r Banner.png"
            if banner_file.exists():
                try:
                    data = base64.b64encode(banner_file.read_bytes()).decode("ascii")
                    banner_src = f"data:image/png;base64,{data}"
                except Exception:
                    pass

            html_content = f"""<!DOCTYPE html>
            <html>
            <head>
                <title>NetSpear Network Analysis Report</title>
                <style>
                    :root {{
                        --bg: #0b1221;
                        --card: #111a2f;
                        --text: #e8f0ff;
                        --accent: #7a06cd;
                        --muted: #8fa2c2;
                        --danger: #f25f5c;
                        --border: #1f2a44;
                        --success: #2ecc71;
                        --sev-high: #ff4d4f;
                        --sev-medium: #f1c40f;
                        --sev-info: #a259ff;
                        --sev-unknown: #9aa5b1;
                    }}
                    * {{ box-sizing: border-box; }}
                    body {{ background: radial-gradient(circle at 20% 20%, rgba(122,6,205,0.08), transparent 25%), radial-gradient(circle at 80% 10%, rgba(242,95,92,0.08), transparent 25%), var(--bg); color: var(--text); font-family: 'Inter', 'SF Pro Display', 'Segoe UI', sans-serif; margin: 0; padding: 32px; }}
                    h1, h2, h3 {{ color: var(--text); margin-bottom: 8px; }}
                    h1 {{ letter-spacing: 0.8px; }}
                    p {{ color: var(--muted); }}
                    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 16px; }}
                    .card {{ background: linear-gradient(145deg, rgba(255,255,255,0.02), rgba(255,255,255,0)); border: 1px solid var(--border); border-radius: 14px; padding: 16px; box-shadow: 0 10px 30px rgba(0,0,0,0.35); }}
                    .pill {{ display: inline-block; padding: 4px 10px; border-radius: 999px; font-size: 12px; letter-spacing: 0.4px; background: rgba(122,6,205,0.1); color: var(--accent); border: 1px solid rgba(122,6,205,0.3); }}
                    table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
                    th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid var(--border); }}
                    th {{ color: var(--muted); text-transform: uppercase; letter-spacing: 0.6px; font-size: 12px; }}
                    tr:last-child td {{ border-bottom: none; }}
                    .muted {{ color: var(--muted); }}
                    .badge-open {{ color: var(--success); font-weight: 600; }}
                    .badge-closed {{ color: var(--muted); }}
                    .badge-filtered {{ color: var(--accent); }}
                    .vuln {{ color: var(--danger); font-weight: 600; }}
                    .sev {{ display: inline-block; padding: 4px 8px; border-radius: 999px; font-size: 12px; margin-left: 6px; border: 1px solid transparent; }}
                    .sev-high, .sev-critical {{ background: rgba(255,77,79,0.16); color: var(--sev-high); border-color: rgba(255,77,79,0.35); }}
                    .sev-medium {{ background: rgba(241,196,15,0.16); color: var(--sev-medium); border-color: rgba(241,196,15,0.45); }}
                    .sev-info, .sev-interesting {{ background: rgba(162,89,255,0.16); color: var(--sev-info); border-color: rgba(162,89,255,0.45); }}
                    .sev-unknown {{ background: rgba(154,165,177,0.12); color: var(--sev-unknown); border-color: rgba(154,165,177,0.4); }}
                    details.log {{ margin-top: 6px; }}
                    details.log summary {{ cursor: pointer; color: var(--muted); }}
                    details.log summary::marker {{ content: ''; }}
                    details.log summary span {{ color: var(--accent); }}
                    .footer-bar {{ display:flex; justify-content: space-between; align-items:center; margin-top:24px; color: var(--muted); font-size:12px; flex-wrap: wrap; gap: 8px; }}
                    .footer {{ margin-top: 24px; color: var(--muted); font-size: 12px; }}
                    @media (max-width: 600px) {{ body {{ padding: 16px; }} }}
                    .actions {{ display:flex; gap:10px; margin: 12px 0 20px 0; flex-wrap: wrap; }}
                    .btn {{ border: 1px solid var(--accent); background: rgba(122,6,205,0.12); color: var(--accent); padding: 8px 14px; border-radius: 8px; cursor: pointer; font-weight: 600; letter-spacing: 0.3px; }}
                    .btn.secondary {{ border-color: var(--muted); color: var(--text); background: rgba(255,255,255,0.05); }}
                    .btn:hover {{ filter: brightness(1.1); }}
                    .hero {{ border: 1px dashed var(--accent); border-radius: 12px; padding: 14px; margin-bottom: 12px; color: var(--muted); text-align:left; background: rgba(122,6,205,0.04); display: inline-block; }}
                    .hero img {{ max-width: 360px; width: 100%; height: auto; display: block; margin: 0; border-radius: 8px; }}
                    .print-footer {{ display: none; }}
                    @media print {{
                        body {{ background: #ffffff !important; color: #000000 !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
                        h1, h2, h3, h4, h5, h6 {{ color: #000000 !important; }}
                        .actions {{ display: none !important; }}
                        .card {{ background: #ffffff; border-color: #444; box-shadow: none; color: #000000; }}
                        .muted {{ color: #333 !important; }}
                        .pill {{ background: #f2e6ff; color: #4a148c; border: 1px solid #b39ddb; }}
                        .sev-high, .sev-critical {{ background: #ffe6e6; color: #c62828; border-color: #ef9a9a; }}
                        .sev-medium {{ background: #fff8e1; color: #ef6c00; border-color: #ffcc80; }}
                        .sev-info, .sev-interesting {{ background: #e3f2fd; color: #1565c0; border-color: #90caf9; }}
                        .sev-unknown {{ background: #eeeeee; color: #424242; border-color: #bdbdbd; }}
                        @page {{ margin: 16mm; }}
                        .print-footer {{ display: block; position: fixed; bottom: 6mm; left: 0; right: 0; text-align: center; font-size: 10px; color: #000; }}
                        .print-footer:not(.first-page) {{ display: none; }}
                    }}
                    .collapsible summary {{ cursor: pointer; color: var(--accent); font-weight: 600; }}
                    .pill-wrap {{ display:flex; gap:6px; flex-wrap: wrap; margin-top:8px; }}
                </style>
            </head>
            <body>
                <div class="hero"><img src="{banner_src}" alt="NetSpear Banner"></div>
                <h1>NetSpear Network Analysis Report</h1>
                <p class="muted">{summary["unique_targets"]} unique target(s) • Built by OpenNET LLC (All rights reserved)</p>
                <div class="actions">
                    <button class="btn" id="btn-pdf">Export PDF</button>
                </div>
                <script id="report-data" type="application/json">{json_payload}</script>
                <div class="print-footer first-page">© 2025 OpenNET LLC • NetSpear</div>
                <div class="card" style="margin-top:12px;" id="summary">
                    <h2>Summary</h2>
                    <p class="muted">A NetSpear analysis was conducted against {summary["unique_targets"]} unique target(s), assessing open ports, service exposure, web-layer anomalies, and vulnerability signatures.</p>
                    <div class="card" style="margin-top:10px; background: rgba(255,255,255,0.03);">
                        <h3>Exposure Overview</h3>
                        <ul class="muted" style="padding-left: 18px; line-height: 1.5;">
                            <li>{summary["open_ports"]} open port identified</li>
                            <li>{summary["total_vulnerabilities"]} confirmed vulnerabilities</li>
                            <li>{summary["web_enum_anomalies"]} web enumeration anomalies detected (TLS, directory enumeration, login endpoints)</li>
                            <li>{summary["recon_profiles"]} recon profiles captured</li>
                            <li>{summary["critical_findings"]} critical/high-severity indicators</li>
                        </ul>
                    </div>
                    <div class="card" style="margin-top:10px; background: rgba(255,255,255,0.03);">
                        <h3>Security Posture Assessment</h3>
                        <p class="muted">The target demonstrates a low attack surface with no confirmed vulnerabilities. However, the presence of web-layer anomalies suggests potential areas of weakness, misconfiguration, or information disclosure.</p>
                    </div>
                    <div class="card" style="margin-top:10px; background: rgba(255,255,255,0.03);">
                        <h3>Recommended Next Steps</h3>
                        <ul class="muted" style="padding-left: 18px; line-height: 1.5;">
                            <li>Investigate web anomalies to validate whether they expose sensitive information</li>
                            <li>Review configuration of exposed services (TLS hardening, directory access policies, authentication endpoints)</li>
                            <li>Apply mitigations and perform a follow-up scan to confirm remediation effectiveness</li>
                        </ul>
                    </div>
                    <div class="card" style="margin-top:10px; background: rgba(122,6,205,0.08); border-color: rgba(122,6,205,0.3);">
                        <h3>Security Score: {summary.get("security_score", 0)} / 100 ({summary.get("exposure","Unknown")})</h3>
                        <p class="muted" style="margin:4px 0;">Attack Surface: Minimal</p>
                        <p class="muted" style="margin:4px 0;">Confirmed Vulnerabilities: {summary["total_vulnerabilities"]}</p>
                        <p class="muted" style="margin:4px 0;">Anomalies Detected: {summary.get("anomalies_label","-")}</p>
                        <p class="muted" style="margin:4px 0;">Critical Issues: {"None" if summary["critical_findings"] == 0 else summary["critical_findings"]}</p>
                    </div>
                    {"" if not summary.get("technologies") else f"<details class='collapsible'><summary>Tech highlights</summary><div class='pill-wrap'>" + ''.join([f"<span class='pill'>{html.escape(t)}</span>" for t in summary.get('technologies', [])]) + "</div></details>"}
                </div>
                <div class="grid" id="technical">
                    <div class="card"><h3>Scans</h3><p class="pill">{summary["total_scans"]} recorded</p></div>
                    <div class="card"><h3>Open Ports</h3><p class="pill">{summary["open_ports"]} detected</p></div>
                    <div class="card"><h3>Vulnerabilities</h3><p class="pill" style="background: rgba(242,95,92,0.12); color: var(--danger); border-color: rgba(242,95,92,0.3);">{summary["total_vulnerabilities"]} flagged</p></div>
                    <div class="card"><h3>Recon Profiles</h3><p class="pill">{summary["recon_profiles"]} captured</p></div>
                </div>
            """

            if not self.report_data["scans"]:
                html_content += "<p class='muted'>No scans captured yet.</p>"
            else:
                for scan in self.report_data["scans"]:
                    html_content += f"""
                    <div class="card" style="margin-top:16px;">
                        <div style="display:flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap;">
                            <div>
                                <h2>{html.escape(scan["target"])}</h2>
                                <p class="muted">{html.escape(scan["label"])} • {html.escape(scan["timestamp"])}</p>
                            </div>
                            <span class="pill">{html.escape(scan.get("host_state", "unknown")).upper()}</span>
                        </div>
                        <table>
                            <tr><th>Port</th><th>Protocol</th><th>Service</th><th>Version</th><th>Status</th></tr>
                    """
                    ports = scan.get("ports", [])
                    if not ports:
                        html_content += "<tr><td colspan='5' class='muted'>No port data recorded.</td></tr>"
                    else:
                        for port in ports:
                            state = html.escape(port.get("state", "unknown"))
                            state_class = "badge-open" if state == "open" else "badge-filtered" if state == "filtered" else "badge-closed"
                            html_content += f"<tr><td>{port.get('port')}</td><td>{html.escape(port.get('protocol',''))}</td><td>{html.escape(port.get('service',''))}</td><td>{html.escape(port.get('version',''))}</td><td class='{state_class}'>{state}</td></tr>"
                    html_content += "</table>"

                    vulns = scan.get("vulnerabilities", [])
                    if vulns:
                        html_content += "<h3 style='margin-top:14px;' id='vulnerabilities'>Vulnerabilities</h3><table><tr><th>CVE</th><th>Description</th><th>Port</th><th>Service</th><th>Risk</th></tr>"
                        for vuln in vulns:
                            sev = vuln.get("severity") or self._severity_from_text(vuln.get("description"))
                            score = self._risk_score_for_severity(sev)
                            html_content += f"<tr><td class='vuln'>{html.escape(vuln.get('cve','Unknown'))}</td><td>{html.escape(vuln.get('description','No description'))}</td><td>{html.escape(str(vuln.get('port','-')))}</td><td>{html.escape(vuln.get('service',''))}</td><td>{self._severity_badge(sev)} <span class='muted' style='margin-left:6px;'>CVSS: {html.escape(score)}</span></td></tr>"
                        html_content += "</table>"
                    
                    suggestions = scan.get("suggestions", []) or []
                    if suggestions:
                        html_content += "<h3 style='margin-top:14px;'>Attack Opportunities</h3><ul>"
                        for suggestion in suggestions:
                            html_content += f"<li>{html.escape(suggestion)}</li>"
                        html_content += "</ul>"
                    web_enum = scan.get("web_enum") or {}
                    if web_enum:
                        html_content += "<h3 style='margin-top:14px;'>Web Enumeration</h3>"
                        html_content += f"<p class='muted'>Base URL: {html.escape(web_enum.get('base_url','-'))}</p>"
                        fp = web_enum.get("fingerprint") or []
                        if fp:
                            html_content += "<h4>Fingerprint</h4><ul>"
                            for entry in fp:
                                if not entry:
                                    continue
                                html_content += f"<li><code>{html.escape(entry.get('cmd',''))}</code>"
                                stdout = (entry.get('stdout') or '').strip()
                                stderr = (entry.get('stderr') or '').strip()
                                rc = entry.get('returncode')
                                if stdout:
                                    html_content += f"<details class='log'><summary><span>[+]</span> stdout (click to expand)</summary><pre style='white-space:pre-wrap; background:rgba(255,255,255,0.03); padding:8px; border-radius:8px; border:1px solid var(--border); color: var(--muted); margin-top:6px;'>{html.escape(stdout)}</pre></details>"
                                if stderr:
                                    html_content += f"<details class='log'><summary><span>[+]</span> stderr (click to expand)</summary><pre style='white-space:pre-wrap; background:rgba(255,255,255,0.03); padding:8px; border-radius:8px; border:1px solid var(--border); color: var(--muted); margin-top:6px;'>{html.escape(stderr)}</pre></details>"
                                if rc is not None:
                                    html_content += f"<div class='muted'>exit: {rc}</div>"
                                html_content += "</li>"
                            html_content += "</ul>"
                        dir_enum = web_enum.get("dir_enum") or []
                        if dir_enum:
                            html_content += "<h4>Directory Bruteforce</h4><ul>"
                            for entry in dir_enum:
                                html_content += f"<li><code>{html.escape(entry.get('cmd',''))}</code>"
                                stdout = (entry.get('stdout') or '').strip()
                                stderr = (entry.get('stderr') or '').strip()
                                rc = entry.get('returncode')
                                if stdout:
                                    html_content += f"<details class='log'><summary><span>[+]</span> stdout (click to expand)</summary><pre style='white-space:pre-wrap; background:rgba(255,255,255,0.03); padding:8px; border-radius:8px; border:1px solid var(--border); color: var(--muted); margin-top:6px;'>{html.escape(stdout)}</pre></details>"
                                if stderr:
                                    html_content += f"<details class='log'><summary><span>[+]</span> stderr (click to expand)</summary><pre style='white-space:pre-wrap; background:rgba(255,255,255,0.03); padding:8px; border-radius:8px; border:1px solid var(--border); color: var(--muted); margin-top:6px;'>{html.escape(stderr)}</pre></details>"
                                if rc is not None:
                                    html_content += f"<div class='muted'>exit: {rc}</div>"
                                html_content += "</li>"
                            html_content += "</ul>"
                        waf = web_enum.get("waf") or []
                        if waf:
                            html_content += "<h4>WAF Detection</h4><ul>"
                            for entry in waf:
                                html_content += f"<li><code>{html.escape(entry.get('cmd',''))}</code>"
                                stdout = (entry.get('stdout') or '').strip()
                                stderr = (entry.get('stderr') or '').strip()
                                if stdout:
                                    html_content += f"<details class='log'><summary><span>[+]</span> stdout (click to expand)</summary><pre style='white-space:pre-wrap; background:rgba(255,255,255,0.03); padding:8px; border-radius:8px; border:1px solid var(--border); color: var(--muted); margin-top:6px;'>{html.escape(stdout)}</pre></details>"
                                if stderr:
                                    html_content += f"<details class='log'><summary><span>[+]</span> stderr (click to expand)</summary><pre style='white-space:pre-wrap; background:rgba(255,255,255,0.03); padding:8px; border-radius:8px; border:1px solid var(--border); color: var(--muted); margin-top:6px;'>{html.escape(stderr)}</pre></details>"
                                html_content += "</li>"
                            html_content += "</ul>"
                        nuclei_runs = web_enum.get("nuclei") or []
                        if nuclei_runs:
                            html_content += "<h4>Nuclei Findings</h4><ul>"
                            for entry in nuclei_runs:
                                html_content += f"<li><code>{html.escape(entry.get('cmd',''))}</code>"
                                stdout = (entry.get('stdout') or '').strip()
                                stderr = (entry.get('stderr') or '').strip()
                                if stdout:
                                    html_content += f"<details class='log'><summary><span>[+]</span> stdout (click to expand)</summary><pre style='white-space:pre-wrap; background:rgba(255,255,255,0.03); padding:8px; border-radius:8px; border:1px solid var(--border); color: var(--muted); margin-top:6px;'>{html.escape(stdout)}</pre></details>"
                                if stderr:
                                    html_content += f"<details class='log'><summary><span>[+]</span> stderr (click to expand)</summary><pre style='white-space:pre-wrap; background:rgba(255,255,255,0.03); padding:8px; border-radius:8px; border:1px solid var(--border); color: var(--muted); margin-top:6px;'>{html.escape(stderr)}</pre></details>"
                                html_content += "</li>"
                            html_content += "</ul>"
                        sqlmap_runs = web_enum.get("sqlmap") or []
                        if sqlmap_runs:
                            html_content += "<h4>SQLMap</h4><ul>"
                            for entry in sqlmap_runs:
                                html_content += f"<li><code>{html.escape(entry.get('cmd',''))}</code>"
                                stdout = (entry.get('stdout') or '').strip()
                                stderr = (entry.get('stderr') or '').strip()
                                if stdout:
                                    html_content += f"<details class='log'><summary><span>[+]</span> stdout (click to expand)</summary><pre style='white-space:pre-wrap; background:rgba(255,255,255,0.03); padding:8px; border-radius:8px; border:1px solid var(--border); color: var(--muted); margin-top:6px;'>{html.escape(stdout)}</pre></details>"
                                if stderr:
                                    html_content += f"<details class='log'><summary><span>[+]</span> stderr (click to expand)</summary><pre style='white-space:pre-wrap; background:rgba(255,255,255,0.03); padding:8px; border-radius:8px; border:1px solid var(--border); color: var(--muted); margin-top:6px;'>{html.escape(stderr)}</pre></details>"
                                html_content += "</li>"
                            html_content += "</ul>"
                        admin_hits = web_enum.get("admin_hits") or []
                        if admin_hits:
                            html_content += "<h4>Admin Endpoints</h4><ul>"
                            for hit in admin_hits:
                                html_content += f"<li>{self._severity_badge('info')} {html.escape(hit)}</li>"
                            html_content += "</ul>"
                        errors = web_enum.get("errors") or []
                        if errors:
                            grouped = self._categorize_web_errors(errors)
                            html_content += "<h4>Web Enum Notes</h4>"
                            for category, notes in grouped.items():
                                if category == "TLS Issues":
                                    html_content += f"<details class='collapsible'><summary>{html.escape(category)} ({len(notes)})</summary><ul>"
                                else:
                                    html_content += f"<h5>{html.escape(category)}</h5><ul>"
                                for err in notes:
                                    sev = self._severity_from_text(err)
                                    html_content += f"<li>{self._severity_badge(sev)} <span class='muted'>{html.escape(err)}</span></li>"
                                html_content += "</ul>"
                                if category == "TLS Issues":
                                    html_content += "</details>"
                    html_content += "</div>"

            if recon_entries:
                html_content += "<div class='card' style='margin-top:16px;' id='recon'><h2>Recon Profiles</h2>"
                for recon in recon_entries:
                    location_parts = [recon.get("geo", {}).get(k) for k in ("city", "region", "country")]
                    location = ", ".join([p for p in location_parts if p])
                    isp = recon.get("geo", {}).get("isp")
                    http_info = recon.get("http", {}) or {}
                    html_content += "<div class='card' style='margin-top:12px;'>"
                    html_content += "<div style='display:flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap;'>"
                    html_content += f"<div><h3>{html.escape(str(recon.get('target') or recon.get('resolved_ip') or recon.get('input') or 'Unknown'))}</h3>"
                    html_content += f"<p class='muted'>{html.escape(recon.get('type',''))} • {html.escape(recon.get('resolved_ip','-'))}</p></div>"
                    if location:
                        html_content += f"<span class='pill'>{html.escape(location)}</span>"
                    html_content += "</div>"
                    html_content += "<table><tr><th>ISP / Org</th><th>ASN</th><th>HTTP Server</th><th>X-Powered-By</th><th>Status</th></tr>"
                    html_content += f"<tr><td>{html.escape(isp or recon.get('geo', {}).get('org','-'))}</td><td>{html.escape(recon.get('geo', {}).get('asn','-'))}</td>"
                    html_content += f"<td>{html.escape(str(http_info.get('server','-')))}</td><td>{html.escape(str(http_info.get('powered_by','-')))}</td>"
                    html_content += f"<td>{html.escape(str(http_info.get('status','-')))}</td></tr></table>"

                    ports = recon.get("scan", {}).get("ports", []) or []
                    html_content += "<h3 style='margin-top:12px;'>Open Ports</h3><table><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Version</th><th>Status</th></tr>"
                    if not ports:
                        html_content += "<tr><td colspan='5' class='muted'>No port data recorded.</td></tr>"
                    else:
                        for port in ports:
                            state = html.escape(port.get("state", "unknown"))
                            state_class = "badge-open" if state == "open" else "badge-filtered" if state == "filtered" else "badge-closed"
                            html_content += f"<tr><td>{port.get('port')}</td><td>{html.escape(port.get('protocol',''))}</td><td>{html.escape(port.get('service',''))}</td><td>{html.escape(port.get('version',''))}</td><td class='{state_class}'>{state}</td></tr>"
                    html_content += "</table>"

                    vulns = recon.get("vulnerabilities", []) or []
                    if vulns:
                        html_content += "<h3 style='margin-top:12px;'>Vulnerabilities</h3><table><tr><th>CVE</th><th>Description</th><th>Port</th><th>Service</th><th>Risk</th></tr>"
                        for vuln in vulns:
                            sev = vuln.get("severity") or self._severity_from_text(vuln.get("description"))
                            score = self._risk_score_for_severity(sev)
                            html_content += f"<tr><td class='vuln'>{html.escape(vuln.get('cve','Unknown'))}</td><td>{html.escape(vuln.get('description','No description'))}</td><td>{html.escape(str(vuln.get('port','-')))}</td><td>{html.escape(vuln.get('service',''))}</td><td>{self._severity_badge(sev)} <span class='muted' style='margin-left:6px;'>CVSS: {html.escape(score)}</span></td></tr>"
                        html_content += "</table>"

                    suggestions = recon.get("suggestions", []) or []
                    if suggestions:
                        html_content += "<h3 style='margin-top:12px;'>Attack Opportunities</h3><ul>"
                        for suggestion in suggestions:
                            html_content += f"<li>{html.escape(suggestion)}</li>"
                        html_content += "</ul>"
                    osint = recon.get("osint") or {}
                    spiderfoot_runs = osint.get("spiderfoot") or []
                    if spiderfoot_runs:
                        html_content += "<h3 style='margin-top:12px;'>OSINT / SpiderFoot</h3><ul>"
                        for entry in spiderfoot_runs:
                            html_content += f"<li><code>{html.escape(entry.get('cmd',''))}</code>"
                            stdout = (entry.get('stdout') or '').strip()
                            stderr = (entry.get('stderr') or '').strip()
                            if stdout:
                                html_content += f"<details class='log'><summary><span>[+]</span> stdout (click to expand)</summary><pre style='white-space:pre-wrap; background:rgba(255,255,255,0.03); padding:8px; border-radius:8px; border:1px solid var(--border); color: var(--muted); margin-top:6px;'>{html.escape(stdout)}</pre></details>"
                            if stderr:
                                html_content += f"<details class='log'><summary><span>[+]</span> stderr (click to expand)</summary><pre style='white-space:pre-wrap; background:rgba(255,255,255,0.03); padding:8px; border-radius:8px; border:1px solid var(--border); color: var(--muted); margin-top:6px;'>{html.escape(stderr)}</pre></details>"
                            html_content += "</li>"
                        html_content += "</ul>"
                    web_enum = recon.get("web_enum") or {}
                    if web_enum:
                        html_content += "<h3 style='margin-top:12px;'>Web Enumeration</h3>"
                        html_content += f"<p class='muted'>Base URL: {html.escape(web_enum.get('base_url','-'))}</p>"
                        fp = web_enum.get("fingerprint") or []
                        if fp:
                            html_content += "<h4>Fingerprint</h4><ul>"
                            for entry in fp:
                                if not entry:
                                    continue
                                html_content += f"<li><code>{html.escape(entry.get('cmd',''))}</code>"
                                stdout = (entry.get('stdout') or '').strip()
                                stderr = (entry.get('stderr') or '').strip()
                                rc = entry.get('returncode')
                                if stdout:
                                    html_content += f"<details class='log'><summary><span>[+]</span> stdout (click to expand)</summary><pre style='white-space:pre-wrap; background:rgba(255,255,255,0.03); padding:8px; border-radius:8px; border:1px solid var(--border); color: var(--muted); margin-top:6px;'>{html.escape(stdout)}</pre></details>"
                                if stderr:
                                    html_content += f"<details class='log'><summary><span>[+]</span> stderr (click to expand)</summary><pre style='white-space:pre-wrap; background:rgba(255,255,255,0.03); padding:8px; border-radius:8px; border:1px solid var(--border); color: var(--muted); margin-top:6px;'>{html.escape(stderr)}</pre></details>"
                                if rc is not None:
                                    html_content += f"<div class='muted'>exit: {rc}</div>"
                                html_content += "</li>"
                            html_content += "</ul>"
                        dir_enum = web_enum.get("dir_enum") or []
                        if dir_enum:
                            html_content += "<h4>Directory Bruteforce</h4><ul>"
                            for entry in dir_enum:
                                html_content += f"<li><code>{html.escape(entry.get('cmd',''))}</code>"
                                stdout = (entry.get('stdout') or '').strip()
                                stderr = (entry.get('stderr') or '').strip()
                                rc = entry.get('returncode')
                                if stdout:
                                    html_content += f"<details class='log'><summary><span>[+]</span> stdout (click to expand)</summary><pre style='white-space:pre-wrap; background:rgba(255,255,255,0.03); padding:8px; border-radius:8px; border:1px solid var(--border); color: var(--muted); margin-top:6px;'>{html.escape(stdout)}</pre></details>"
                                if stderr:
                                    html_content += f"<details class='log'><summary><span>[+]</span> stderr (click to expand)</summary><pre style='white-space:pre-wrap; background:rgba(255,255,255,0.03); padding:8px; border-radius:8px; border:1px solid var(--border); color: var(--muted); margin-top:6px;'>{html.escape(stderr)}</pre></details>"
                                if rc is not None:
                                    html_content += f"<div class='muted'>exit: {rc}</div>"
                                html_content += "</li>"
                            html_content += "</ul>"
                        waf = web_enum.get("waf") or []
                        if waf:
                            html_content += "<h4>WAF Detection</h4><ul>"
                            for entry in waf:
                                html_content += f"<li><code>{html.escape(entry.get('cmd',''))}</code>"
                                stdout = (entry.get('stdout') or '').strip()
                                stderr = (entry.get('stderr') or '').strip()
                                if stdout:
                                    html_content += f"<details class='log'><summary><span>[+]</span> stdout (click to expand)</summary><pre style='white-space:pre-wrap; background:rgba(255,255,255,0.03); padding:8px; border-radius:8px; border:1px solid var(--border); color: var(--muted); margin-top:6px;'>{html.escape(stdout)}</pre></details>"
                                if stderr:
                                    html_content += f"<details class='log'><summary><span>[+]</span> stderr (click to expand)</summary><pre style='white-space:pre-wrap; background:rgba(255,255,255,0.03); padding:8px; border-radius:8px; border:1px solid var(--border); color: var(--muted); margin-top:6px;'>{html.escape(stderr)}</pre></details>"
                                html_content += "</li>"
                            html_content += "</ul>"
                        nuclei_runs = web_enum.get("nuclei") or []
                        if nuclei_runs:
                            html_content += "<h4>Nuclei Findings</h4><ul>"
                            for entry in nuclei_runs:
                                html_content += f"<li><code>{html.escape(entry.get('cmd',''))}</code>"
                                stdout = (entry.get('stdout') or '').strip()
                                stderr = (entry.get('stderr') or '').strip()
                                if stdout:
                                    html_content += f"<details class='log'><summary><span>[+]</span> stdout (click to expand)</summary><pre style='white-space:pre-wrap; background:rgba(255,255,255,0.03); padding:8px; border-radius:8px; border:1px solid var(--border); color: var(--muted); margin-top:6px;'>{html.escape(stdout)}</pre></details>"
                                if stderr:
                                    html_content += f"<details class='log'><summary><span>[+]</span> stderr (click to expand)</summary><pre style='white-space:pre-wrap; background:rgba(255,255,255,0.03); padding:8px; border-radius:8px; border:1px solid var(--border); color: var(--muted); margin-top:6px;'>{html.escape(stderr)}</pre></details>"
                                html_content += "</li>"
                            html_content += "</ul>"
                        sqlmap_runs = web_enum.get("sqlmap") or []
                        if sqlmap_runs:
                            html_content += "<h4>SQLMap</h4><ul>"
                            for entry in sqlmap_runs:
                                html_content += f"<li><code>{html.escape(entry.get('cmd',''))}</code>"
                                stdout = (entry.get('stdout') or '').strip()
                                stderr = (entry.get('stderr') or '').strip()
                                if stdout:
                                    html_content += f"<details class='log'><summary><span>[+]</span> stdout (click to expand)</summary><pre style='white-space:pre-wrap; background:rgba(255,255,255,0.03); padding:8px; border-radius:8px; border:1px solid var(--border); color: var(--muted); margin-top:6px;'>{html.escape(stdout)}</pre></details>"
                                if stderr:
                                    html_content += f"<details class='log'><summary><span>[+]</span> stderr (click to expand)</summary><pre style='white-space:pre-wrap; background:rgba(255,255,255,0.03); padding:8px; border-radius:8px; border:1px solid var(--border); color: var(--muted); margin-top:6px;'>{html.escape(stderr)}</pre></details>"
                                html_content += "</li>"
                            html_content += "</ul>"
                        admin_hits = web_enum.get("admin_hits") or []
                        if admin_hits:
                            html_content += "<h4>Admin Endpoints</h4><ul>"
                            for hit in admin_hits:
                                html_content += f"<li>{self._severity_badge('info')} {html.escape(hit)}</li>"
                            html_content += "</ul>"
                        errors = web_enum.get("errors") or []
                        if errors:
                            grouped = self._categorize_web_errors(errors)
                            html_content += "<h4>Web Enum Notes</h4>"
                            for category, notes in grouped.items():
                                html_content += f"<h5>{html.escape(category)}</h5><ul>"
                                for err in notes:
                                    sev = self._severity_from_text(err)
                                    html_content += f"<li>{self._severity_badge(sev)} <span class='muted'>{html.escape(err)}</span></li>"
                                html_content += "</ul>"
                    html_content += "</div>"
                html_content += "</div>"

            if all_vulns:
                html_content += "<div class='card' style='margin-top:16px;' id='vulnerabilities'><h2>Vulnerability Rollup</h2><table><tr><th>Target</th><th>CVE</th><th>Description</th><th>Port</th><th>Service</th><th>Risk</th></tr>"
                for vuln in all_vulns:
                    sev = vuln.get("severity") or self._severity_from_text(vuln.get("description"))
                    score = self._risk_score_for_severity(sev)
                    html_content += f"<tr><td>{html.escape(vuln.get('target',''))}</td><td class='vuln'>{html.escape(vuln.get('cve','Unknown'))}</td><td>{html.escape(vuln.get('description','No description'))}</td><td>{html.escape(str(vuln.get('port','-')))}</td><td>{html.escape(vuln.get('service',''))}</td><td>{self._severity_badge(sev)} <span class='muted' style='margin-left:6px;'>CVSS: {html.escape(score)}</span></td></tr>"
                html_content += "</table></div>"

            html_content += "<div class='card' style='margin-top:16px;' id='appendix'><h2>Appendix (JSON dump)</h2><p class='muted'>Download the full report data as JSON.</p><button class='btn secondary' id='btn-json'>Download JSON</button></div>"

            html_content += f"<div class='footer-bar'><div>Report id: {html.escape(timestamp)} • Saved to {html.escape(str(filepath))}</div><div>© 2025 OpenNET LLC • NetSpear v1.0</div></div></body></html>"

            html_content += """
            <script>
                (function() {
                    const fname = \"""" + filename.replace('.html','') + """\";
                    const pdfBtn = document.getElementById('btn-pdf');
                    const jsonBtn = document.getElementById('btn-json');
                    const dataEl = document.getElementById('report-data');
                    const payload = dataEl ? dataEl.textContent : null;
                    if (pdfBtn) {
                        pdfBtn.addEventListener('click', () => window.print());
                    }
                    if (jsonBtn && payload) {
                        jsonBtn.addEventListener('click', () => {
                            try {
                                const blob = new Blob([payload], { type: 'application/json' });
                                const url = URL.createObjectURL(blob);
                                const a = document.createElement('a');
                                a.href = url;
                                a.download = `${fname}.json`;
                                document.body.appendChild(a);
                                a.click();
                                document.body.removeChild(a);
                                URL.revokeObjectURL(url);
                            } catch (e) {
                                console.error('Failed to export JSON', e);
                            }
                        });
                    }
                })();
            </script>
            """

            try:
                with open(filepath, "w") as f:
                    f.write(html_content)
            except OSError as exc:
                logging.error("Failed to write report %s: %s", filepath, exc)
                print(WHITE + f"Failed to write report: {exc}" + RESET)
                return
        else:
            logging.error("Unsupported report format requested: %s", format)
            print(WHITE + f"Unsupported report format: {format}" + RESET)
            return
        
        logging.info(f"Report generated: {filepath}")
        print(WHITE + f"Report generated: {filepath}" + RESET)

    def archive_old_reports(self, days_old: int = 7) -> int:
        """Move reports older than N days into Reports/Archive."""
        report_dir = self.report_dir
        report_dir.mkdir(parents=True, exist_ok=True)
        archive_dir = self.archive_dir
        archive_dir.mkdir(parents=True, exist_ok=True)
        now_ts = datetime.now().timestamp()
        threshold = None if days_old is None else now_ts - (days_old * 86400)
        moved = 0
        try:
            for file in report_dir.iterdir():
                if file.is_file() and file.suffix in {".html", ".json"} and file.parent == report_dir:
                    # Skip files modified moments ago to avoid moving in-use files.
                    if file.stat().st_mtime > now_ts - ARCHIVE_GRACE_SECONDS:
                        continue
                    if threshold is None or file.stat().st_mtime <= threshold:
                        dest = archive_dir / file.name
                        if dest.exists():
                            dest = archive_dir / f"{file.stem}_{int(now_ts)}{file.suffix}"
                        file.rename(dest)
                        moved += 1
        except OSError as exc:
            logging.error("Failed to archive reports: %s", exc)
        logging.info(f"Archived {moved} report(s) to {archive_dir}")
        return moved

    def clear_all_reports(self) -> int:
        """Delete all reports in the Reports directory."""
        report_dir = self.report_dir
        report_dir.mkdir(parents=True, exist_ok=True)
        removed = 0
        try:
            for file in report_dir.iterdir():
                if file.is_file() and file.suffix in {".html", ".json"}:
                    if file.stat().st_mtime > datetime.now().timestamp() - ARCHIVE_GRACE_SECONDS:
                        continue
                    try:
                        file.unlink()
                        removed += 1
                    except OSError as exc:
                        logging.warning("Failed to remove report %s: %s", file, exc)
        except OSError as exc:
            logging.error("Failed to iterate reports for clear: %s", exc)
        logging.info(f"Cleared {removed} report(s) in {report_dir}")
        return removed

    def clear_archived_reports(self) -> int:
        """Delete all reports stored in Reports/Archive."""
        archive_dir = self.archive_dir
        archive_dir.mkdir(parents=True, exist_ok=True)
        removed = 0
        try:
            for file in archive_dir.iterdir():
                if file.is_file() and file.suffix in {".html", ".json"}:
                    if file.stat().st_mtime > datetime.now().timestamp() - ARCHIVE_GRACE_SECONDS:
                        continue
                    try:
                        file.unlink()
                        removed += 1
                    except OSError as exc:
                        logging.warning("Failed to remove archived report %s: %s", file, exc)
        except OSError as exc:
            logging.error("Failed to iterate archive for clear: %s", exc)
        logging.info(f"Cleared {removed} archived report(s) in {archive_dir}")
        return removed
