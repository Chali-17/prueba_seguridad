cat > generate_report.py << 'EOF'
#!/usr/bin/env python3
import os, time, requests

DT_URL = os.environ["DT_URL"]
DT_API_KEY = os.environ["DT_API_KEY"]
PROJECT_UUID = os.environ["DT_PROJECT_UUID"]
HEADERS = {"X-Api-Key": DT_API_KEY}

def get_findings():
    r = requests.get(f"{DT_URL}/api/v1/finding/project/{PROJECT_UUID}", headers=HEADERS)
    r.raise_for_status()
    return r.json()

def severity_order(sev):
    order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4,"UNASSIGNED":5}
    return order.get(sev, 6)

def build_markdown(findings):
    lines = [f"# Informe de Analisis de Vulnerabilidades\n",
             f"**Proyecto UUID:** {PROJECT_UUID}\n",
             f"**Fecha:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n",
             f"**Total de hallazgos:** {len(findings)}\n"]
    if not findings:
        lines.append("\nNo se encontraron vulnerabilidades.\n")
    else:
        findings.sort(key=lambda f: severity_order(f["vulnerability"].get("severity","UNASSIGNED")))
        counts = {}
        for f in findings:
            sev = f["vulnerability"].get("severity","UNASSIGNED")
            counts[sev] = counts.get(sev,0)+1
        lines.append("\n## Resumen por severidad\n")
        lines.append("| Severidad | Cantidad |")
        lines.append("|---|---|")
        for sev,c in sorted(counts.items(), key=lambda x: severity_order(x[0])):
            lines.append(f"| {sev} | {c} |")
        lines.append("\n## Detalle de vulnerabilidades\n")
        for f in findings:
            comp, vuln = f["component"], f["vulnerability"]
            lines.append(f"### {vuln.get('vulnId','N/A')} - {vuln.get('severity','N/A')}\n")
            lines.append(f"- **Componente:** {comp.get('name')} {comp.get('version')}")
            lines.append(f"- **CVSS:** {vuln.get('cvssV3BaseScore', vuln.get('cvssV2BaseScore','N/A'))}")
            lines.append(f"- **Descripcion:** {(vuln.get('description') or 'Sin descripcion').strip()[:500]}")
            rec = vuln.get('recommendation') or "Actualizar a una version del componente donde esta vulnerabilidad este corregida."
            lines.append(f"- **Recomendacion:** {rec}\n")
    return "\n".join(lines)

if __name__ == "__main__":
    findings = get_findings()
    with open("reporte.md","w",encoding="utf-8") as f:
        f.write(build_markdown(findings))
    print("reporte.md generado.")
EOF
