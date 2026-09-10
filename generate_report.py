#!/usr/bin/env python3
import os, time, requests

DT_URL = os.environ["DT_URL"]
DT_API_KEY = os.environ["DT_API_KEY"]
PROJECT_UUID = os.environ["DT_PROJECT_UUID"]
HEADERS = {"X-Api-Key": DT_API_KEY}

SEVERITY_COLOR = {
    "CRITICAL": "red",
    "HIGH": "orange",
    "MEDIUM": "yellow!70!black",
    "LOW": "blue",
    "INFO": "gray",
    "UNASSIGNED": "gray"
}

def get_findings():
    r = requests.get(f"{DT_URL}/api/v1/finding/project/{PROJECT_UUID}", headers=HEADERS)
    r.raise_for_status()
    return r.json()

def severity_order(sev):
    order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4,"UNASSIGNED":5}
    return order.get(sev, 6)

def colored(text, sev):
    color = SEVERITY_COLOR.get(sev, "black")
    return f"\\textcolor{{{color}}}{{\\textbf{{{text}}}}}"

def build_markdown(findings):
    lines = []
    lines.append("---")
    lines.append("title: \"Informe de Analisis de Vulnerabilidades\"")
    lines.append(f"subtitle: \"Proyecto: mi-proyecto-demo\"")
    lines.append(f"date: \"{time.strftime('%Y-%m-%d %H:%M:%S')}\"")
    lines.append("author: \"Generado automaticamente por el pipeline de Jenkins\"")
    lines.append("toc: true")
    lines.append("toc-depth: 2")
    lines.append("colorlinks: true")
    lines.append("---")
    lines.append("")
    lines.append(f"**Proyecto UUID:** `{PROJECT_UUID}`")
    lines.append("")
    lines.append(f"**Total de hallazgos:** {len(findings)}")
    lines.append("")
    lines.append("\\newpage")
    lines.append("")

    if not findings:
        lines.append("## Resultado")
        lines.append("")
        lines.append("No se encontraron vulnerabilidades en los componentes analizados.")
    else:
        findings.sort(key=lambda f: severity_order(f["vulnerability"].get("severity","UNASSIGNED")))
        counts = {}
        for f in findings:
            sev = f["vulnerability"].get("severity","UNASSIGNED")
            counts[sev] = counts.get(sev,0)+1

        lines.append("## Resumen Ejecutivo")
        lines.append("")
        lines.append("| Severidad | Cantidad |")
        lines.append("|:---|---:|")
        for sev, c in sorted(counts.items(), key=lambda x: severity_order(x[0])):
            lines.append(f"| {colored(sev, sev)} | {c} |")
        lines.append("")
        lines.append("\\newpage")
        lines.append("")

        lines.append("## Detalle de Vulnerabilidades")
        lines.append("")
        for f in findings:
            comp, vuln = f["component"], f["vulnerability"]
            sev = vuln.get('severity','N/A')
            lines.append(f"### {vuln.get('vulnId','N/A')} {colored('[' + sev + ']', sev)}")
            lines.append("")
            lines.append(f"| Campo | Valor |")
            lines.append(f"|:---|:---|")
            lines.append(f"| **Componente** | `{comp.get('name')}` version `{comp.get('version')}` |")
            lines.append(f"| **CVSS Score** | {vuln.get('cvssV3BaseScore', vuln.get('cvssV2BaseScore','N/A'))} |")
            lines.append("")
            desc = (vuln.get('description') or 'Sin descripcion disponible.').strip()[:600].replace('\n', ' ')
            lines.append(f"**Descripcion:** {desc}")
            lines.append("")
            rec = vuln.get('recommendation') or "Actualizar el componente a una version donde esta vulnerabilidad este corregida."
            lines.append(f"**Recomendacion:** {rec}")
            lines.append("")
            lines.append("---")
            lines.append("")

    return "\n".join(lines)

if __name__ == "__main__":
    findings = get_findings()
    with open("reporte.md","w",encoding="utf-8") as f:
        f.write(build_markdown(findings))
    print("reporte.md generado.")
