import argparse
import json
import os
from jinja2 import Environment, FileSystemLoader, select_autoescape
import plotly.graph_objects as go

def parse_garak_jsonl(path):
    vulnerabilities = []
    with open(path, 'r') as file:
        for line in file:
            vulnerabilities.append(json.loads(line))
    return vulnerabilities

def summarize_vulnerabilities(vulnerabilities):
    summary = {
        "total": len(vulnerabilities),
        "severity_counts": {"low": 0, "medium": 0, "high": 0, "critical": 0},
        "categories": {}
    }
    for vuln in vulnerabilities:
        sev = vuln.get("severity", "low").lower()
        summary["severity_counts"][sev] = summary["severity_counts"].get(sev, 0) + 1

        cats = vuln.get("categories", [])
        for cat in cats:
            summary["categories"][cat] = summary["categories"].get(cat, 0) + 1
    return summary

def create_severity_pie_chart(severity_counts):
    labels = list(severity_counts.keys())
    values = [severity_counts[label] for label in labels]

    fig = go.Figure(data=[go.Pie(labels=labels, values=values, hole=.4)])
    fig.update_traces(marker=dict(colors=['#4caf50', '#2196f3', '#ff9800', '#f44336']))
    return fig.to_html(full_html=False)

def create_category_bar_chart(categories):
    labels = list(categories.keys())
    values = [categories[label] for label in labels]

    fig = go.Figure(data=[go.Bar(x=labels, y=values, marker_color='indianred')])
    fig.update_layout(xaxis_title="OWASP LLM Categories", yaxis_title="Number of Vulnerabilities")
    return fig.to_html(full_html=False)

def main(args):
    env = Environment(
        loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), "../templates")),
        autoescape=select_autoescape(['html', 'xml'])
    )

    vulnerabilities = parse_garak_jsonl(args.input)
    summary = summarize_vulnerabilities(vulnerabilities)
    severity_chart = create_severity_pie_chart(summary["severity_counts"])
    category_chart = create_category_bar_chart(summary["categories"])

    template = env.get_template("report_template.html")
    rendered_html = template.render(
        total_vulns=summary["total"],
        severity_counts=summary["severity_counts"],
        category_counts=summary["categories"],
        vulnerabilities=vulnerabilities,
        severity_chart=severity_chart,
        category_chart=category_chart
    )

    # Ensure output directory exists
    os.makedirs(os.path.dirname(args.output), exist_ok=True)

    with open(args.output, 'w') as f:
        f.write(rendered_html)

    print(f"Report generated at {args.output}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate HTML report from Garak JSONL output.")
    parser.add_argument('--input', required=True, help="Path to Garak JSONL scan output")
    parser.add_argument('--output', required=True, help="Path to output HTML report")
    args = parser.parse_args()
    main(args)
