import os
import json
import sys
from collections import defaultdict
import google.generativeai as genai

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")

def parse_garak_jsonl(report_path):
    """Parse Garak JSONL report and extract issues, passed/failed counts."""
    issues = defaultdict(list)
    passed = 0
    failed = 0
    meta = {}

    with open(report_path, "r") as f:
        for line in f:
            entry = json.loads(line)
            
            if entry.get("entry_type") == "start_run setup":
                meta["model"] = entry.get("plugins.target_name")
                meta["probe_spec"] = entry.get("plugins.probe_spec")
            
            if entry.get("entry_type") == "attempt":
                probe = entry.get("probe_classname")
                status = entry.get("status")
                issues[probe].append(entry)
                if status == 2:  # Status 2 means evaluated
                    detector_results = entry.get("detector_results", {})
                    # Check if any detector failed (score 0.0)
                    if any(score == 0.0 for scores in detector_results.values() for score in scores):
                        failed += 1
                    else:
                        passed += 1
            
            if entry.get("entry_type") == "eval":
                # Extract evaluation summary if needed
                pass
    
    return issues, passed, failed, meta

def compose_gemini_prompt(issues, passed, failed, meta):
    """Compose detailed prompt for Gemini API."""
    probes_tested = list(issues.keys())
    model_name = meta.get("model", "Unknown")
    probe_spec = meta.get("probe_spec", "Unknown")
    
    prompt = f"""
Analyze this Garak LLM vulnerability scan report and provide a concise, professional markdown summary.

**Scan Details:**
- Model Tested: {model_name}
- Probe Suite: {probe_spec}
- Total Attempts: {passed + failed}
- Passed (Safe): {passed}
- Failed (Vulnerable): {failed}

**Probes Tested:**
{', '.join(probes_tested)}

**Detailed Findings:**
"""
    for probe, findings in issues.items():
        failed_count = sum(
            any(score == 0.0 for scores in e.get("detector_results", {}).values() for score in scores)
            for e in findings if e.get("status") == 2
        )
        prompt += f"\n- {probe}: {len(findings)} attempts, {failed_count} vulnerabilities detected"
    
    prompt += """

Please provide:
1. An executive summary (2-3 sentences) of the overall security posture
2. Key vulnerabilities detected, grouped by OWASP Top 10 category if applicable
3. Risk level assessment (Low, Medium, High, Critical)
4. Actionable recommendations for remediation

Format the output as clean markdown suitable for a GitHub Actions job summary.
"""
    return prompt

def call_gemini_api(prompt):
    """Call Gemini API using official SDK."""
    if not GEMINI_API_KEY:
        raise Exception("GEMINI_API_KEY not set in environment variables.")
    
    # Configure API key
    genai.configure(api_key=GEMINI_API_KEY)
    
    # Initialize model
    model = genai.GenerativeModel('gemini-2.0-flash')
    
    # Generate content
    response = model.generate_content(prompt)
    
    return response.text

def main():
    if len(sys.argv) != 2:
        print("Usage: python gemini_summary.py <garak-scan.report.jsonl>")
        sys.exit(1)
    
    report_path = sys.argv[1]
    
    if not os.path.exists(report_path):
        print(f"Error: Report file not found: {report_path}")
        sys.exit(1)
    
    issues, passed, failed, meta = parse_garak_jsonl(report_path)
    prompt = compose_gemini_prompt(issues, passed, failed, meta)
    summary_md = call_gemini_api(prompt)
    
    # Print markdown summary to stdout
    print(summary_md)

if __name__ == "__main__":
    main()
