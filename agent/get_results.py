#!/usr/bin/env python
"""Get AI analysis results from server"""
import sys, json, requests, os
from dotenv import load_dotenv

load_dotenv()

BACKEND = os.getenv("BACKEND_URL", "http://localhost:8000").rstrip("/")
API_TOKEN = os.getenv("API_TOKEN", "server-demo-token")

def print_header(text):
    """Print a formatted header"""
    print("\n" + "="*70)
    print(f"  {text}")
    print("="*70)

def print_severity_badge(severity):
    """Return colored severity badge"""
    badges = {
        "CRITICAL": "🔴 CRITICAL",
        "HIGH": "🟠 HIGH",
        "MEDIUM": "🟡 MEDIUM",
        "LOW": "🟢 LOW"
    }
    return badges.get(severity, severity)

def display_results(result):
    """Display results in user-friendly format"""
    if result.get("status") == "pending":
        print("\n⏳ Analysis still processing... try again in a few seconds")
        return
    
    if result.get("status") != "done":
        print(f"\n? Status: {result.get('status')}")
        return
    
    ai = result.get("ai", {})
    summary = ai.get("summary", "")
    
    # Extract model type from summary
    model_type = "Unknown"
    if "HuggingFace" in summary:
        model_type = "🤖 AI Model: HuggingFace (codechrl/bert-micro-cybersecurity)"
    elif "Rule-based" in summary:
        model_type = "📋 Analysis Method: Rule-based (Hardcoded Logic)"
    
    print_header("VULNERABILITY SCAN REPORT")
    print(f"\n{model_type}")
    print(f"Scan ID: {result.get('scan_id')}")
    print(f"Status: ✓ Complete")
    print(f"\n{summary}")
    
    findings = ai.get("prioritized_findings", [])
    
    # Group by severity
    by_severity = {}
    for f in findings:
        sev = f.get("severity", "LOW")
        if sev not in by_severity:
            by_severity[sev] = []
        by_severity[sev].append(f)
    
    # Summary table
    print_header("SEVERITY BREAKDOWN")
    print(f"\n{'Severity':<15} {'Count':<10} {'Description'}")
    print("-" * 70)
    
    severity_desc = {
        "CRITICAL": "Immediate action required",
        "HIGH": "Should be fixed soon",
        "MEDIUM": "Fix when possible",
        "LOW": "Monitor or review"
    }
    
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = len(by_severity.get(sev, []))
        if count > 0:
            badge = print_severity_badge(sev)
            desc = severity_desc.get(sev, "")
            print(f"{badge:<20} {count:<10} {desc}")
    
    # Top priorities
    print_header("TOP PRIORITY ISSUES")
    checklist = ai.get('fix_now_checklist', [])[:5]
    if checklist:
        for idx, item in enumerate(checklist, 1):
            # Find the full finding details
            finding = next((f for f in findings if f.get('title') == item), None)
            if finding:
                sev = finding.get('severity', 'LOW')
                badge = print_severity_badge(sev)
                print(f"\n{idx}. {badge} - {item}")
                
                # Show service info if available
                service_type = finding.get('service_type', 'Unknown')
                process_name = finding.get('process_name', 'Unknown')
                if service_type != 'Unknown' or process_name != 'Unknown':
                    info_parts = []
                    if service_type != 'Unknown':
                        info_parts.append(f"Service: {service_type}")
                    if process_name != 'Unknown':
                        info_parts.append(f"Process: {process_name}")
                    if info_parts:
                        print(f"   ℹ️  {' | '.join(info_parts)}")
                
                print(f"   What this means: {finding.get('recommended_steps', ['No steps available'])[0]}")
    else:
        print("\nNo critical issues found!")
    
    # Detailed findings by severity
    print_header("DETAILED FINDINGS")
    
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        items = by_severity.get(sev, [])
        if not items:
            continue
        
        print(f"\n{print_severity_badge(sev)} - {len(items)} issue(s):")
        print("-" * 70)
        
        # Remove duplicates by uid
        seen = set()
        unique_items = []
        for item in items:
            uid = item.get('uid')
            if uid not in seen:
                seen.add(uid)
                unique_items.append(item)
        
        for idx, f in enumerate(unique_items[:10], 1):  # Show max 10 per severity
            title = f.get('title', 'Unknown issue')
            steps = f.get('recommended_steps', [])
            
            # Display title
            print(f"\n  {idx}. {title}")
            
            # Show service info for open ports
            if 'service_type' in f or 'process_name' in f:
                service_type = f.get('service_type', 'Unknown')
                process_name = f.get('process_name', 'Unknown')
                if service_type != 'Unknown' or process_name != 'Unknown':
                    info_parts = []
                    if service_type != 'Unknown':
                        info_parts.append(f"Service: {service_type}")
                    if process_name != 'Unknown':
                        info_parts.append(f"Process: {process_name}")
                    if info_parts:
                        print(f"     ℹ️  {' | '.join(info_parts)}")
            
            if steps:
                print(f"     → What to do: {steps[0]}")
            
            # Show verification if available
            verify = f.get('verification_commands', [])
            if verify:
                print(f"     → Check with: {verify[0]}")
        
        if len(items) > 10:
            print(f"\n  ... and {len(items) - 10} more {sev} severity issues")
    
    # Raw JSON option
    print_header("ACTIONS")
    print("\n📝 To see full JSON report, run:")
    print(f"   python get_results.py {result.get('scan_id')} --json")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python get_results.py <scan_id> [--json]")
        sys.exit(1)
    
    scan_id = sys.argv[1]
    show_json = "--json" in sys.argv
    
    url = f"{BACKEND}/api/scans/{scan_id}"
    headers = {"Authorization": f"Bearer {API_TOKEN}"}
    
    try:
        r = requests.get(url, headers=headers, timeout=10)
        result = r.json()
        
        if show_json:
            print(json.dumps(result, indent=2))
        else:
            display_results(result)
            
    except Exception as e:
        print(f"✗ Error: {e}")
        sys.exit(1)
