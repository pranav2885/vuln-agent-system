import json, hashlib
from datetime import datetime, timezone

def make_uid(host, port, protocol, name):
    key = f"{host}|{port}|{protocol}|{name}"
    return hashlib.sha256(key.encode()).hexdigest()

def normalize_report(raw):
    findings = []
    host = raw.get("hostname", "unknown")

    # Open ports
    for conn in raw.get("listening", []):
        laddr = conn.get("laddr","")
        parts = laddr.split(":")
        port = int(parts[-1]) if parts and parts[-1].isdigit() else None
        
        # Extract service information
        process_name = conn.get("process_name", "Unknown")
        service_type = conn.get("service_type", "Unknown")
        
        # Create description with service info
        description = f"Listening on {laddr}"
        if service_type != "Unknown":
            description += f" - {service_type} service"
        if process_name != "Unknown":
            description += f" (Process: {process_name})"

        findings.append({
            "uid": make_uid(host, port, "tcp", "open_port"),
            "type": "open_port",
            "title": f"Open port {port}",
            "description": description,
            "host_ip": host,
            "port": port,
            "process_name": process_name,
            "service_type": service_type,
            "severity": "LOW",
            "evidence": conn
        })

    # Simple demo missing-patch rule
    hotfixes = raw.get("hotfixes", [])
    demo_kb = "KB999999"
    found = False
    if isinstance(hotfixes, list):
        for h in hotfixes:
            if isinstance(h, dict) and h.get("HotFixID") == demo_kb:
                found = True
                break

    if not found:
        findings.append({
            "uid": make_uid(host, 0, "os", "missing_hotfix_demo"),
            "type": "missing_patch",
            "title": f"Missing patch {demo_kb}",
            "description": f"{demo_kb} not present in hotfix list (demo rule)",
            "host_ip": host,
            "port": None,
            "severity": "HIGH",
            "evidence": hotfixes
        })

    aggregated = {
        "scan_id": hashlib.sha256((host + datetime.now(timezone.utc).isoformat()).encode()).hexdigest(),
        "generated_at": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        "host": {"hostname": host, "platform": raw.get("platform")},
        "findings": findings,
        "summary": {"total_findings": len(findings)}
    }
    return aggregated

if __name__ == "__main__":
    raw = {}
    try:
        raw = json.load(open("report_raw.json","r",encoding="utf-8"))
    except:
        print("report_raw.json not found or invalid")
    agg = normalize_report(raw)
    with open("agg.json","w",encoding="utf-8") as fh:
        json.dump(agg, fh, indent=2)
    print("Saved agg.json")
