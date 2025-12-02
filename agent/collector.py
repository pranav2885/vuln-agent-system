import psutil, socket, platform, subprocess, json
from datetime import datetime, timezone

def run_powershell(cmd):
    p = subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                       capture_output=True, text=True)
    return p.stdout

def gather_basic():
    data = {}
    data['hostname'] = socket.gethostname()
    data['platform'] = platform.platform()
    data['time'] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')

    conns = []
    # Build process lookup dictionary for faster access
    process_map = {}
    for p in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            process_map[p.info['pid']] = {
                'name': p.info['name'],
                'exe': p.info.get('exe')
            }
        except:
            pass
    
    try:
        for c in psutil.net_connections(kind='inet'):
            if c.status == 'LISTEN':
                laddr = f"{c.laddr.ip}:{c.laddr.port}"
                port = c.laddr.port
                
                # Get process info for this connection
                service_name = "Unknown"
                process_name = "Unknown"
                if c.pid and c.pid in process_map:
                    process_name = process_map[c.pid]['name']
                    service_name = process_name
                
                # Map common ports to known services
                known_services = {
                    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
                    53: "DNS", 80: "HTTP", 110: "POP3", 135: "RPC",
                    139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
                    445: "SMB", 3306: "MySQL", 3389: "RDP",
                    5432: "PostgreSQL", 5900: "VNC", 8000: "HTTP-Alt",
                    8080: "HTTP-Proxy", 27017: "MongoDB"
                }
                
                service_type = known_services.get(port, "Unknown")
                
                conns.append({
                    "laddr": laddr,
                    "pid": c.pid,
                    "type": str(c.type),
                    "port": port,
                    "process_name": process_name,
                    "service_name": service_name,
                    "service_type": service_type
                })
    except Exception as e:
        conns = [{"error": str(e)}]
    data['listening'] = conns

    procs = []
    for pid, info in process_map.items():
        procs.append({
            "pid": pid,
            "name": info['name'],
            "exe": info.get('exe')
        })
    data['processes'] = procs

    return data

def gather_hotfixes():
    out = run_powershell("Get-HotFix | Select HotFixID,InstalledOn | ConvertTo-Json -Compress")
    try:
        return json.loads(out)
    except:
        return {"raw": out}

def gather_services():
    out = run_powershell("Get-Service | Select Name,DisplayName,Status,StartType | ConvertTo-Json -Compress")
    try:
        return json.loads(out)
    except:
        return {"raw": out}

def collect_all():
    report = gather_basic()
    report['hotfixes'] = gather_hotfixes()
    report['services'] = gather_services()
    return report

if __name__ == "__main__":
    r = collect_all()
    with open("report_raw.json","w",encoding="utf-8") as fh:
        json.dump(r, fh, indent=2)
    print("Saved report_raw.json")

