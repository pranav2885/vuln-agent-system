import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading, json, os
from collector import collect_all
from normalize import normalize_report
from uploader import upload_aggregated
from dotenv import load_dotenv

load_dotenv()

class VulnAgentApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Vuln Agent (Prototype)")
        self.root.geometry("900x640")

        self.last_scan_id = None
        self.backend = os.getenv("BACKEND_URL", "http://localhost:8000").rstrip("/")
        self.api_token = os.getenv("API_TOKEN", "server-demo-token")

        # Top frame with buttons
        top = ttk.Frame(root, padding=8)
        top.pack(side=tk.TOP, fill=tk.X)

        self.scan_btn = ttk.Button(top, text="Scan Now", command=self._threaded(self.do_scan))
        self.upload_btn = ttk.Button(top, text="Upload Report", command=self._threaded(self.do_upload))
        self.poll_btn = ttk.Button(top, text="Get Result", command=self._threaded(self.do_poll))
        self.clear_btn = ttk.Button(top, text="Clear", command=self.do_clear)
        self.scan_btn.pack(side=tk.LEFT, padx=6)
        self.upload_btn.pack(side=tk.LEFT, padx=6)
        self.poll_btn.pack(side=tk.LEFT, padx=6)
        self.clear_btn.pack(side=tk.LEFT, padx=6)

        # Middle: status label
        self.status_var = tk.StringVar(value="Idle")
        status = ttk.Label(top, textvariable=self.status_var)
        status.pack(side=tk.RIGHT)

        # Center: scrolled text for output
        self.output = scrolledtext.ScrolledText(root, wrap=tk.WORD, font=("Consolas", 10))
        self.output.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        # Bottom: help text
        help_frame = ttk.Frame(root, padding=6)
        help_frame.pack(side=tk.BOTTOM, fill=tk.X)
        ttk.Label(help_frame, text="Scan → Upload → Get Result | Configure BACKEND_URL + API_TOKEN in .env").pack(side=tk.LEFT)

    def _threaded(self, fn):
        def wrapper():
            t = threading.Thread(target=fn, daemon=True)
            t.start()
        return wrapper

    def log(self, text):
        self.output.insert(tk.END, text + "\n")
        self.output.see(tk.END)

    def set_status(self, s):
        self.status_var.set(s)

    def do_clear(self):
        """Clear the output window"""
        self.output.delete(1.0, tk.END)
        self.set_status("Cleared")

    def do_scan(self):
        try:
            self.set_status("Scanning...")
            self.log("Running local scan...")
            raw = collect_all()
            with open("report_raw.json","w",encoding="utf-8") as f:
                json.dump(raw, f, indent=2)
            agg = normalize_report(raw)
            with open("agg.json","w",encoding="utf-8") as f:
                json.dump(agg, f, indent=2)
            self.log("Scan complete. agg.json created.")
            self.set_status("Scan OK")
        except Exception as e:
            self.log(f"Scan error: {e}")
            self.set_status("Error")

    def do_upload(self):
        try:
            if not os.path.exists("agg.json"):
                messagebox.showwarning("Missing file", "Run Scan first.")
                return
            self.set_status("Uploading...")
            self.log("Uploading agg.json to server...")
            resp = upload_aggregated("agg.json")
            
            if isinstance(resp, dict) and resp.get("scan_id"):
                self.last_scan_id = resp["scan_id"]
                self.log(f"✓ Upload successful!")
                self.log(f"Scan ID: {self.last_scan_id}")
                self.log(f"Status: {resp.get('status', 'queued')}")
                self.log("\nClick 'Get Result' to retrieve the analysis report.")
                self.set_status("Upload OK")
            else:
                self.log(f"Upload failed: {json.dumps(resp, indent=2)}")
                self.set_status("Upload Failed")
        except Exception as e:
            self.log(f"Upload error: {e}")
            self.set_status("Error")

    def do_poll(self):
        try:
            if not self.last_scan_id:
                messagebox.showinfo("No scan id", "Upload first.")
                return
            self.set_status("Fetching results...")
            url = f"{self.backend}/api/scans/{self.last_scan_id}"
            headers = {"Authorization": f"Bearer {self.api_token}"}
            import requests
            
            # Poll with retry mechanism
            max_retries = 3
            retry_delay = 2  # seconds
            
            for attempt in range(max_retries):
                r = requests.get(url, headers=headers, timeout=60)
                try:
                    j = r.json()
                except Exception:
                    self.log(f"Non-JSON response: {r.status_code} {r.text}")
                    self.set_status("Error")
                    return
                
                # Check if analysis is complete
                if j.get("status") == "done":
                    self.display_formatted_results(j)
                    self.set_status("Done")
                    return
                elif j.get("status") == "pending" or j.get("status") == "processing":
                    if attempt < max_retries - 1:
                        self.log(f"Analysis in progress... (attempt {attempt + 1}/{max_retries})")
                        self.log(f"Waiting {retry_delay} seconds before retry...")
                        self.set_status("Processing...")
                        import time
                        time.sleep(retry_delay)
                    else:
                        self.log("Analysis still in progress. Please click 'Get Result' again in a few seconds.")
                        self.set_status("Pending")
                else:
                    self.log(f"Unknown status: {j.get('status')}")
                    self.set_status("Unknown")
                    return
        except Exception as e:
            self.log(f"Polling error: {e}")
            self.set_status("Error")

    def display_formatted_results(self, result):
        """Display all vulnerabilities with detailed mitigation steps in clear format"""
        ai = result.get("ai", {})
        
        # Extract AI model info
        ai_model = ai.get("ai_model", "Google Gemini (gemini-2.5-flash)")
        
        self.log("\n" + "╔" + "═"*78 + "╗")
        self.log("║" + " "*20 + "VULNERABILITY SCAN REPORT" + " "*33 + "║")
        self.log("╚" + "═"*78 + "╝")
        self.log("")
        
        # Show metadata
        self.log(f"📋 Scan ID:    {result.get('scan_id')}")
        self.log(f"🤖 AI Model:   {ai_model}")
        self.log(f"🖥️  Host:       {ai.get('host', 'unknown')}")
        self.log(f"⏰ Generated:   {ai.get('generated_at', 'N/A')}")
        self.log("")
        
        # Get findings - support both new and old response formats
        analyzed_findings = ai.get("analyzed_findings", [])
        findings = ai.get("prioritized_findings", [])
        all_findings = analyzed_findings if analyzed_findings else findings
        
        if not all_findings:
            self.log("⚠️ No findings returned by server. Check server logs.")
            return
        
        # Calculate summary
        summary = ai.get("summary", {})
        if isinstance(summary, dict):
            critical_count = summary.get("critical_count", 0)
            high_count = summary.get("high_count", 0)
            medium_count = summary.get("medium_count", 0)
            low_count = summary.get("low_count", 0)
        else:
            critical_count = sum(1 for f in all_findings if self._get_severity(f) == "CRITICAL")
            high_count = sum(1 for f in all_findings if self._get_severity(f) == "HIGH")
            medium_count = sum(1 for f in all_findings if self._get_severity(f) == "MEDIUM")
            low_count = sum(1 for f in all_findings if self._get_severity(f) == "LOW")
        
        # Display severity summary
        self.log("╔" + "═"*78 + "╗")
        self.log("║  SEVERITY BREAKDOWN" + " "*58 + "║")
        self.log("╚" + "═"*78 + "╝")
        self.log("")
        self.log(f"  🔴 CRITICAL: {critical_count:3d} issue(s)")
        self.log(f"  🟠 HIGH:     {high_count:3d} issue(s)")
        self.log(f"  🟡 MEDIUM:   {medium_count:3d} issue(s)")
        self.log(f"  🟢 LOW:      {low_count:3d} issue(s)")
        self.log(f"  ─────────────────────")
        self.log(f"  📊 TOTAL:    {len(all_findings):3d} vulnerability(ies) found")
        self.log("")
        
        # Group findings by severity
        by_severity = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
        for f in all_findings:
            sev = self._get_severity(f)
            by_severity[sev].append(f)
        
        # Remove duplicates
        for sev in by_severity:
            seen = set()
            unique = []
            for item in by_severity[sev]:
                uid = item.get('uid')
                if uid not in seen:
                    seen.add(uid)
                    unique.append(item)
            by_severity[sev] = unique
        
        # Display all findings organized by severity
        global_idx = 1
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            findings_list = by_severity[severity]
            if not findings_list:
                continue
            
            severity_symbol = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
            severity_text = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}
            
            self.log("╔" + "═"*78 + "╗")
            self.log(f"║  {severity_symbol[severity]} {severity_text[severity]} SEVERITY ISSUES ({len(findings_list)} found)" + " "*(78-27-len(str(len(findings_list)))) + "║")
            self.log("╚" + "═"*78 + "╝")
            self.log("")
            
            for idx, finding in enumerate(findings_list, 1):
                title = self._get_title(finding)
                description = self._get_description(finding)
                
                # Main vulnerability header
                self.log(f"┌─ [{global_idx}] {severity_symbol[severity]} {title}")
                self.log(f"│")
                self.log(f"│  📝 Description: {description}")
                
                # Get AI analysis
                ai_analysis = self._get_ai_analysis(finding)
                
                if ai_analysis:
                    # CVSS Score
                    cvss = ai_analysis.get("cvss_score", "N/A")
                    severity_rating = ai_analysis.get("severity", "UNKNOWN")
                    self.log(f"│  🎯 Severity: {severity_rating} | CVSS Score: {cvss}")
                    
                    # Recommended Priority
                    priority = ai_analysis.get("recommended_priority", "This Week")
                    priority_emoji = {"Immediate": "🚨", "This Week": "⏱️", "This Month": "📅"}
                    priority_icon = priority_emoji.get(priority, "📌")
                    self.log(f"│  {priority_icon} Priority: {priority}")
                    self.log(f"│")
                    
                    # Mitigation techniques
                    mitigations = ai_analysis.get("mitigation_techniques", [])
                    if mitigations and isinstance(mitigations, list) and mitigations and isinstance(mitigations[0], dict):
                        self.log(f"│  💡 MITIGATION TECHNIQUES:")
                        for step in mitigations:
                            step_num = step.get("step_number", 1)
                            step_title = step.get("title", "Step")
                            what_to_do = step.get("what_to_do", "")
                            why_it_works = step.get("why_it_works", "")
                            est_time = step.get("estimated_time", "N/A")
                            difficulty = step.get("difficulty", "N/A")
                            
                            self.log(f"│")
                            self.log(f"│     ├─ STEP {step_num}: {step_title}")
                            self.log(f"│     │")
                            self.log(f"│     ├─ What to do:")
                            self.log(f"│     │    {what_to_do}")
                            self.log(f"│     │")
                            self.log(f"│     ├─ Why it works:")
                            self.log(f"│     │    {why_it_works}")
                            self.log(f"│     │")
                            
                            # Non-technical steps
                            non_tech = step.get("non_technical_steps", [])
                            if non_tech:
                                self.log(f"│     ├─ 👤 FOR NON-TECHNICAL USERS:")
                                for nt_step in non_tech:
                                    self.log(f"│     │    {nt_step}")
                                self.log(f"│     │")
                            
                            # Technical steps
                            tech = step.get("technical_steps", [])
                            if tech:
                                self.log(f"│     ├─ 👨‍💻 FOR TECHNICAL USERS (PowerShell):")
                                for t_step in tech:
                                    self.log(f"│     │    $ {t_step}")
                                self.log(f"│     │")
                            
                            # Verification
                            verification = step.get("verification", "")
                            if verification:
                                self.log(f"│     ├─ ✓ VERIFICATION:")
                                self.log(f"│     │    {verification}")
                                self.log(f"│     │")
                            
                            # Additional info
                            self.log(f"│     ├─ ⏱️  Estimated Time: {est_time}")
                            self.log(f"│     ├─ 📈 Difficulty: {difficulty}")
                            
                            # Rollback
                            rollback = step.get("rollback_steps", [])
                            if rollback:
                                self.log(f"│     │")
                                self.log(f"│     └─ ↩️  ROLLBACK (if needed):")
                                for rb_step in rollback:
                                    self.log(f"│         {rb_step}")
                    
                    self.log(f"│")
                    
                    # Possible attacks
                    attacks = ai_analysis.get("possible_attacks", [])
                    if attacks and isinstance(attacks, list) and attacks and isinstance(attacks[0], dict):
                        self.log(f"│  ⚠️  POSSIBLE ATTACKS:")
                        for attack in attacks:
                            attack_name = attack.get("attack_name", "Attack")
                            attack_vector = attack.get("attack_vector", "")
                            impact = attack.get("impact", "")
                            likelihood = attack.get("likelihood", "")
                            
                            self.log(f"│")
                            self.log(f"│     • {attack_name}")
                            self.log(f"│       ├─ Vector: {attack_vector}")
                            self.log(f"│       ├─ Impact: {impact}")
                            self.log(f"│       └─ Likelihood: {likelihood}")
                        self.log(f"│")
                    
                    # Compliance references
                    compliance = ai_analysis.get("compliance_references", [])
                    if compliance:
                        self.log(f"│  📋 COMPLIANCE REFERENCES:")
                        for comp in compliance:
                            self.log(f"│     • {comp}")
                        self.log(f"│")
                else:
                    # Fallback for old format
                    mitigations = finding.get('mitigation_techniques', [])
                    if mitigations:
                        self.log(f"│  💡 Mitigation: {', '.join(mitigations[:3])}")
                    attacks = finding.get('possible_attacks', [])
                    if attacks:
                        self.log(f"│  ⚠️  Possible Attacks: {', '.join(attacks[:3])}")
                
                # Close this finding
                if global_idx < len(all_findings):
                    self.log(f"└─" + "─"*76)
                else:
                    self.log(f"└─" + "─"*76)
                self.log("")
                global_idx += 1
        
        # Footer
        self.log("╔" + "═"*78 + "╗")
        self.log(f"║  REPORT SUMMARY" + " "*63 + "║")
        self.log("╚" + "═"*78 + "╝")
        self.log(f"Total Vulnerabilities Analyzed: {len(all_findings)}")
        self.log(f"Critical Issues Requiring Immediate Action: {critical_count}")
        self.log("")
        self.log("🎯 NEXT STEPS:")
        self.log("   1. Address all CRITICAL severity vulnerabilities immediately")
        self.log("   2. Follow the detailed mitigation steps provided above")
        self.log("   3. Test both technical and non-technical solutions")
        self.log("   4. Verify fixes using the provided verification commands")
        self.log("")
        self.log("═"*80)
    
    def _get_severity(self, finding):
        """Extract severity from finding (supports both old and new format)"""
        if "ai_analysis" in finding:
            return finding.get("ai_analysis", {}).get("severity", "MEDIUM")
        return finding.get("severity", "MEDIUM")
    
    def _get_title(self, finding):
        """Extract title from finding (supports both old and new format)"""
        if "original_finding" in finding:
            return finding.get("original_finding", {}).get("title", "Unknown")
        return finding.get("title", "Unknown")
    
    def _get_description(self, finding):
        """Extract description from finding (supports both old and new format)"""
        if "original_finding" in finding:
            return finding.get("original_finding", {}).get("description", "")
        return finding.get("description", "")
    
    def _get_ai_analysis(self, finding):
        """Extract AI analysis from finding"""
        if "ai_analysis" in finding:
            return finding.get("ai_analysis", {})
        return None

def main():
    root = tk.Tk()
    VulnAgentApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()