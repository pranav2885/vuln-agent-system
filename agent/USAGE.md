# Vulnerability Scanner - Quick Usage Guide

## 🚀 Quick Start

### Option 1: GUI (Easiest)
```powershell
cd d:\urop\vuln-agent-system\agent
python ui.py
```
Then click: **Scan Now** → **Upload Report** → **Get Result**

### Option 2: Command Line
```powershell
cd d:\urop\vuln-agent-system\agent

# Step 1: Scan your system
python collector.py

# Step 2: Normalize findings
python normalize.py

# Step 3: Upload to server
python test_upload.py

# Step 4: Get formatted results (copy the scan_id from step 3)
python get_results.py <scan_id>
```

## 📊 Understanding the Output

### Model Information
The report clearly shows which analysis method was used:

- **🤖 AI Model: HuggingFace** - Using machine learning to classify severity
  - Model: `codechrl/bert-micro-cybersecurity`
  - Smarter, context-aware severity ratings
  
- **📋 Rule-based** - Using hardcoded logic
  - Simple if/then rules
  - Faster but less intelligent

### Severity Levels

| Symbol | Level | Meaning | Action Needed |
|--------|-------|---------|---------------|
| 🔴 | **CRITICAL** | Severe security risk | Fix immediately |
| 🟠 | **HIGH** | Significant vulnerability | Fix soon |
| 🟡 | **MEDIUM** | Moderate issue | Fix when possible |
| 🟢 | **LOW** | Minor concern | Monitor or review |

### Report Sections

1. **Vulnerability Scan Report**
   - Shows which AI model/method was used
   - Scan ID for reference
   - Total findings summary

2. **Severity Breakdown**
   - Quick overview of issue counts by severity
   - Helps prioritize your work

3. **Top Priority Issues**
   - The most important 5 issues to fix
   - Plain language explanation of what to do
   - Shows severity level for each

4. **Detailed Findings**
   - Full list organized by severity
   - Each issue includes:
     - **What it is**: The vulnerability found
     - **What to do**: Step-by-step fix instructions
     - **Check with**: PowerShell command to verify

## 🔍 Example Output Explained

```
🟠 HIGH - Missing patch KB999999
   → What to do: Install the missing patch mentioned (demo).
   → Check with: Get-HotFix | Where-Object {$_.HotFixID -eq 'KB999999'}
```

**Translation:** Your Windows system is missing an important security update (patch KB999999). You should install this patch from Windows Update, then restart your computer. After restarting, run the PowerShell command shown to verify it's installed.

```
🟢 LOW - Open port 445
   → What to do: Review service listening on port 445. If not needed, stop the service.
   → Check with: netstat -ano | findstr 445
```

**Translation:** Your computer has port 445 open and listening for connections. This port is used for file sharing (SMB). If you're not actively sharing files on your network, you might want to close it. Run the command to see what program is using it.

## 🎯 Common Issues Explained

### Missing Patches
- **What it means**: Your Windows is missing security updates
- **Why it matters**: Hackers can exploit unpatched systems
- **How to fix**: Run Windows Update and install all patches

### Open Ports
- **What it means**: Your computer is accepting connections on certain network ports
- **Why it matters**: Each open port is a potential entry point for attacks
- **How to fix**: 
  - Identify what service uses the port
  - If not needed, stop the service or block with firewall
  - Common risky ports: 21, 22, 23, 445, 3389

## 💡 Tips

- Run scans regularly (weekly recommended)
- Fix HIGH and CRITICAL issues first
- Keep scan IDs for historical comparison
- Use `--json` flag to see raw data if needed

## 🔧 View Raw JSON
If you need the complete technical details:
```powershell
python get_results.py <scan_id> --json
```
