import os, json, time
import google.generativeai as genai

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

if not GEMINI_API_KEY:
    raise ValueError("GEMINI_API_KEY environment variable is required!")

# --- Model Configuration with System Instruction ---
# --- ENHANCED System Instruction ---
CYBER_SECURITY_SYSTEM_INSTRUCTION = (
    "You are a highly-experienced Cybersecurity Analyst specializing in Windows vulnerability remediation. "
    "Your role is to provide CLEAR, STEP-BY-STEP, ACTIONABLE mitigation techniques that both technical and non-technical users can follow. "
    "For each vulnerability:\n"
    "1. Provide severity (CRITICAL/HIGH/MEDIUM/LOW) based on CVSS and exploitability\n"
    "2. Provide 5-7 DETAILED mitigation steps (not just bullet points). Each step must include:\n"
    "   - WHAT to do (clear action)\n"
    "   - HOW to do it (step-by-step with commands/GUI paths for Windows)\n"
    "   - WHY it works (brief explanation)\n"
    "   - For technical users: PowerShell/CMD commands\n"
    "   - For non-technical users: GUI navigation steps\n"
    "3. List realistic attack vectors with impact\n"
    "4. Provide compliance references (if applicable)\n"
    "5. Include rollback/recovery steps in case something goes wrong\n"
    "Output ONLY valid JSON, no explanations."
)

genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel(
    'gemini-2.5-flash',
    system_instruction=CYBER_SECURITY_SYSTEM_INSTRUCTION
)
print(f"✅ Loaded Google Gemini API (gemini-2.5-flash) with specialized system instruction.")
# ----------------------------------------------------

def calculate_severity_with_ai(finding):
    """
    Use Google Gemini to determine severity with detailed, actionable mitigation steps.
    Returns: Detailed JSON with step-by-step remediation for technical and non-technical users.
    """
    title = finding.get("title", "")
    desc = finding.get("description", "")
    ftype = finding.get("type", "")
    service_type = finding.get("service_type", "Unknown")
    process_name = finding.get("process_name", "Unknown")
    port = finding.get("port", "N/A")
    protocol = finding.get("protocol", "N/A")
    
    prompt = f"""You are a Windows cybersecurity expert. Analyze this vulnerability and provide CLEAR, DETAILED, ACTIONABLE remediation steps.

VULNERABILITY DETAILS:
- Type: {ftype}
- Title: {title}
- Description: {desc}
- Service/Component: {service_type}
- Process Name: {process_name}
- Port/Protocol: {port} / {protocol}

CRITICAL REQUIREMENTS:
1. Assign severity (CRITICAL/HIGH/MEDIUM/LOW) based on exploitability and impact
2. Calculate CVSS score (0-10 float)
3. Provide 2-4 detailed mitigation steps (not generic, specific to this vulnerability)
4. For EACH mitigation step, include:
   - Step number (1, 2, 3...)
   - Clear title
   - "what_to_do": Specific action (1 sentence)
   - "why_it_works": 2-3 sentence technical explanation
   - "non_technical_steps": 5-8 detailed GUI navigation steps for non-technical users (step 1, step 2, etc.)
   - "technical_steps": 3-4 PowerShell commands with expected output
   - "estimated_time": How long it takes (e.g., "5 minutes", "15 minutes")
   - "difficulty": "Easy", "Medium", or "Hard"
   - "rollback_steps": How to undo if something goes wrong (list of commands)
   - "verification": How to confirm the fix worked

5. List 2-3 realistic attack vectors with:
   - "attack_name": Specific exploit name
   - "attack_vector": How attackers exploit this
   - "impact": Consequences if exploited
   - "likelihood": "VERY HIGH", "HIGH", "MEDIUM", "LOW"

6. Set "recommended_priority": "Immediate", "This Week", or "This Month"
7. Include relevant compliance references (CIS Controls, NIST CSF, PCI-DSS, etc.)

RESPOND WITH ONLY THIS JSON (no markdown, no explanation):
{{
    "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "cvss_score": <float between 0 and 10>,
    "mitigation_techniques": [
        {{
            "step_number": 1,
            "title": "Clear, specific mitigation step title",
            "what_to_do": "Specific action for this vulnerability",
            "why_it_works": "2-3 sentences explaining why this fixes the issue",
            "non_technical_steps": [
                "1. First action for non-technical users",
                "2. Second action with clear navigation",
                "3. Continue with numbered steps",
                "4. Include menu paths and button names",
                "5. Include confirmation steps"
            ],
            "technical_steps": [
                "powershell command or first action",
                "second command or expected output",
                "verification command to confirm success"
            ],
            "estimated_time": "X minutes",
            "difficulty": "Easy|Medium|Hard",
            "rollback_steps": ["Command to undo step 1", "Command to undo step 2"],
            "verification": "How to confirm the mitigation is successful"
        }}
    ],
    "possible_attacks": [
        {{
            "attack_name": "Specific attack name",
            "attack_vector": "Specific method of exploitation",
            "impact": "Specific consequences",
            "likelihood": "VERY HIGH|HIGH|MEDIUM|LOW"
        }}
    ],
    "recommended_priority": "Immediate|This Week|This Month",
    "compliance_references": ["Standard or framework reference"],
    "additional_notes": "Any important context"
}}"""

    try:
        response = model.generate_content(prompt)
        response_text = response.text.strip()
        
        # Handle markdown code blocks if present
        if "```" in response_text:
            parts = response_text.split("```")
            response_text = parts[1]
            if response_text.startswith("json"):
                response_text = response_text[4:]
        
        # Clean up any extra whitespace
        response_text = response_text.strip()
        result = json.loads(response_text)
        
        # Validate that mitigation_techniques is present and populated
        if not result.get("mitigation_techniques") or len(result.get("mitigation_techniques", [])) == 0:
            print(f"    ⚠ Warning: Empty mitigation_techniques returned by AI")
            print(f"    Raw response: {response_text[:200]}...")
        
        return result
        
    except Exception as e:
        print(f"    ⚠ Error parsing AI response: {e}")
        print(f"    Response text: {response.text[:500] if 'response' in locals() else 'No response'}")
        return {
            "severity": "MEDIUM",
            "cvss_score": 5.5,
            "error": str(e),
            "mitigation_techniques": [
                {
                    "step_number": 1,
                    "title": "Review and address this vulnerability",
                    "what_to_do": "Manually investigate this finding and apply appropriate security controls",
                    "why_it_works": "Context-specific security measures reduce attack surface",
                    "non_technical_steps": [
                        "1. Research this vulnerability type online",
                        "2. Consult with IT security team",
                        "3. Apply vendor-recommended patches",
                        "4. Document the remediation steps taken"
                    ],
                    "technical_steps": [
                        "Review security advisories for this component",
                        "Apply latest security patches",
                        "Verify fix with security scanning tools"
                    ],
                    "estimated_time": "30 minutes",
                    "difficulty": "Medium",
                    "rollback_steps": ["Document original configuration before changes"],
                    "verification": "Re-scan to confirm vulnerability is resolved"
                }
            ],
            "possible_attacks": [
                {
                    "attack_name": "Exploitation of vulnerability",
                    "attack_vector": "Attackers may exploit this weakness",
                    "impact": "Potential unauthorized access or data exposure",
                    "likelihood": "MEDIUM"
                }
            ],
            "recommended_priority": "This Week",
            "compliance_references": ["NIST CSF", "CIS Controls"]
        }


def analyze_agg(agg):
    """
    Analyze aggregated vulnerability report using Gemini AI with detailed mitigation steps.
    Returns comprehensive analysis with step-by-step remediation for both technical and non-technical users.
    """
    findings = agg.get("findings", [])
    
    # Remove duplicate UIDs to reduce processing
    unique_findings = {}
    for f in findings:
        uid = f.get("uid")
        if uid not in unique_findings:
            unique_findings[uid] = f
    
    findings = list(unique_findings.values())
    print(f"Processing {len(findings)} unique vulnerabilities with Gemini AI...")
    
    analyzed_findings = []
    
    # Process each finding with detailed AI analysis
    for idx, f in enumerate(findings, 1):
        title = f.get("title", "Unknown")
        print(f"  [{idx}/{len(findings)}] Analyzing: {title}")
        
        try:
            # Get detailed analysis from Gemini
            ai_result = calculate_severity_with_ai(f)
            
            # Check if AI returned valid mitigation techniques
            mitigations = ai_result.get("mitigation_techniques", [])
            if mitigations:
                print(f"    ✓ Received {len(mitigations)} mitigation step(s)")
            else:
                print(f"    ⚠ No mitigation techniques in response (using fallback)")
            
            # Build comprehensive finding object
            analyzed_findings.append({
                "uid": f.get("uid", "unknown"),
                "original_finding": {
                    "type": f.get("type", "unknown"),
                    "title": title,
                    "description": f.get("description", ""),
                    "service": f.get("service_type", "Unknown"),
                    "process": f.get("process_name", "Unknown"),
                    "port": f.get("port", "N/A"),
                    "protocol": f.get("protocol", "N/A")
                },
                "ai_analysis": ai_result
            })
            
        except Exception as e:
            print(f"    ⚠ Error analyzing {title}: {e}")
            # Fallback analysis with mitigation techniques
            analyzed_findings.append({
                "uid": f.get("uid", "unknown"),
                "original_finding": {
                    "type": f.get("type", "unknown"),
                    "title": title,
                    "description": f.get("description", ""),
                    "service": f.get("service_type", "Unknown"),
                    "process": f.get("process_name", "Unknown"),
                    "port": f.get("port", "N/A"),
                    "protocol": f.get("protocol", "N/A")
                },
                "ai_analysis": {
                    "severity": "MEDIUM",
                    "cvss_score": 5.5,
                    "error": str(e),
                    "mitigation_techniques": [
                        {
                            "step_number": 1,
                            "title": "Investigate and remediate this vulnerability",
                            "what_to_do": "Review security best practices for this component",
                            "why_it_works": "Following security standards reduces risk",
                            "non_technical_steps": [
                                "1. Consult with IT security team",
                                "2. Research vendor security advisories",
                                "3. Apply recommended patches or configurations"
                            ],
                            "technical_steps": [
                                "Review security documentation",
                                "Apply security hardening measures"
                            ],
                            "estimated_time": "15 minutes",
                            "difficulty": "Medium",
                            "rollback_steps": ["Save configuration before changes"],
                            "verification": "Re-scan system to verify fix"
                        }
                    ],
                    "possible_attacks": [
                        {
                            "attack_name": "Potential exploitation",
                            "attack_vector": "Varies based on vulnerability type",
                            "impact": "Could lead to unauthorized access",
                            "likelihood": "MEDIUM"
                        }
                    ],
                    "recommended_priority": "This Week"
                }
            })
    
    # Sort by severity priority
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    analyzed_findings.sort(
        key=lambda x: severity_order.get(
            x.get("ai_analysis", {}).get("severity", "LOW"), 4
        )
    )
    
    # Calculate summary statistics
    summary = {
        "critical_count": sum(1 for a in analyzed_findings if a.get("ai_analysis", {}).get("severity") == "CRITICAL"),
        "high_count": sum(1 for a in analyzed_findings if a.get("ai_analysis", {}).get("severity") == "HIGH"),
        "medium_count": sum(1 for a in analyzed_findings if a.get("ai_analysis", {}).get("severity") == "MEDIUM"),
        "low_count": sum(1 for a in analyzed_findings if a.get("ai_analysis", {}).get("severity") == "LOW")
    }
    
    print(f"✅ Analysis complete: {len(analyzed_findings)} vulnerabilities analyzed")
    print(f"   CRITICAL: {summary['critical_count']} | HIGH: {summary['high_count']} | MEDIUM: {summary['medium_count']} | LOW: {summary['low_count']}")
    
    result = {
        "scan_id": agg.get("scan_id", "unknown"),
        "generated_at": agg.get("generated_at", ""),
        "host": agg.get("host", "unknown"),
        "total_findings": len(findings),
        "summary": summary,
        "analyzed_findings": analyzed_findings,
        "ai_model": "Google Gemini (gemini-2.5-flash)",
        "prompt_type": "Detailed Remediation with Technical & Non-Technical Steps"
    }
    return result