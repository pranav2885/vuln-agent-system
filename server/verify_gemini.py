"""
Verification script to prove Google Gemini AI integration
"""
import os
from dotenv import load_dotenv

load_dotenv()

print("="*70)
print("  GOOGLE GEMINI AI MODEL VERIFICATION")
print("="*70)

USE_REAL_MODEL = os.getenv("USE_REAL_MODEL", "false").lower() == "true"
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

print(f"\n1. ENVIRONMENT CONFIGURATION:")
print("-" * 70)
print(f"USE_REAL_MODEL: {USE_REAL_MODEL}")
print(f"GEMINI_API_KEY: {'✅ Set (' + GEMINI_API_KEY[:20] + '...)' if GEMINI_API_KEY else '❌ Not set'}")

print(f"\n2. CHECKING DEPENDENCIES:")
print("-" * 70)
try:
    import google.generativeai as genai
    print(f"✅ google-generativeai: Installed")
    
    if USE_REAL_MODEL and GEMINI_API_KEY:
        print(f"\n3. TESTING GEMINI API CONNECTION:")
        print("-" * 70)
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel('gemini-2.5-flash')
        
        # Test with a sample vulnerability
        test_prompt = """Analyze this vulnerability and respond with ONE word only: CRITICAL, HIGH, MEDIUM, or LOW

Vulnerability: Open port 445 (SMB file sharing) exposed to network
Service: SMB
Process: System"""
        
        print("Sending test request to Gemini...")
        response = model.generate_content(test_prompt)
        severity = response.text.strip()
        
        print(f"✅ API Connection: Success")
        print(f"✅ Model: gemini-2.5-flash")
        print(f"✅ Test Response: {severity}")
        
        print(f"\n4. LIVE VULNERABILITY ANALYSIS TESTS:")
        print("-" * 70)
        test_cases = [
            {
                "desc": "Open port 3389 (Remote Desktop) exposed to internet",
                "type": "open_port",
                "service": "RDP",
                "process": "System"
            },
            {
                "desc": "Missing critical security patch KB5034441",
                "type": "missing_patch",
                "service": "N/A",
                "process": "N/A"
            },
            {
                "desc": "Open port 50923 (Spotify) on localhost",
                "type": "open_port",
                "service": "Unknown",
                "process": "Spotify.exe"
            }
        ]
        
        for i, test in enumerate(test_cases, 1):
            prompt = f"""Analyze this vulnerability and respond ONLY: CRITICAL, HIGH, MEDIUM, or LOW

Vulnerability Type: {test['type']}
Description: {test['desc']}
Service: {test['service']}
Process: {test['process']}"""
            
            result = model.generate_content(prompt)
            severity = result.text.strip()
            
            print(f"\nTest {i}: {test['desc']}")
            print(f"  → Gemini Severity: {severity}")
        
        print(f"\n" + "="*70)
        print("✅ GOOGLE GEMINI AI MODEL IS ACTIVE AND WORKING!")
        print("="*70)
        print(f"\nModel Details:")
        print(f"  • Provider: Google AI")
        print(f"  • Model: gemini-2.5-flash")
        print(f"  • Type: Large Language Model (LLM)")
        print(f"  • Task: Cybersecurity vulnerability assessment")
        print(f"  • API Key: Active")
        
    else:
        print(f"\n❌ Gemini not configured")
        if not USE_REAL_MODEL:
            print(f"   Set USE_REAL_MODEL=true in .env")
        if not GEMINI_API_KEY:
            print(f"   Set GEMINI_API_KEY in .env")
        
except ImportError:
    print(f"❌ google-generativeai: Not installed")
    print(f"\nRun: pip install google-generativeai")
except Exception as e:
    print(f"❌ Error: {e}")

print()
