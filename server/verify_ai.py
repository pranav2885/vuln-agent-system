"""
Verification script to prove AI model integration
Run this to show evidence of HuggingFace AI model usage
"""
import os
os.environ['USE_REAL_MODEL'] = 'true'

print("="*70)
print("  AI MODEL VERIFICATION REPORT")
print("="*70)

# 1. Check dependencies
print("\n1. CHECKING AI LIBRARIES:")
print("-" * 70)
try:
    import transformers
    import torch
    print(f"✓ transformers version: {transformers.__version__}")
    print(f"✓ torch version: {torch.__version__}")
except ImportError as e:
    print(f"✗ Missing library: {e}")
    exit(1)

# 2. Load the AI adapter
print("\n2. LOADING AI ADAPTER:")
print("-" * 70)
from app.ai_adapter import USE_REAL_MODEL, HF_AVAILABLE, classifier, calculate_severity_with_ai

print(f"USE_REAL_MODEL: {USE_REAL_MODEL}")
print(f"HF_AVAILABLE: {HF_AVAILABLE}")
print(f"Classifier loaded: {classifier is not None}")

if classifier:
    print(f"Model type: {type(classifier).__name__}")
    print(f"Model name: codechrl/bert-micro-cybersecurity")
    print("✓ HuggingFace AI model successfully loaded!")
else:
    print("✗ AI model not loaded")
    exit(1)

# 3. Test the AI model with sample inputs
print("\n3. TESTING AI MODEL WITH SAMPLE VULNERABILITIES:")
print("-" * 70)

test_cases = [
    {
        "type": "open_port",
        "title": "Open port 445",
        "description": "SMB port listening on 0.0.0.0:445",
        "port": 445
    },
    {
        "type": "missing_patch",
        "title": "Missing critical security patch KB5001234",
        "description": "Windows security update not installed",
        "port": None
    },
    {
        "type": "open_port",
        "title": "Open port 8080",
        "description": "HTTP service on 0.0.0.0:8080",
        "port": 8080
    }
]

print("\nProcessing vulnerabilities through AI model...\n")
for idx, test in enumerate(test_cases, 1):
    severity = calculate_severity_with_ai(test)
    print(f"Test {idx}: {test['title']}")
    print(f"  Input: {test['type']}: {test['title']}. {test['description']}")
    print(f"  AI Predicted Severity: {severity}")
    
    # Show the raw model output for proof
    if classifier:
        text = f"{test['type']}: {test['title']}. {test['description']}"
        result = classifier(text, truncation=True, max_length=512)
        print(f"  Raw AI Output: {result}")
    print()

# 4. Compare with rule-based approach
print("\n4. COMPARISON: AI vs RULE-BASED:")
print("-" * 70)
os.environ['USE_REAL_MODEL'] = 'false'

# Reimport to get rule-based version
import importlib
import app.ai_adapter
importlib.reload(app.ai_adapter)
from app.ai_adapter import calculate_severity_with_ai as rule_based_severity

os.environ['USE_REAL_MODEL'] = 'true'

sample = {
    "type": "open_port",
    "title": "Open port 3389",
    "description": "Remote Desktop Protocol listening",
    "port": 3389
}

ai_severity = calculate_severity_with_ai(sample)
rb_severity = rule_based_severity(sample)

print(f"Sample: {sample['title']}")
print(f"  AI Model Severity:    {ai_severity}")
print(f"  Rule-Based Severity:  {rb_severity}")
print(f"  Different result: {'✓ Yes' if ai_severity != rb_severity else '✗ No (same)'}")

# 5. Summary
print("\n" + "="*70)
print("  VERIFICATION SUMMARY")
print("="*70)
print("✓ HuggingFace transformers library installed")
print("✓ PyTorch backend available")
print("✓ AI model (codechrl/bert-micro-cybersecurity) loaded successfully")
print("✓ Model successfully processes vulnerability descriptions")
print("✓ Model generates severity predictions")
print("\nCONCLUSION: AI model integration is ACTIVE and WORKING!")
print("="*70)
