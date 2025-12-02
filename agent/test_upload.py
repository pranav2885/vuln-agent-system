#!/usr/bin/env python
"""Quick test script for uploading to server"""
import sys
from uploader import upload_aggregated

print("Uploading agg.json to server...")
try:
    result = upload_aggregated('agg.json')
    print("\n=== Upload Result ===")
    import json
    print(json.dumps(result, indent=2))
    
    if result.get("scan_id"):
        print(f"\n✓ Success! Scan ID: {result['scan_id']}")
        print("\nRun this to get results:")
        print(f"  python -c \"from uploader import BACKEND, API_TOKEN; import requests; r=requests.get('{result.get('scan_id')}', headers={{'Authorization': f'Bearer {{API_TOKEN}}'}}, timeout=10); print(r.json())\"")
    else:
        print("\n✗ Upload failed")
        sys.exit(1)
except Exception as e:
    print(f"\n✗ Error: {e}")
    sys.exit(1)
