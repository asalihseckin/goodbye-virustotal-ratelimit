#!/usr/bin/env python3
"""Quick sanity check: verify API keys from api_keys.env are valid and reachable."""
import urllib.request
import json
import sys

def load_keys(filepath='api_keys.env'):
    keys = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                key = line.strip()
                if key and len(key) > 20:
                    keys.append(key)
    except FileNotFoundError:
        print(f"[ERROR] {filepath} not found")
        sys.exit(1)
    return keys

def test_key(label, key, url):
    print(f"\n[TEST] {label}: {key[:16]}...")
    try:
        req = urllib.request.Request(url, headers={"x-apikey": key})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode('utf-8'))
            print(f"  [OK] Working (HTTP {r.status}) - scanned: {data['data']['id']}")
            return True
    except urllib.error.HTTPError as e:
        reason = {429: "Rate Limited", 403: "Forbidden", 401: "Invalid key"}.get(e.code, f"HTTP {e.code}")
        print(f"  [ERROR] HTTP {e.code} - {reason}")
        return False
    except Exception as e:
        print(f"  [ERROR] {e}")
        return False

def main():
    keys = load_keys()
    if not keys:
        print("[ERROR] No keys found in api_keys.env")
        sys.exit(1)

    url = "https://www.virustotal.com/api/v3/domains/google.com"

    # Test only the first and last key by default (quick spot-check, not a full audit)
    to_test = [keys[0]] if len(keys) == 1 else [keys[0], keys[-1]]

    print("="*70)
    print(f"API KEY SPOT-CHECK ({len(keys)} keys loaded, testing {len(to_test)})")
    print("="*70)

    results = []
    for i, key in enumerate(to_test):
        label = f"Key #{i+1}"
        results.append(test_key(label, key, url))

    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    if all(results):
        print("All tested keys are working.")
    elif any(results):
        print("Some keys failed - check individual results above.")
    else:
        print("All tested keys failed - check network/IP status.")

if __name__ == "__main__":
    main()
