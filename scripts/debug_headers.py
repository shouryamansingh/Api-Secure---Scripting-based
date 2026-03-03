"""
Debug script: fetch a URL and print response headers.
Run from Main Project: py scripts/debug_headers.py [URL]
Example: py scripts/debug_headers.py https://mietjmu.in
"""
import sys
import os

# Allow importing from parent
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import scanner as _scanner_mod
    print("Loaded scanner from:", getattr(_scanner_mod, "__file__", "?"))
    fetch_url = _scanner_mod.fetch_url
    REQUIRED_HEADERS = _scanner_mod.REQUIRED_HEADERS
    get_header = _scanner_mod.get_header
    _normalize_headers = _scanner_mod._normalize_headers
except ImportError:
    from importlib.util import spec_from_file_location, module_from_spec
    spec = spec_from_file_location("scanner", os.path.join(os.path.dirname(os.path.dirname(__file__)), "scanner.py"))
    scanner = module_from_spec(spec)
    spec.loader.exec_module(scanner)
    fetch_url = scanner.fetch_url
    REQUIRED_HEADERS = scanner.REQUIRED_HEADERS
    get_header = scanner.get_header
    _normalize_headers = scanner._normalize_headers

def main():
    import requests
    url = (sys.argv[1] if len(sys.argv) > 1 else "https://mietjmu.in").strip()
    print(f"Fetching: {url}")
    print("Raw request (with redirects):")
    try:
        r = requests.get(url, allow_redirects=True, timeout=15, verify=False, headers={"User-Agent": "Mozilla/5.0"})
        print(f"  Status: {r.status_code}, URL: {r.url}")
        print(f"  type(resp.headers): {type(r.headers)}")
        print(f"  len(resp.headers): {len(r.headers)}")
        print(f"  list(resp.headers): {list(r.headers)[:20]}")
        if r.headers:
            for k in list(r.headers)[:15]:
                print(f"    {k!r}: {r.headers[k][:50]!r}")
        # Test _normalize_headers on this response
        norm = _normalize_headers(r.headers)
        print(f"  _normalize_headers(r.headers) -> {len(norm)} keys: {list(norm.keys())}")
    except Exception as e:
        print(f"  Error: {e}")
        import traceback
        traceback.print_exc()
    print("\nWith redirects (final response):")
    try:
        headers_r, _, status_r = fetch_url(url, follow_redirects=True)
        print(f"  Status: {status_r}")
        print(f"  Total header keys: {len(headers_r)}")
        print("  All received keys (lowercase):", list(headers_r.keys())[:30])
        for name in REQUIRED_HEADERS:
            val = get_header(headers_r, name)
            print(f"  {name}: {'Present = ' + repr(val)[:60] if val else 'MISSING'}")
    except Exception as e:
        print(f"  Error: {e}")
    print("\nWithout redirects (first response):")
    try:
        headers_nr, _, status_nr = fetch_url(url, follow_redirects=False)
        print(f"  Status: {status_nr}")
        print(f"  Total header keys: {len(headers_nr)}")
        print("  All received keys (lowercase):", list(headers_nr.keys())[:30])
        for name in REQUIRED_HEADERS:
            val = get_header(headers_nr, name)
            print(f"  {name}: {'Present = ' + repr(val)[:60] if val else 'MISSING'}")
    except Exception as e:
        print(f"  Error: {e}")

if __name__ == "__main__":
    main()
