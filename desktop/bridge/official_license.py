"""Use the installed vendor checker; never activate, generate or copy a key."""
import json
import os
import pathlib
import sys

sys.dont_write_bytecode = True

def main():
    root = pathlib.Path(sys.argv[1]).resolve()
    operation = sys.argv[2]
    if operation not in ('status', 'servers'):
        raise ValueError('Unsupported operation')
    sys.path.insert(0, str(root))
    import license_core
    status = license_core.get_current_license_status()
    result = {'license': {k: status[k] for k in ('active', 'reason', 'plan_name', 'days_left', 'expires_at') if k in status}}
    if operation == 'servers':
        if not status.get('active'):
            result['error'] = 'license_inactive'
            return result
        user_cache = pathlib.Path(os.environ.get('APPDATA') or pathlib.Path.home()) / 'InternetAzad369' / 'v2ray_configs_cache.json'
        for cache in (user_cache, root / 'v2ray_configs_cache.json'):
            if not cache.is_file() or cache.stat().st_size > 8 * 1024 * 1024:
                continue
            try:
                items = json.loads(cache.read_text(encoding='utf-8-sig'))
                if not isinstance(items, list):
                    continue
                configs = [{'remarks': str(item.get('name') or 'Official server'), 'outbounds': [item['outbound']]} for item in items[:10000] if isinstance(item, dict) and isinstance(item.get('outbound'), dict)]
                if configs:
                    result['configs'] = configs
                    result['cached_at'] = int(cache.stat().st_mtime)
                    return result
            except (ValueError, OSError, TypeError):
                continue
        result['error'] = 'no_cached_servers'
    return result

if __name__ == '__main__':
    try:
        result = main()
    except Exception:
        result = {'error': 'official_checker_failed'}
    # ASCII transport is intentional: the bundled Python console uses cp1252.
    print(json.dumps(result, ensure_ascii=True))
