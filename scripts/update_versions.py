#!/usr/bin/env python3
import asyncio
import os
import sys
import json
from typing import List

# Allow importing package from src/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from zap_rag_security_agent.data.version_database import get_version_database  # noqa: E402


async def main(argv: List[str]) -> int:
    """
    Update latest versions using public registries and save to cache.

    Usage:
      - No args: updates all known technologies
      - With args: updates only the specified technologies (space-separated)
    """
    db = get_version_database()

    technologies = argv[1:] if len(argv) > 1 else None

    if technologies:
        print("[*] Updating specified technologies...")
        updated = await db.update_versions(technologies)
        if not updated:
            print("[!] No updates fetched (possibly rate-limited or offline). Using cached/default versions.")
        current = {tech: db.get_version_info(tech) for tech in technologies}
        print("[INFO] Version info (post-update):")
        print(json.dumps(current, indent=2, sort_keys=True))
        try:
            cache_path = db.cache_path  # type: ignore[attr-defined]
            print(f"[INFO] Cache written to: {cache_path}")
        except Exception:
            pass
    else:
        # Avoid long-running global network update by default.
        # Show cached versions snapshot and instruct passing tech names to update.
        print("[*] No technologies specified. Showing cached versions snapshot (no network calls).")
        try:
            all_versions = getattr(db, 'versions', {})
            keys = sorted(all_versions.keys())
            snapshot = {k: all_versions.get(k) for k in keys[:25]}
            print("[INFO] Current version snapshot (first 25):")
            print(json.dumps(snapshot, indent=2, sort_keys=True))
            try:
                cache_path = db.cache_path  # type: ignore[attr-defined]
                print(f"[INFO] Cache file: {cache_path}")
            except Exception:
                pass
            print("[HINT] To refresh, pass technology names, e.g.: python scripts/update_versions.py jquery php nginx")
        except Exception as e:
            print(f"[ERROR] Could not read cached versions: {e}")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(main(sys.argv)))
    except KeyboardInterrupt:
        raise SystemExit(130)


