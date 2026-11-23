#!/usr/bin/env python3

# Strip remote URLs from assets.json, so that uBO makes no outgoing
# connections until the browser configures assetsBootstrapLocation,
# i.e. until the user has consented to it.

import json
import re
import sys

re_remote = re.compile(r'^[a-z-]+://')

def rename_key(d, old, new):
    return {(new if k == old else k): v for k, v in d.items()}

for path in sys.argv[1:]:
    with open(path, encoding='utf-8') as f:
        assets = json.load(f)

    for name, entry in assets.items():
        if entry.get('off'):
            continue

        urls = entry.get('contentURL', [])
        if isinstance(urls, str):
            urls = [urls]
        entry['contentURL'] = [u for u in urls if not re_remote.match(u)]

        entry = rename_key(entry, 'cdnURLs', '^cdnURLs')
        entry = rename_key(entry, 'patchURLs', '^patchURLs')
        assets[name] = entry

    with open(path, 'w', encoding='utf-8') as f:
        json.dump(assets, f, indent='\t', ensure_ascii=False)
        f.write('\n')
