"""Assemble the same stdlib source as the JavaScript SSH client."""
import json
import pathlib

def helper_source():
    source = pathlib.Path(__file__).parents[1] / 'src'
    names = json.loads((source / 'remote_helpers/manifest.json').read_text(encoding='utf-8'))
    modules = '\n\n'.join((source / 'remote_helpers' / (name + '.py')).read_text(encoding='utf-8') for name in names)
    return (source / 'remote_helper.py').read_text(encoding='utf-8').replace('# BUNDLED_HELPERS', modules)
