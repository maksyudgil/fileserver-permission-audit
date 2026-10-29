"""Build the single-file viewer: inlines JSZip into viewer/src.html -> FS-Audit-Viewer.html.
Usage: python viewer/build.py path/to/jszip.min.js
"""
import sys, pathlib
root = pathlib.Path(__file__).resolve().parent
src = (root / 'src.html').read_text(encoding='utf-8')
js = pathlib.Path(sys.argv[1]).read_text(encoding='utf-8')
assert '</script' not in js.lower()
out = src.replace('/*JSZIP*/', js, 1)
(root.parent / 'FS-Audit-Viewer.html').write_text(out, encoding='utf-8')
print('written', len(out), 'bytes')
