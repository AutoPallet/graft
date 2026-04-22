# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "markdown-it-py",
#     "mdit-py-plugins",
# ]
# ///
"""Serve docs/*.md locally, rendered with GFM tables + task-list checkboxes.

Usage:  uv run serve.py [--host 127.0.0.1] [--port 8765]
"""
from __future__ import annotations

import argparse
import http.server
import socketserver
from pathlib import Path

from markdown_it import MarkdownIt
from mdit_py_plugins.tasklists import tasklists_plugin

ROOT = Path(__file__).parent / "docs"

md = (
    MarkdownIt("commonmark", {"html": True, "linkify": True, "typographer": True})
    .enable(["table", "strikethrough"])
    .use(tasklists_plugin, enabled=True)
)

PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>
  :root {{ color-scheme: light dark; --rule: rgba(127,127,127,.3); --soft: rgba(127,127,127,.12); }}
  body {{ font: 16px/1.55 -apple-system, system-ui, "Segoe UI", sans-serif;
          max-width: 52rem; margin: 2rem auto; padding: 0 1.25rem; }}
  h1, h2, h3 {{ line-height: 1.25; }}
  code, pre {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .92em; }}
  pre {{ background: var(--soft); padding: .75rem 1rem; overflow-x: auto; border-radius: 6px; }}
  code {{ background: var(--soft); padding: .1em .3em; border-radius: 3px; }}
  pre code {{ background: none; padding: 0; }}
  table {{ border-collapse: collapse; margin: 1rem 0; }}
  th, td {{ border: 1px solid var(--rule); padding: .35rem .7rem; text-align: left; vertical-align: top; }}
  th {{ background: var(--soft); }}
  a {{ color: #0a6cff; }}
  blockquote {{ border-left: 3px solid var(--rule); margin: 0; padding: .1rem 1rem; opacity: .85; }}
  hr {{ border: none; border-top: 1px solid var(--rule); }}
  ul.contains-task-list {{ list-style: none; padding-left: 1.2em; }}
  li.task-list-item {{ margin-left: -1.2em; }}
  li.task-list-item input {{ margin-right: .45em; }}
  nav.crumbs {{ font-size: .9em; margin-bottom: 1.5rem; opacity: .8; }}
</style>
</head>
<body>
{body}
</body>
</html>
"""


def render_markdown(path: Path) -> str:
    html = md.render(path.read_text(encoding="utf-8"))
    crumbs = '<nav class="crumbs"><a href="/">← index</a></nav>'
    return PAGE.format(title=path.stem, body=crumbs + html)


def render_index() -> str:
    files = sorted(ROOT.glob("*.md"))
    items = "".join(f'<li><a href="/{f.name}">{f.name}</a></li>' for f in files)
    body = f"<h1>docs/</h1><ul>{items}</ul>"
    return PAGE.format(title="docs", body=body)


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ("/", "/index.html"):
            return self._send(200, "text/html; charset=utf-8", render_index())

        rel = self.path.lstrip("/").split("?", 1)[0]
        if not rel.endswith(".md"):
            rel += ".md"

        target = (ROOT / rel).resolve()
        try:
            target.relative_to(ROOT.resolve())
        except ValueError:
            return self._send(403, "text/plain; charset=utf-8", "forbidden")

        if target.is_file():
            return self._send(200, "text/html; charset=utf-8", render_markdown(target))
        return self._send(404, "text/plain; charset=utf-8", f"not found: {self.path}")

    def log_message(self, fmt, *args):
        print(f"{self.address_string()} - {fmt % args}")

    def _send(self, code: int, ctype: str, body: str):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8765)
    args = ap.parse_args()

    if not ROOT.is_dir():
        raise SystemExit(f"no docs directory at {ROOT}")

    with socketserver.TCPServer((args.host, args.port), Handler) as srv:
        print(f"serving {ROOT} at http://{args.host}:{args.port}  (Ctrl-C to stop)")
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            print()


if __name__ == "__main__":
    main()
