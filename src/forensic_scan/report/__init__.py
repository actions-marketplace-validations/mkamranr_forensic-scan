"""Output formats: Markdown for humans, JSON for tools, SARIF for CI."""

from .json_ import render_json
from .markdown import render_markdown
from .sarif import render_sarif

RENDERERS = {"markdown": render_markdown, "json": render_json, "sarif": render_sarif}

__all__ = ["render_json", "render_markdown", "render_sarif", "RENDERERS"]
