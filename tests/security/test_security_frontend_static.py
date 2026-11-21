"""Static checks for the Next.js console (``frontend/``).

Telemetry rendered by the console (log lines, HTTP paths, commit messages,
Kubernetes fields, AI summaries) is attacker-controlled. React escapes text by
default; these checks keep the escape hatches closed and keep credentials out
of browser code (AGENTS.md invariants 2 and 5):

* no ``dangerouslySetInnerHTML`` (unless marked ``extorq: html-reviewed <reason>``
  after review: only for developer-controlled content such as chart CSS),
  ``innerHTML``/``outerHTML`` assignment,
  ``insertAdjacentHTML``, ``document.write``, ``eval``/``new Function``;
* no raw-HTML markdown rendering (``rehype-raw``, ``allowDangerousHtml``);
* no secret-looking ``NEXT_PUBLIC_*`` variables (they are inlined into bundles);
* client components never reference secret-looking ``process.env`` names;
* tokens are never written to ``localStorage``/``sessionStorage``.

Skipped until ``frontend/`` contains source files.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from security_helpers import REPO_ROOT, format_findings, iter_files, read_text, rel

SOURCE_SUFFIXES = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mdx")

FORBIDDEN = {
    "dangerouslySetInnerHTML": re.compile(r"dangerouslySetInnerHTML"),
    "innerHTML/outerHTML assignment": re.compile(r"\.(inner|outer)HTML\s*=(?!=)"),
    "insertAdjacentHTML": re.compile(r"insertAdjacentHTML\s*\("),
    "document.write": re.compile(r"document\.write(ln)?\s*\("),
    "eval()": re.compile(r"(?<![\w.$])eval\s*\("),
    "new Function()": re.compile(r"new\s+Function\s*\("),
    "raw HTML markdown (rehype-raw)": re.compile(r"rehype-raw"),
    "raw HTML markdown (allowDangerousHtml)": re.compile(r"allowDangerousHtml"),
    "secret-looking NEXT_PUBLIC_ variable": re.compile(
        r"NEXT_PUBLIC_[A-Z0-9_]*(TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|PRIVATE|CREDENTIAL)"
    ),
    "token persisted in web storage": re.compile(
        r"(localStorage|sessionStorage)\.setItem\(\s*[^,)]*(token|secret|password|api[_-]?key)",
        re.IGNORECASE,
    ),
}

CLIENT_SECRET_ENV = re.compile(r"process\.env\.[A-Z0-9_]*(TOKEN|SECRET|PASSWORD|PASSWD|KEY)\b")
USE_CLIENT = re.compile(r"""^\s*["']use client["']""", re.MULTILINE)


#: ESLint configuration names the sinks in order to ban them; it never ships to the
#: browser, so it is excluded from the sink scan and checked positively instead.
LINT_CONFIG = re.compile(r"(^|/)(eslint\.config\.[cm]?[jt]s|\.eslintrc(\.[a-z]+)?)$")


def _frontend_sources() -> list[Path]:
    return sorted(
        p
        for p in iter_files(suffixes=SOURCE_SUFFIXES, roots=("frontend",))
        if not LINT_CONFIG.search(rel(p))
    )


def _lint_configs() -> list[Path]:
    return sorted(
        p
        for p in iter_files(roots=("frontend",))
        if LINT_CONFIG.search(rel(p)) and "/node_modules/" not in rel(p)
    )


SOURCES = _frontend_sources()
requires_frontend = pytest.mark.skipif(
    not SOURCES, reason="frontend/ has no source files yet (owner: D2)"
)


#: Reviewed exception marker for HTML sinks, on the flagged line or up to two
#: lines above, e.g. ``// extorq: html-reviewed keys/colours validated by SAFE_CSS``.
HTML_PRAGMA = re.compile(r"extorq:\s*html-reviewed\s+(?P<reason>[^*\n]{10,})")
PRAGMA_ELIGIBLE = frozenset({"dangerouslySetInnerHTML"})


_LINE_COMMENT = re.compile(r"(^|[\s;{}(),])//")


def _code_part(line: str, in_block: bool) -> tuple[str, bool]:
    """Strip ``/* */`` and ``//`` comments (heuristic; ``://`` in URLs is kept)."""
    code = []
    i = 0
    while i < len(line):
        if in_block:
            end = line.find("*/", i)
            if end == -1:
                return "".join(code), True
            i, in_block = end + 2, False
            continue
        start = line.find("/*", i)
        match = _LINE_COMMENT.search(line, i)
        line_comment = match.start() + len(match.group(1)) if match else -1
        if line_comment != -1 and (start == -1 or line_comment < start):
            code.append(line[i:line_comment])
            return "".join(code), False
        if start == -1:
            code.append(line[i:])
            break
        code.append(line[i:start])
        i, in_block = start + 2, True
    return "".join(code), in_block


def scan_frontend_text(text: str, *, relative: str) -> list[str]:
    findings: list[str] = []
    is_client = bool(USE_CLIENT.search(text[:500]))
    lines = text.splitlines()
    in_block_comment = False
    for number, line in enumerate(lines, start=1):
        window = lines[max(0, number - 3) : number]
        reviewed = any(HTML_PRAGMA.search(candidate) for candidate in window)
        code, in_block_comment = _code_part(line, in_block_comment)
        for label, pattern in FORBIDDEN.items():
            if pattern.search(code):
                if reviewed and label in PRAGMA_ELIGIBLE:
                    continue
                findings.append(f"{relative}:{number}: {label}")
        if is_client and CLIENT_SECRET_ENV.search(code):
            findings.append(f"{relative}:{number}: client component reads a secret-looking env var")
    return findings


@requires_frontend
def test_frontend_has_no_xss_sinks_or_browser_credentials() -> None:
    findings: list[str] = []
    for path in SOURCES:
        findings.extend(scan_frontend_text(read_text(path), relative=rel(path)))
    assert not findings, format_findings(findings)


def test_frontend_lint_bans_raw_html() -> None:
    """Positive control: D2's ESLint config keeps the raw-HTML escape hatch banned."""
    configs = _lint_configs()
    if not configs:
        pytest.skip("frontend has no ESLint configuration yet (owner: D2)")
    text = "\n".join(read_text(p) for p in configs)
    bans_no_danger = re.search(r"""["']react/no-danger["']\s*:\s*["'](error|2)["']""", text)
    bans_by_selector = "JSXAttribute[name.name='dangerouslySetInnerHTML']" in text
    assert bans_no_danger or bans_by_selector, (
        "ESLint config no longer bans dangerouslySetInnerHTML (react/no-danger)"
    )


@pytest.mark.parametrize(
    ("path", "is_lint_config"),
    [
        ("frontend/eslint.config.mjs", True),
        ("frontend/.eslintrc.json", True),
        ("frontend/src/app/page.tsx", False),
        ("frontend/src/eslint-helpers.ts", False),
    ],
)
def test_lint_config_pattern(path: str, is_lint_config: bool) -> None:
    assert bool(LINT_CONFIG.search(path)) is is_lint_config


@requires_frontend
def test_frontend_env_templates_have_no_public_secrets() -> None:
    findings: list[str] = []
    frontend = REPO_ROOT / "frontend"
    for template in sorted(frontend.glob(".env*.example")) + sorted(frontend.glob("*.env.example")):
        if template.is_symlink():
            continue
        text = read_text(template)
        for number, line in enumerate(text.splitlines(), start=1):
            if FORBIDDEN["secret-looking NEXT_PUBLIC_ variable"].search(line):
                findings.append(f"{rel(template)}:{number}: secret-looking NEXT_PUBLIC_ variable")
    assert not findings, format_findings(findings)


# ── scanner self-tests ───────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "snippet",
    [
        "<div dangerouslySetInnerHTML={{ __html: event.message }} />",
        "el.innerHTML = summary;",
        "node.insertAdjacentHTML('beforeend', html)",
        "document.write(x)",
        "const f = new Function('a', body)",
        "eval(payload)",
        "import rehypeRaw from 'rehype-raw'",
        "<ReactMarkdown allowDangerousHtml>{text}</ReactMarkdown>",
        "const t = process.env.NEXT_PUBLIC_API_TOKEN",
        "localStorage.setItem('apiToken', t)",
    ],
)
def test_frontend_scanner_flags_sinks(snippet: str) -> None:
    assert scan_frontend_text(snippet, relative="snippet.tsx"), snippet


def test_frontend_scanner_flags_secret_env_in_client_component() -> None:
    text = '"use client";\nconst t = process.env.EXTORQ_API_TOKEN;\n'
    assert scan_frontend_text(text, relative="c.tsx")


@pytest.mark.parametrize(
    "snippet",
    [
        "<pre>{event.message}</pre>",
        "if (el.innerHTML === '') {}",
        "const base = process.env.NEXT_PUBLIC_APP_NAME",
        "const v = evaluate(x)",
        "localStorage.setItem('theme', 'dark')",
    ],
)
def test_frontend_scanner_accepts_safe_code(snippet: str) -> None:
    assert not scan_frontend_text(snippet, relative="snippet.tsx"), snippet


def test_server_code_may_read_server_env() -> None:
    # Server-only modules (no "use client") may read the API token from the env.
    text = 'import "server-only";\nconst t = process.env.EXTORQ_API_TOKEN_FILE;\n'
    assert not scan_frontend_text(text, relative="server.ts")


def test_reviewed_html_exception_requires_reason() -> None:
    reviewed = "// extorq: html-reviewed chart keys and colours validated against SAFE_CSS\n"
    sink = "<style dangerouslySetInnerHTML={{ __html: css }} />\n"
    assert not scan_frontend_text(reviewed + sink, relative="chart.tsx")
    assert scan_frontend_text("// extorq: html-reviewed ok\n" + sink, relative="chart.tsx")
    # The marker never excuses other sinks.
    assert scan_frontend_text(reviewed + "el.innerHTML = x;\n", relative="x.ts")


def test_comments_are_not_code() -> None:
    doc = (
        "/**\n * The console never uses dangerouslySetInnerHTML.\n */\n"
        "const x = 1; // no innerHTML = here\n"
    )
    assert not scan_frontend_text(doc, relative="doc.ts")
    assert scan_frontend_text("const u = 'http://x'; el.innerHTML = u;", relative="u.ts")
