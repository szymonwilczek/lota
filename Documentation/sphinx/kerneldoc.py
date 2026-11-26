# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# kernel-doc directive: renders the /** ... */ comments of a C header.
#
#   .. kernel-doc:: include/lota_gaming.h
#      :identifiers: lota_connect lota_disconnect
#
#   .. kernel-doc:: include/lota_gaming.h
#      :doc: Connection lifetime
#
# With neither option every comment in the file is rendered. A path is
# relative to the repository root. A comment that does not parse,
# a parameter or member left undescribed or described but absent,
# and an identifier or DOC: title not found are build warnings.

import os
import re

from docutils import nodes
from docutils.parsers.rst import Directive, directives
from docutils.statemachine import ViewList
from sphinx.util import logging
from sphinx.util.nodes import nested_parse_with_titles

logger = logging.getLogger(__name__)

HEAD = re.compile(
    r"^(?:(?P<kind>struct|union|enum|typedef)\s+)?"
    r"(?P<name>[A-Za-z_]\w*)(?P<call>\(\))?\s+-\s+(?P<summary>\S.*)$"
)
DOC = re.compile(r"^DOC:\s*(?P<title>\S.*)$")
PARAM = re.compile(r"^@(?P<name>\w+|\.\.\.):\s*(?P<desc>.*)$")
SECTION = re.compile(
    r"^(?P<name>Return|Returns|Context|Note|Notes|Example|"
    r"Examples|Locking):\s*(?P<text>.*)$"
)
IDENT = re.compile(r"[A-Za-z_]\w*")
HIGHLIGHTS = [
    (re.compile(r"&(struct|union|enum)\s+(\w+)"), r":c:\1:`\2`"),
    (re.compile(r"(?<![\w`:@])(\w+)\(\)"), r":c:func:`\1()`"),
    (re.compile(r"(?<![\w`@])@(\w+|\.\.\.)"), r"``\1``"),
    (re.compile(r"(?<![\w`%])%([A-Za-z_]\w*)"), r"``\1``"),
]


class Comment:
    def __init__(self, path, line):
        self.path = path
        self.line = line
        self.kind = None
        self.name = None
        self.summary = ""
        self.params = []
        self.body = []
        self.decl = ""
        self.members = []


def comment_lines(text, start):
    """Yield (line number, text) of one comment, ' * ' prefix removed."""
    for i, raw in enumerate(text, start):
        s = raw.strip()
        if s.startswith("*/"):
            return
        if s.startswith("* "):
            s = raw.split("* ", 1)[1].rstrip()
        elif s == "*":
            s = ""
        yield i, s


def declaration(lines, i):
    """Text after a comment up to the end of its declaration."""
    out, depth = [], 0
    while i < len(lines):
        s = lines[i].split("//", 1)[0]
        out.append(s)
        i += 1
        if s.lstrip().startswith("#define"):
            while s.endswith("\\") and i < len(lines):
                s = lines[i]
                out.append(s)
                i += 1
            break
        depth += s.count("{") - s.count("}")
        if depth > 0 and not any(t in out[0] for t in ("struct", "union", "enum")):
            break
        if depth <= 0 and (
            ";" in s or ("{" in "".join(out) and depth == 0 and "}" in s)
        ):
            break
    return "\n".join(out)


def parse(path):
    with open(path, encoding="utf-8") as f:
        lines = f.read().splitlines()
    comments, bad = [], []
    i = 0
    while i < len(lines):
        if lines[i].strip() != "/**":
            i += 1
            continue
        c = Comment(path, i + 1)
        body = list(comment_lines(lines[i + 1 :], i + 2))
        end = i + 1 + len(body) + 1
        if not body:
            bad.append((i + 1, "empty kernel-doc comment"))
            i = end
            continue
        first = body[0][1]
        m = DOC.match(first)
        if m:
            c.kind, c.name = "doc", m.group("title")
        else:
            m = HEAD.match(first)
            if not m:
                bad.append((body[0][0], f"cannot parse kernel-doc head '{first}'"))
                i = end
                continue
            c.kind = m.group("kind") or ("function" if m.group("call") else "macro")
            c.name = m.group("name")
            c.summary = m.group("summary")
        rest = body[1:]
        param = None
        for n, s in rest:
            pm = PARAM.match(s)
            if pm and not c.body:
                param = [pm.group("name"), pm.group("desc"), n]
                c.params.append(param)
                continue
            if (
                param is not None
                and s
                and not c.body
                and (s[0].isspace() or not SECTION.match(s))
            ):
                param[1] += " " + s.strip()
                continue
            param = None
            c.body.append((n, s))
        if c.kind != "doc":
            c.decl = declaration(lines, end)
        comments.append(c)
        i = end
    return comments, bad


def highlight(text):
    """kernel-doc inline markup: @arg, %CONST, func(), &struct name."""
    parts = re.split(r"(``.*?``)", text)
    for i in range(0, len(parts), 2):
        for pat, sub in HIGHLIGHTS:
            parts[i] = pat.sub(sub, parts[i])
    return "".join(parts)


def prototype(c):
    d = c.decl
    if c.kind == "function":
        d = d.split("{", 1)[0].split(";", 1)[0]
        d = re.sub(r"^\s*(static\s+)?(inline\s+)?", "", d)
    elif c.kind == "macro" and d.lstrip().startswith("#define"):
        m = re.match(r"\s*#define\s+(\w+(?:\([^)]*\))?)", d)
        return m.group(1) if m else c.name
    return " ".join(d.split())


def split_top(s, sep=","):
    out, depth, cur = [], 0, ""
    for ch in s:
        depth += (ch in "([") - (ch in ")]")
        if ch == sep and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    out.append(cur)
    return [p.strip() for p in out if p.strip()]


def arg_name(arg):
    if arg in ("void", "..."):
        return None if arg == "void" else "..."
    m = re.search(r"\(\s*\*\s*(\w+)\s*\)", arg)
    if m:
        return m.group(1)
    arg = re.sub(r"\[[^\]]*\]", "", arg)
    names = IDENT.findall(arg)
    return names[-1] if names else None


def declared(c):
    """Parameter or member names the declaration itself carries."""
    if c.kind == "function":
        proto = prototype(c)
        if "(" not in proto:
            return None
        inner = proto[proto.index("(") + 1 : proto.rindex(")")]
        return {arg_name(a): a for a in split_top(inner) if arg_name(a)}
    if c.kind == "macro":
        m = re.match(r"\s*#define\s+\w+\(([^)]*)\)", c.decl)
        return (
            {a.strip(): a.strip() for a in m.group(1).split(",") if a.strip()}
            if m
            else None
        )
    if c.kind in ("struct", "union"):
        if "{" not in c.decl:
            return None
        inner = c.decl[c.decl.index("{") + 1 : c.decl.rindex("}")]
        inner = re.sub(r"/\*.*?\*/", "", inner, flags=re.DOTALL)
        names = {}
        for field in split_top(inner, ";"):
            if field.startswith("#"):
                continue
            field = " ".join(field.split())
            parts = split_top(field)
            base = re.sub(r"[\s*]*\w+(\[[^\]]*\])?$", "", parts[0]) if parts else ""
            for k, part in enumerate(parts):
                n = arg_name(part)
                if n:
                    names[n] = part if k == 0 else f"{base} {part}"
        return names
    return None


def check(c):
    """(line, message) for every parameter or member mismatch."""
    have = declared(c)
    if have is None:
        return []
    what = "member" if c.kind in ("struct", "union") else "parameter"
    label = f"{c.name}()" if c.kind == "function" else f"{c.kind} {c.name}"
    described = {p[0]: p[2] for p in c.params}
    out = [
        (c.line, f"{what} '{n}' not described in '{label}'")
        for n in have
        if n not in described
    ]
    out += [
        (line, f"excess {what} '{n}' described in '{label}'")
        for n, line in described.items()
        if n not in have
    ]
    return out


def render(c, out, src):
    def add(text, line):
        out.append(text, src, line - 1)

    if c.kind == "doc":
        for n, s in c.body:
            add(highlight(s), n)
        add("", c.line)
        return
    directive = {
        "function": "c:function",
        "struct": "c:struct",
        "union": "c:union",
        "enum": "c:enum",
        "typedef": "c:type",
        "macro": "c:macro",
    }[c.kind]
    sig = prototype(c) if c.kind in ("function", "macro") else c.name
    add(f".. {directive}:: {sig}", c.line)
    add("", c.line)
    add(f"   {highlight(c.summary)}", c.line)
    add("", c.line)
    have = declared(c) or {}
    if c.params:
        title = "Members" if c.kind in ("struct", "union") else "Parameters"
        add(f"   **{title}**", c.line)
        add("", c.line)
        for name, desc, n in c.params:
            add(f"   ``{have.get(name, name)}``", n)
            add(f"     {highlight(desc) or '*undescribed*'}", n)
            add("", n)
    for n, s in c.body:
        m = SECTION.match(s)
        if m:
            add(f"   **{m.group('name')}**", n)
            add("", n)
            s = m.group("text")
            if not s:
                continue
        add(f"   {highlight(s)}" if s else "", n)
    add("", c.line)


class KernelDoc(Directive):
    required_arguments = 1
    optional_arguments = 0
    has_content = False
    option_spec = {
        "identifiers": directives.unchanged,
        "doc": directives.unchanged_required,
    }

    def run(self):
        env = self.state.document.settings.env
        root = env.config.kerneldoc_srctree
        rel = self.arguments[0]
        path = os.path.join(root, rel)
        where = "%s:%s" % self.state_machine.get_source_and_line(self.lineno)
        if not os.path.isfile(path):
            logger.warning(f"kernel-doc: no such file {rel}", location=where)
            return []
        env.note_dependency(os.path.abspath(path))

        comments, bad = parse(path)
        for line, msg in bad:
            logger.warning(f"kernel-doc: {msg}", location=f"{path}:{line}")

        want = None
        if "identifiers" in self.options:
            want = self.options["identifiers"].split() or None
        title = self.options.get("doc")
        if title is not None:
            picked = [c for c in comments if c.kind == "doc" and c.name == title]
            if not picked:
                logger.warning(
                    f"kernel-doc: no 'DOC: {title}' in {rel}", location=where
                )
        elif want:
            byname = {c.name: c for c in comments if c.kind != "doc"}
            picked = []
            for name in want:
                if name in byname:
                    picked.append(byname[name])
                else:
                    logger.warning(
                        f"kernel-doc: no comment for '{name}' in {rel}", location=where
                    )
        else:
            picked = [c for c in comments if c.kind != "doc"]

        out = ViewList()
        for c in picked:
            for line, msg in check(c):
                logger.warning(f"kernel-doc: {msg}", location=f"{path}:{line}")
            render(c, out, path)

        node = nodes.section()
        node.document = self.state.document
        nested_parse_with_titles(self.state, out, node)
        return node.children


def setup(app):
    app.add_config_value(
        "kerneldoc_srctree", os.path.abspath(os.path.join(app.confdir, "..")), "env"
    )
    app.add_directive("kernel-doc", KernelDoc)
    return {"parallel_read_safe": True, "parallel_write_safe": True}
