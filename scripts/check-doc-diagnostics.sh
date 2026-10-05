#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# Doc-quoted diagnostic gate.
#
# An operator reaches the documentation with the message the machine printed,
# and searches for it. A quote that paraphrases the message answers nobody:
# it neither matches what is on the screen nor names a string that exists.
#
# This gate takes every sentence-shaped inline literal in the documentation
# and requires the program to be able to print it. The message table is built
# from the source, with adjacent C string literals joined -- a message wrapped
# over four lines is one string to the reader of the journal, so it is one
# string here -- and with format specifiers treated as the text they stand in
# for.
#
# It reads inline literals only. Output quoted inside a code block is
# a transcript, and a transcript carries values from the run that produced it.
#
# Usage: scripts/check-doc-diagnostics.sh
# Requires: git, python3 (no build, no toolchain)
set -euo pipefail

cd "$(dirname "$0")/.."

EXEMPTIONS="scripts/doc-diagnostics-exemptions.txt"

python3 - "$EXEMPTIONS" <<'PY'
import os
import re
import subprocess
import sys

exemptions_path = sys.argv[1]


def normalise(text):
	return re.sub(r"\s+", " ", text).strip()


def tracked(*patterns):
	out = subprocess.run(
		["git", "ls-files", *patterns],
		capture_output=True, text=True, check=True).stdout
	return [p for p in out.split("\n") if p]


# A literal is a candidate diagnostic when it reads like a sentence
# the program printed: several words, opening on a capital, and none of
# the punctuation that marks a shell command or a configuration fragment.
def candidates():
	found = []
	for path in tracked("Documentation/*.rst", "*.rst"):
		text = open(path, encoding="utf-8").read()
		for match in re.finditer(r"``(.+?)``", text, re.S):
			literal = normalise(match.group(1))
			if len(literal.split()) < 4:
				continue
			if not re.match(r"^[A-Z]", literal):
				continue
			if re.search(r"[$|&<>;\\]", literal):
				continue
			line = text[:match.start()].count("\n") + 1
			found.append((path, line, literal))
	return found


C_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "0": "\0",
             '"': '"', "\\": "\\", "'": "'"}


def unescape(text):
	out = []
	i = 0
	while i < len(text):
		if text[i] == "\\" and i + 1 < len(text):
			out.append(C_ESCAPES.get(text[i + 1], text[i + 1]))
			i += 2
		else:
			out.append(text[i])
			i += 1
	return "".join(out)


STRING = re.compile(r'"((?:[^"\\]|\\.)*)"')
# adjacent literals are one message; only whitespace and comments may
# separate them, which is how every wrapped lota_err() in the tree is written
GAP = re.compile(r"(?:\s|/\*.*?\*/|//[^\n]*\n)*", re.S)


def c_messages(path, text):
	messages = []
	pos = 0
	while True:
		match = STRING.search(text, pos)
		if not match:
			break
		parts = [unescape(match.group(1))]
		end = match.end()
		while True:
			gap = GAP.match(text, end)
			nxt = STRING.match(text, gap.end())
			if not nxt:
				break
			parts.append(unescape(nxt.group(1)))
			end = nxt.end()
		messages.append("".join(parts))
		pos = end
	return messages


BACKTICK = re.compile(r"`([^`]*)`", re.S)


def go_messages(path, text):
	return ([unescape(m.group(1)) for m in STRING.finditer(text)]
	        + [m.group(1) for m in BACKTICK.finditer(text)])


SPECIFIER = re.compile(r"%[-+ #0-9.*']*(?:hh|h|ll|l|L|z|j|t)?[a-zA-Z%]")

# Literal characters a message must carry before it can stand for a quote
# that runs across one of its specifiers.
ANCHOR_CHARS = 12


def fragments(message):
	return SPECIFIER.split(message)


def pattern_of(message):
	return re.compile(
		".*?".join(re.escape(f) for f in fragments(message)), re.S)


def message_table():
	table = []
	for path in tracked("src/*.c", "src/*.h", "src/*.go",
	                    "tools/*.c", "tools/*.go",
	                    "examples/*.c", "examples/*.h", "examples/*.go"):
		text = open(path, encoding="utf-8", errors="replace").read()
		reader = go_messages if path.endswith(".go") else c_messages
		for message in reader(path, text):
			if len(message) < 8:
				continue
			table.append(message)
	# shell script prints its text as it stands, so it needs no parsing
	for path in tracked("scripts/*.sh", "scripts/lota-*"):
		if os.path.isdir(path):
			continue
		table.append(open(path, encoding="utf-8", errors="replace").read())
	return table


def explains(message, literal):
    # The literal is a span of the message the program prints.
    # It either sits inside one of the message's literal fragments,
    # or it runs across a specifier, in which case the substituted
    # text is what closes it.
	parts = fragments(message)
	if any(literal in normalise(f) for f in parts):
		return True
	# A message that is mostly specifiers ("%s: %s") stands for any text at
	# all, so matching against it proves nothing.
        # Require the message to open on words of its own and to carry enough of
        # them to be an anchor.
	if not parts[0].strip():
		return False
	if sum(len(f.strip()) for f in parts) < ANCHOR_CHARS:
		return False
	return pattern_of(normalise(message)).fullmatch(literal) is not None


def main():
	exempt = set()
	if os.path.exists(exemptions_path):
		for line in open(exemptions_path, encoding="utf-8"):
			line = line.strip()
			if line and not line.startswith("#"):
				exempt.add(line)

	table = message_table()
	checked = 0
	failures = 0

	for path, line, literal in candidates():
		if literal in exempt:
			continue
		checked += 1
		if any(explains(message, literal) for message in table):
			continue
		print(f"check-doc-diagnostics: {path}:{line}: "
		      f"no source message prints {literal!r}", file=sys.stderr)
		failures += 1

	if failures:
		print(f"check-doc-diagnostics: {failures} quote(s) name a message "
		      "the program cannot print", file=sys.stderr)
		print("quote the message verbatim, or add the literal to "
		      f"{exemptions_path} when it is not program output",
		      file=sys.stderr)
		return 1

	print(f"check-doc-diagnostics: clean ({checked} quoted diagnostics)")
	return 0


sys.exit(main())
PY
