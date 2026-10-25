#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# Shipped-configuration command gate.
#
# Every option a tracked file under policies/ or configs/ passes to a lota-*
# command must be in that command's option table in the source.
# A lota-* word followed by a dot is a file name, not an invocation.
#
# Usage: scripts/check-config-commands.sh
# Requires: git, python3 (no build, no toolchain)
set -euo pipefail

cd "$(dirname "$0")/.."

python3 - <<'PY'
import re
import subprocess
import sys


# command -> (table syntax, source); a command missing here fails the gate
OPTION_TABLES = {
	"lota-agent": ("c", "src/agent/cli.c"),
	"lota-verifier": ("go", "src/verifier/main.go"),
	"lota-attest-ca": ("go", "src/attestca/main.go"),
}

# getopt_long table entries: { "name", has_arg, ... }
C_OPTION = re.compile(r'\{\s*"([a-z][a-z0-9-]*)"\s*,')
# flag.String("name", ...) and flag.StringVar(&x, "name", ...)
GO_OPTION = re.compile(r'flag\.[A-Za-z]+\(\s*(?:&?[\w.\[\]]+\s*,\s*)?'
		       r'"([a-zA-Z][\w-]*)"')

INVOCATION = re.compile(r"\blota-[a-z][a-z0-9-]*")
# getopt_long needs two dashes, Go's flag package takes one or two
LONG_OPTION = re.compile(r"(?<![\w-])--([a-zA-Z][\w-]*)")
GO_ARG = re.compile(r"(?<![\w-])--?([a-zA-Z][\w-]*)")
# what follows belongs to another program
SHELL_BREAK = re.compile(r"[|;>&`]")


def tracked(*patterns):
	out = subprocess.run(["git", "ls-files", *patterns],
			     capture_output=True, text=True,
			     check=True).stdout
	return [p for p in out.split("\n") if p]


def options_of(command):
	kind, path = OPTION_TABLES[command]
	source = open(path, encoding="utf-8").read()
	if kind == "c":
		table = re.search(r"long_options\[\]\s*=\s*\{(.*?)\n\t\};",
				  source, re.S)
		if not table:
			sys.exit(f"{path}: no long_options table to read")
		return set(C_OPTION.findall(table.group(1)))
	return set(GO_OPTION.findall(source))


known_options = {}
failures = []

for path in tracked("policies/*", "configs/*"):
	try:
		text = open(path, encoding="utf-8").read()
	except (UnicodeDecodeError, IsADirectoryError):
		continue

	for lineno, line in enumerate(text.split("\n"), 1):
		hits = list(INVOCATION.finditer(line))
		for i, hit in enumerate(hits):
			command = hit.group(0)
			end = hits[i + 1].start() if i + 1 < len(hits) else len(line)
			segment = line[hit.end():end]
			if segment.startswith("."):
				continue
			cut = SHELL_BREAK.search(segment)
			if cut:
				segment = segment[:cut.start()]
			kind = OPTION_TABLES.get(command, ("c", None))[0]
			named = (GO_ARG if kind == "go" else
				 LONG_OPTION).findall(segment)
			if not named:
				continue
			if command not in OPTION_TABLES:
				failures.append(
					f"{path}:{lineno}: {command} is given "
					f"options and this gate has no table "
					f"for it; add one or fix the name")
				continue
			if command not in known_options:
				known_options[command] = options_of(command)
			for opt in named:
				if opt not in known_options[command]:
					failures.append(
						f"{path}:{lineno}: "
						f"{command} --{opt} is not an "
						f"option {command} accepts")

if failures:
	print("Commands named in shipped configuration that do not resolve:\n")
	for line in failures:
		print(f"  {line}")
	print("\nA comment is read on a host where the command has to run.")
	sys.exit(1)

print("check-config-commands: every command named in policies/ and "
      "configs/ resolves")
PY
