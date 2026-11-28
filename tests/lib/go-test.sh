#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
#
# tests/lib/go-test.sh [go test flags] [packages]
#
# Prints what plain `go test` prints and records each package as a group
# in LOTA_TEST_SUMMARY.
#
# Requires: go, python3.

set -euo pipefail

verbose=0
for a in "$@"; do
    case $a in
	-v | -test.v | -v=true | -test.v=true) verbose=1 ;;
    esac
done

# the workspace lists every module; ask for this one alone
module=$(GOWORK=off go list -m)
prefix=$(git rev-parse --show-prefix 2>/dev/null || true)
prefix=${prefix%/}

go test -json "$@" 2>&1 | python3 -I -c '
import json, os, sys

verbose, module, prefix = sys.argv[1] == "1", sys.argv[2], sys.argv[3]
summary = os.environ.get("LOTA_TEST_SUMMARY", "")
pkgs = {}

def group(pkg):
    rest = pkg[len(module):] if pkg.startswith(module) else "/" + pkg
    return (prefix + rest).lstrip("/") or pkg

def state(pkg):
    return pkgs.setdefault(pkg, {"order": [], "out": {}, "res": {},
                                 "kids": {}})

def emit(text):
    sys.stdout.write(text)
    sys.stdout.flush()

def finish(pkg, st):
    top = [t for t in st["order"] if "/" not in t]
    count = {"pass": 0, "fail": 0, "skip": 0}
    for t in top:
        res = st["res"].get(t, "fail")
        count[res] += 1
    fails = []
    for t in st["order"]:
        if st["res"].get(t, "fail") != "fail":
            continue
        if any(o.startswith(t + "/") and st["res"].get(o, "fail") == "fail"
               for o in st["order"]):
            continue
        n = top.index(t.split("/")[0]) + 1
        fails.append((n, t))
    if st.get("failed") and not fails:
        fails.append((0, "(package)"))
        count["fail"] += 1
    if not summary or not (top or fails):
        return
    g = group(pkg)
    with open(summary, "a") as f:
        for n, t in fails:
            f.write("F\t%s\t%d\t%s\n" % (g, n, t))
        f.write("G\t%s\t%d\t%d\t%d\n" % (g, count["pass"], count["fail"],
                                        count["skip"]))

for line in sys.stdin:
    try:
        ev = json.loads(line)
    except ValueError:
        emit(line)
        continue
    act = ev.get("Action")
    if act in ("build-output", "build-fail"):
        emit(ev.get("Output", ""))
        continue
    pkg = ev.get("Package")
    if pkg is None:
        emit(ev.get("Output", ""))
        continue
    st = state(pkg)
    test = ev.get("Test")
    out = ev.get("Output", "")
    if test is None:
        if act == "output" and (verbose or out not in ("PASS\n",)):
            emit(out)
        elif act == "fail":
            st["failed"] = True
        if act in ("pass", "fail", "skip"):
            finish(pkg, st)
        continue
    if act == "run" and test not in st["res"]:
        st["order"].append(test)
        st["res"][test] = "fail"
    elif act == "output":
        if verbose:
            emit(out)
        else:
            st["out"].setdefault(test, []).append(out)
    elif act in ("pass", "fail", "skip"):
        if test not in st["res"]:
            st["order"].append(test)
        st["res"][test] = act
        lines = st["out"].pop(test, [])
        kids = st["kids"].pop(test, [])
        if act != "fail" or verbose:
            continue
        # plain go test prints a failed test as its --- FAIL line,
        # its own log, then its failed subtests, without the === lines
        lines = [l for l in lines if not l.lstrip().startswith("=== ")]
        head = [l for l in lines if l.lstrip().startswith("--- FAIL")]
        body = [l for l in lines if l not in head]
        text = head + body + kids
        parent = test.rpartition("/")[0]
        if parent:
            st["kids"].setdefault(parent, []).extend("    " + l for l in text)
        else:
            emit("".join(text))

# plain go test ends a run with a failed package on a bare FAIL
if any(st.get("failed") for st in pkgs.values()):
    emit("FAIL\n")
' "$verbose" "$module" "$prefix"
