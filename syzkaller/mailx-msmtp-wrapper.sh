#!/bin/sh
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Szymon Wilczek
# Minimal mailx-compatible frontend for syz-manager crash mail.
set -eu

subject=

while [ "$#" -gt 0 ]; do
	case "$1" in
	-s)
		shift
		if [ "$#" -eq 0 ]; then
			echo "mailx wrapper: missing subject after -s" >&2
			exit 64
		fi
		subject=$1
		shift
		;;
	--)
		shift
		break
		;;
	-*)
		echo "mailx wrapper: unsupported option: $1" >&2
		exit 64
		;;
	*)
		break
		;;
	esac
done

if [ "$#" -eq 0 ]; then
	echo "mailx wrapper: missing recipient" >&2
	exit 64
fi

recipients=
for addr in "$@"; do
	if [ -z "$recipients" ]; then
		recipients=$addr
	else
		recipients="$recipients, $addr"
	fi
done

{
	printf 'To: %s\n' "$recipients"
	printf 'Subject: %s\n' "$subject"
	printf 'Content-Type: text/plain; charset=utf-8\n'
	printf '\n'
	cat
} | msmtp "$@"
