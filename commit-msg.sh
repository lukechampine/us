#!/bin/sh
#
# A commit-msg hook to enforce the us commit message style.

if ! egrep ': [A-Z0-9]+' "$1" >/dev/null; then
	echo >&2 "Commit message should be of the form \"lowercase: Uppercase\""
	echo >&2 "(Your commit message was saved in $1)"
	exit 1
fi
if head -n1 "$1" | grep "\.$"; then
	echo >&2 "Commit message should not end in a period"
	echo >&2 "(Your commit message was saved in $1)"
	exit 1
fi
