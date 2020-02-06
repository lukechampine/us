#!/bin/bash

# A pre-push hook to prevent accidentally pushing new major versions.

vs="$(git tag | sort -rV | cut -c 1,2 | head -n 2)"
if [[ "$(echo "$vs" | wc -l | awk '{print $1}')" == "2" ]] && [[ -z $(echo "$vs" | uniq -d) ]]; then
    echo >&2 "It looks like you're pushing a tag with a new major version!"
    echo >&2 "...I'm gonna assume that was a mistake."
    echo >&2 "If it wasn't, just rm this hook before pushing again."
    exit 1;
fi
