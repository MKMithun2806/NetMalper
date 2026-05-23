#!/bin/sh
set -eu

NOFILE_SOFT="${NETMALPER_NOFILE_SOFT:-8192}"

if ulimit -n "$NOFILE_SOFT" 2>/dev/null; then
    :
else
    echo "netmalper: could not raise nofile limit to $NOFILE_SOFT" >&2
fi

exec /usr/bin/python3 /usr/share/netmalper/netmalper.py "$@"
