#!/usr/bin/env bash
set -euo pipefail
if [ $# -lt 1 ]; then echo "usage: crack-helper.sh <hashfile>" >&2; exit 2; fi
hashfile="$1"
if command -v john >/dev/null 2>&1; then
  john "$hashfile" --wordlist="${WORDLIST:-/usr/share/wordlists/rockyou.txt}" || true
  john --show "$hashfile" || true
elif command -v hashcat >/dev/null 2>&1; then
  hashcat -a 0 "$hashfile" "${WORDLIST:-/usr/share/wordlists/rockyou.txt}" || true
else
  echo "john/hashcat missing" >&2; exit 127
fi
