#!/bin/sh
# Linux: runs seedvanity until it reports a verified hit (exit 0). If it dies for any other reason,
# restarts it (up to 5 times). Desktop notifications via notify-send if available.
# Usage: ./supervise.sh PATTERN MODE OUTFILE LOGFILE
# Detached, without sleep:
#   nohup setsid systemd-inhibit --what=sleep:idle ./supervise.sh '[a-z_]HELLO' bip39-12 \
#     ../results/found.txt ../results/run.log >/dev/null 2>&1 &
cd "$(dirname "$0")" || exit 1
pat=$1 mode=$2 out=$3 log=$4
notify() { command -v notify-send >/dev/null 2>&1 && notify-send "seedvanity" "$1"; }
n=0
while :; do
  ./seedvanity --suffix "$pat" --mode "$mode" --out "$out" >> "$log" 2>&1
  code=$?
  if [ "$code" -eq 0 ]; then
    notify "Search $pat finished, see $log"
    exit 0
  fi
  n=$((n + 1))
  echo "--- seedvanity exited with code $code at $(date '+%H:%M:%S'), restart $n/5 ---" >> "$log"
  if [ "$n" -gt 5 ]; then
    notify "Search $pat stopped 5 times, giving up. See $log"
    exit 1
  fi
  sleep 5
done
