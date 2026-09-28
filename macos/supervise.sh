#!/bin/sh
# macOS: runs seedvanity until it reports a verified hit (exit 0). If it dies for any other reason
# (killed, crashed), restarts it (up to 5 times) and shows a silent notification.
# Usage: supervise.sh PATTERN MODE OUTFILE LOGFILE   (start it detached, see README)
cd "$(dirname "$0")" || exit 1
pat=$1 mode=$2 out=$3 log=$4
notify() { osascript -e "display notification \"$1\" with title \"seedvanity\"${2:+ sound name \"$2\"}" >/dev/null 2>&1; }
n=0
while :; do
  caffeinate -i ./seedvanity --suffix "$pat" --mode "$mode" --out "$out" >> "$log" 2>&1
  code=$?
  if [ "$code" -eq 0 ]; then
    notify "Search $pat finished, see $(basename "$log")" Glass
    exit 0
  fi
  n=$((n + 1))
  echo "--- seedvanity exited with code $code at $(date '+%H:%M:%S'), restart $n/5 ---" >> "$log"
  if [ "$n" -gt 5 ]; then
    notify "Search $pat stopped 5 times, giving up. See $(basename "$log")" Basso
    exit 1
  fi
  notify "Search $pat was stopped, restarting ($n/5)"
  sleep 5
done
