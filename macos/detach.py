# Starts a command fully detached from the chat: own session and process group, parent = launchd.
# Usage: python3 detach.py CMD [ARGS...]
import os, sys
if os.fork() > 0:
    sys.exit(0)
os.setsid()
if os.fork() > 0:
    os._exit(0)
fd = os.open("/dev/null", os.O_RDWR)
for i in (0, 1, 2):
    os.dup2(fd, i)
os.execvp(sys.argv[1], sys.argv[1:])
