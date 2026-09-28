# seedvanity (OpenCL)
#   Linux:          make
#   Windows:        make   (in an MSYS2 UCRT64 or MINGW64 shell, see README)
#   macOS:          make   (for testing only; on a Mac use the Metal version in gpu/)
# embedded.h (kernel + wordlist) is generated and shipped; regenerate with `make embed` (needs python3).
SRC = seedvanity.c sha256.c third_party/monocypher/monocypher.c third_party/monocypher/monocypher-ed25519.c
CFLAGS ?= -O3 -Wall -Wextra -Wno-unused-parameter
UNAME := $(shell uname -s 2>/dev/null)
ifeq ($(OS),Windows_NT)
  ifeq ($(origin CC),default)
    CC = gcc
  endif
  LIBS = -lOpenCL -lbcrypt -static-libgcc
  EXE = .exe
else ifeq ($(UNAME),Darwin)
  LIBS = -framework OpenCL -lpthread
  CFLAGS += -Wno-deprecated-declarations
else
  LIBS = -lOpenCL -lpthread -lm
endif

seedvanity$(EXE): $(SRC) embedded.h sha256.h
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LIBS)

embed:
	python3 tools/embed.py

clean:
	rm -f seedvanity seedvanity.exe

.PHONY: embed clean
