#!/bin/sh
# Builds ./seedvanity: embeds the Metal kernel and the BIP39 wordlist into the binary.
set -e
cd "$(dirname "$0")"
[ "$(shasum -a 256 english.txt | cut -d' ' -f1)" = 2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda ] || { echo "english.txt is not the canonical BIP39 list"; exit 1; }
{
  printf 'let kernelSource = #"""\n'
  sed 's/^using namespace metal;$/using namespace metal;/' pbkdf2.metal | awk '/^using namespace metal;$/ { print; while ((getline l < "sha512_consts.h") > 0) print l; next } { print }'
  printf '"""#\n'
  printf 'let wordlistRaw = #"""\n'
  cat english.txt
  printf '"""#\n'
} > generated.swift
clang -O3 -Wall -c cpu_pbkdf2.c -o cpu_pbkdf2.o
swiftc -O -import-objc-header cpu_pbkdf2.h -o seedvanity main.swift generated.swift cpu_pbkdf2.o
echo "built ./seedvanity"
