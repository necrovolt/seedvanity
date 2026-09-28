// Minimal SHA-256 (FIPS 180-4) for BIP39 checksums and TON cell hashes.
#pragma once
#include <stddef.h>
#include <stdint.h>
void sha256(const uint8_t *msg, size_t len, uint8_t out[32]);
