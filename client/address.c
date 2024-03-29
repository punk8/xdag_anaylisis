/* addresses, T13.692-T13.720 $DVS:time$ */

#include <stdint.h>
#include <string.h>
#include "address.h"
#include <stdio.h>
static const uint8_t bits2mime[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static uint8_t mime2bits[256];

// intializes the address module
int xdag_address_init(void)
{
	fprintf(stdout,"xdag_address_init\n");

	int i;

	memset(mime2bits, 0xFF, 256);

	for (i = 0; i < 64; ++i) {
		mime2bits[bits2mime[i]] = i;
	}

	return 0;
}

// converts address to hash
int xdag_address2hash(const char *address, xdag_hash_t hash)
{
	uint8_t *fld = (uint8_t*)hash;
	int i, c, d, n;

	for (int e = n = i = 0; i < 32; ++i) {
		do {
			if (!(c = (uint8_t)*address++))
				return -1;
			d = mime2bits[c];
		} while (d & 0xC0);
		e <<= 6;
		e |= d;
		n += 6;

		if (n >= 8) {
			n -= 8;
			*fld++ = e >> n;
		}
	}

	for (i = 0; i < 8; ++i) {
		*fld++ = 0;
	}
	uint64_t *h = hash;
	fprintf(stdout, "->address2hash  hash: %016llx%016llx%016llx%016llx\n",
			(unsigned long long)h[3], (unsigned long long)h[2], (unsigned long long)h[1], (unsigned long long)h[0]);
	return 0;
}

// converts hash to address
void xdag_hash2address(const xdag_hash_t hash, char *address)
{
	int c, d;
	const uint8_t *fld = (const uint8_t*)hash;

	for (int i = c = d = 0; i < 32; ++i) {
		if (d < 6) {
			d += 8;
			c <<= 8;
			c |= *fld++;
		}
		d -= 6;
		*address++ = bits2mime[c >> d & 0x3F];
	}
	*address = 0;
}
