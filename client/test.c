#include<stdio.h>
#include <sys/time.h>
#include "time.h"
// #include "system.h"
// #include "utils/utils.h"
typedef unsigned long long uint64_t;
#include "sha256.h"
#include "hash.h"


typedef SHA256_CTX SHA256REF_CTX;
typedef uint64_t xdag_hash_t[4];
typedef char BYTE;

void xdag_hash(void *data, size_t size, xdag_hash_t hash)
{
	SHA256REF_CTX ctx;

	sha256_init(&ctx);
	sha256_update(&ctx, data, size);
	sha256_final(&ctx, (uint8_t*)hash);
	sha256_init(&ctx);
	sha256_update(&ctx, (uint8_t*)hash, sizeof(xdag_hash_t));
	sha256_final(&ctx, (uint8_t*)hash);
}


int main(){
    // xdag_hash_t hash;
    // BYTE a[3] = {1,23,4};
    // xdag_hash(a,3,hash);

    printf("hello");
    return 0;

}
