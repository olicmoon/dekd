/*
 * sha.c
 *
 *  Created on: Aug 5, 2014
 *      Author: roy
 */

#include <openssl/sha.h>
#include <string.h>

void sha256(unsigned char *hash, const unsigned char *in, size_t len)
{
    SHA256_CTX sha256;

	memset(hash, 0, SHA256_DIGEST_LENGTH);

    SHA256_Init(&sha256);
    SHA256_Update(&sha256, in, len);
    SHA256_Final(hash, &sha256);
}
