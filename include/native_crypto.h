/*
 * native_crypto.h
 *
 *  Created on: Aug 18, 2015
 *      Author: olic
 */

#ifndef NATIVE_CRYPTO_H_
#define NATIVE_CRYPTO_H_

#include "Item.h"

//Item *base64e(Item *in);
//Item *base64d(Item *in);

int Base64Encode(const unsigned char* buffer, size_t length, char** b64text);
int Base64Decode(char* b64message, unsigned char** buffer, size_t* length);

EncItem *aes_gcm_encrypt(Item *item, SymKey *key);
Item *aes_gcm_decrypt(EncItem *eitem, SymKey *key);

int ecdh_gen_keypair(PubKey *pub, PrivKey *pri);
EncItem *ecdh_encrypt(Item *item, PubKey *devDpub);
Item *ecdh_decrypt(EncItem *dhpay, PrivKey *devDpri);

void sha256(unsigned char *hash, const unsigned char *in, size_t len);

#endif /* NATIVE_CRYPTO_H_ */
