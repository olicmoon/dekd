/*
 * native_crypto.h
 *
 *  Created on: Aug 18, 2015
 *      Author: olic
 */

#ifndef NATIVE_CRYPTO_H_
#define NATIVE_CRYPTO_H_

#include "Item.h"

Item *base64e(Item *in);
Item *base64d(Item *in);

EncItem *aes_gcm_encrypt(Item *item, SymKey *key);
Item *aes_gcm_decrypt(EncItem *eitem, SymKey *key);

int ecdh_gen_keypair(PubKey *pub, PrivKey *pri);
DhPayload *ecdh_encrypt(Item *item, PubKey *devDpub);
Item *ecdh_decrypt(DhPayload *dhpay, PrivKey *devDpri);

void sha256(unsigned char *hash, const unsigned char *in, size_t len);

#endif /* NATIVE_CRYPTO_H_ */
