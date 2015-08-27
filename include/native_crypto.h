/*
 * native_crypto.h
 *
 *  Created on: Aug 18, 2015
 *      Author: olic
 */

#ifndef NATIVE_CRYPTO_H_
#define NATIVE_CRYPTO_H_

#include <Item.h>

#define PBKDF2_ITER_CNT 100000
#define PBKDF2_KEY_MAX 128
#define PBKDF2_KEY_LEN 32
#define PBKDF2_SALT_LEN 16
#define PBKDF2_GCM_TAG_LEN 16

bool Base64Encode(const unsigned char* buffer, size_t length, char** b64text);
bool Base64Decode(char* b64message, unsigned char** buffer, size_t* length);

SymKey *generateSymKey();

EncItem *aes_gcm_encrypt(Item *item, SymKey *key);
Item *aes_gcm_decrypt(EncItem *eitem, SymKey *key);

int ecdh_gen_keypair(PubKey *pub, PrivKey *pri);
EncItem *ecdh_encrypt(Item *item, PubKey *devDpub);
Item *ecdh_decrypt(EncItem *dhpay, PrivKey *devDpri);

void sha256(unsigned char *hash, const unsigned char *in, size_t len);

EncItem *pbkdf_create_mkek(Password *pwd);
SymKey *pbkdf_derive_mkek(EncItem *payload, Password *pwd);

#endif /* NATIVE_CRYPTO_H_ */
