/*
 * pbkdf.cpp
 *
 *  Created on: Aug 4, 2015
 *      Author: olic
 */

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <Item.h>
#include <native_crypto.h>

SymKey *pbkdf2(Password *pwd, const unsigned char* salt)
{
	SymKey *key = new SymKey(PBKDF2_KEY_LEN);

	//PKCS5_PBKDF2_HMAC() return 1 on success or 0 on error.
	if(PKCS5_PBKDF2_HMAC((const char *)pwd->getData(), pwd->len,
			salt, PBKDF2_SALT_LEN, PBKDF2_ITER_CNT, EVP_sha256(),
			PBKDF2_KEY_LEN, key->getData()) == 1)
		return key;

	delete key;
	return NULL;
}

EncItem *pbkdf_create_mkek(Password *pwd) {
	int rc;

	SymKey *mkek =  KeyCrypto::generateSymKey();
	unsigned char salt[PBKDF2_SALT_LEN];
	RAND_bytes(salt, PBKDF2_SALT_LEN);

	SymKey *dKey = pbkdf2(pwd, salt);
	if(dKey == NULL) {
		printf("failed to derive key\n");
		return NULL;
	}

	EncItem *emkek = aes_gcm_encrypt(mkek, dKey);
	emkek->encBy = CryptAlg::PBKDF;
	memcpy(emkek->salt, salt, PBKDF2_SALT_LEN);
	memset(salt, 0, PBKDF2_SALT_LEN);

	delete mkek, dKey;
	return emkek;
}

SymKey *pbkdf_derive_mkek(Password *pwd, EncItem *payload) {
	int rc;

	SymKey *dKey = pbkdf2(pwd, payload->salt);
	if(dKey == NULL) {
		printf("failed to derive key\n");
		return NULL;
	}

	// decrypt mk with kek
	SymKey *mkek = aes_gcm_decrypt(payload, dKey);

	delete dKey;
	return mkek;
}

int pbkdf_change_password(Password *old_pwd, Password *new_pwd,
		EncItem *payload) {
	return 0;
}
