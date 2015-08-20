/*
 * KeyCrypto.cpp
 *
 *  Created on: Aug 17, 2015
 *      Author: olic
 */

#include <KeyCrypto.h>
#include <native_crypto.h>

KeyCrypto::KeyCrypto() {

}

KeyCrypto::~KeyCrypto() {
}

void KeyCrypto::generateKeyPair(int alg,
		PubKey &pubKey, PrivKey &privKey) {

}

EncItem *KeyCrypto::encrypt(Item *item, Key *key) {
	int alg = key->alg;
	EncItem *eitem = NULL;

	switch(alg) {
	case CRYPTO_ALG_AES:
		eitem = aes_gcm_encrypt(item, key);
		break;
	case CRYPTO_ALG_RSA:
		printf("RSA not yet supported");
		break;
	case CRYPTO_ALG_ECDH:
		eitem = ecdh_encrypt(item, key);
		break;
	default:
		printf("unknown alg<%d>\n", alg);
		return NULL;
	}

	return eitem;
}

Item *KeyCrypto::decrypt(EncItem *eitem, Key *key) {
	int alg = key->alg;
	Item *item = NULL;

	switch(alg) {
	case CRYPTO_ALG_AES:
		item = aes_gcm_decrypt(eitem, key);
		break;
	case CRYPTO_ALG_RSA:
		printf("RSA not yet supported");
		break;
	case CRYPTO_ALG_ECDH:
		item = ecdh_decrypt(eitem, key);
		break;
	default:
		printf("unknown alg<%d>\n", alg);
		return NULL;
	}

	return NULL;

}
