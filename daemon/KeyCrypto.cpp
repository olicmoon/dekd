/*
 * KeyCrypto.cpp
 *
 *  Created on: Aug 17, 2015
 *      Author: olic
 */

#include "KeyCrypto.h"

KeyCrypto::KeyCrypto() {
	pubKey = NULL;
	privKey = NULL;
	symKey = NULL;
}

KeyCrypto::~KeyCrypto() {
}

EncItem *KeyCrypto::encrypt(Item *item, Key *key) {
	int alg = key->alg;
	EncItem *eitem = NULL;

	switch(alg) {
	case CryptAlg::AES:
		eitem = aes_gcm_encrypt(item, (SymKey *)key);
		break;
	case CryptAlg::ECDH:
		eitem = ecdh_encrypt(item, (PubKey *)key);
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
	case CryptAlg::AES:
		item = aes_gcm_decrypt(eitem, (SymKey *)key);
		break;
	case CryptAlg::ECDH:
		item = ecdh_decrypt(eitem, (PrivKey *)key);
		break;
	default:
		printf("unknown alg<%d>\n", alg);
		return NULL;
	}

	return item;

}
