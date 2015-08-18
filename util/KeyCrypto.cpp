/*
 * KeyCrypto.cpp
 *
 *  Created on: Aug 17, 2015
 *      Author: olic
 */

#include "KeyCrypto.h"

KeyCrypto::KeyCrypto() {

}

KeyCrypto::~KeyCrypto() {
}

void KeyCrypto::generateKeyPair(int alg,
		PubKey &pubKey, PrivKey &privKey) {

}

bool KeyCrypto::encrypt(shared_ptr<Item> &item, shared_ptr<Key> &key) {
	int alg = key->alg;

	switch(alg) {
	case CRYPTO_ALG_AES:
	{
		SymKey _key = key;
	}
		break;
	case CRYPTO_ALG_RSA:
	{
		PubKey _key = key;
	}
		break;
	case CRYPTO_ALG_ECDH:
	{
		PubKey _key = key;
	}
		break;
	default:
		printf("unknown alg<%d>\n", alg);
		return false;
	}

	return true;
}

bool KeyCrypto::decrypt(shared_ptr<Item> &item, shared_ptr<Key> &key) {
	int alg = key->alg;

	switch(alg) {
	case CRYPTO_ALG_AES:
	{
		SymKey _key = key;
	}
		break;
	case CRYPTO_ALG_RSA:
	{
		PrivKey _key = key;
	}
		break;
	case CRYPTO_ALG_ECDH:
	{
		PrivKey _key = key;
	}
		break;
	default:
		printf("unknown alg<%d>\n", alg);
		return false;
	}

	return true;

}
