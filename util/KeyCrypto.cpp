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

#if 0
bool KeyCrypto::encrypt(shared_ptr<Item> &item, shared_ptr<AbstractKey> &key) {
	int alg = key->alg;

	switch(alg) {
	case CRYPTO_ALG_AES:
	{
		shared_ptr<SymKey> _key = dynamic_pointer_cast<SymKey>(key);
	}
		break;
	case CRYPTO_ALG_RSA:
	{
		shared_ptr<PubKey> _key = dynamic_pointer_cast<PubKey>(key);
	}
		break;
	case CRYPTO_ALG_ECDH:
	{
		shared_ptr<PubKey> _key = dynamic_pointer_cast<PubKey>(key);
	}
		break;
	default:
		printf("unknown alg<%d>\n", alg);
		return false;
	}

	return true;
}

bool KeyCrypto::decrypt(shared_ptr<Item> &item, shared_ptr<AbstractKey> &key) {
	int alg = key->alg;

	switch(alg) {
	case CRYPTO_ALG_AES:
	{
		shared_ptr<SymKey> _key = dynamic_pointer_cast<SymKey>(key);
	}
		break;
	case CRYPTO_ALG_RSA:
	{
		shared_ptr<PrivKey> _key = dynamic_pointer_cast<PrivKey>(key);
	}
		break;
	case CRYPTO_ALG_ECDH:
	{
		shared_ptr<PrivKey> _key = dynamic_pointer_cast<PrivKey>(key);
	}
		break;
	default:
		printf("unknown alg<%d>\n", alg);
		return false;
	}

	return true;

}
#else
bool KeyCrypto::encrypt(Item *item, Key *key) {
	int alg = key->alg;

	switch(alg) {
	case CRYPTO_ALG_AES:
	{
		SymKey *_key = key;
	}
		break;
	case CRYPTO_ALG_RSA:
	{
		PubKey *_key = key;
	}
		break;
	case CRYPTO_ALG_ECDH:
	{
		PubKey *_key = key;
	}
		break;
	default:
		printf("unknown alg<%d>\n", alg);
		return false;
	}

	return true;
}

bool KeyCrypto::decrypt(Item *item, Key *key) {
	int alg = key->alg;

	switch(alg) {
	case CRYPTO_ALG_AES:
	{
		SymKey *_key = key;
	}
		break;
	case CRYPTO_ALG_RSA:
	{
		PrivKey *_key = key;
	}
		break;
	case CRYPTO_ALG_ECDH:
	{
		PrivKey *_key = key;
	}
		break;
	default:
		printf("unknown alg<%d>\n", alg);
		return false;
	}

	return true;

}
#endif
