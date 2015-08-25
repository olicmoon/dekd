/*
 * KeyCrypto.cpp
 *
 *  Created on: Aug 17, 2015
 *      Author: olic
 */

#include "KeyCrypto.h"

KeyCryptoManager *KeyCryptoManager::_instance = new KeyCryptoManager();

KeyCrypto::KeyCrypto(string alias) {
	printf("Creating KeyCrypto %s\n", alias.c_str());

	this->_alias = alias;

	_pubKey = NULL;
	_privKey = NULL;
	_symKey = NULL;
}

KeyCrypto::~KeyCrypto() {
	printf("Destroying KeyCrypto %s\n", _alias.c_str());
	if(_pubKey != NULL) delete _pubKey;
	if(_privKey != NULL) delete _privKey;
	if(_symKey != NULL) delete _symKey;
}

EncItem *KeyCrypto::encrypt(Item *item) {
	if(_symKey)
		return aes_gcm_encrypt(item, _symKey);
	else if(_pubKey)
		return ecdh_encrypt(item, (PubKey *)_pubKey);

	printf("KeyCrypto(%s)::encrypt, no key available\n", _alias.c_str());
	return NULL;
}

Item *KeyCrypto::decrypt(EncItem *eitem) {
	switch(eitem->encBy) {
	case CryptAlg::AES:
		if(_symKey)
			return aes_gcm_decrypt(eitem, _symKey);
		printf("KeyCrypto(%s)::decrypt, sym-key not available\n", _alias.c_str());
		break;
	case CryptAlg::ECDH:
		if(_privKey)
			return ecdh_decrypt(eitem, _privKey);
		printf("KeyCrypto(%s)::decrypt, priv-key not available\n", _alias.c_str());
		break;
	default:
		printf("unknown alg<%d>\n", eitem->encBy);
		return NULL;
	}

	return NULL;

}
