/*
 * KeyCrypto.h
 *
 *  Created on: Aug 17, 2015
 *      Author: olic
 */

#ifndef KEYCRYPTO_H_
#define KEYCRYPTO_H_

#include "List.h"
#include "Item.h"
#include "native_crypto.h"

class KeyCrypto {
public:
	KeyCrypto();
	virtual ~KeyCrypto();

	void generateKeyPair(int alg,
			PubKey &pubKey, PrivKey &privKey);
#if 0
	bool encrypt(shared_ptr<Item> &item, shared_ptr<AbstractKey> &key);
	bool decrypt(shared_ptr<Item> &item, shared_ptr<AbstractKey> &key);
#else
	EncItem *encrypt(Item *item, Key *key);
	Item *decrypt(EncItem *eitem, Key *key);
#endif
};

#endif /* KEYCRYPTO_H_ */
