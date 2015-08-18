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
	bool encrypt(Item *item, Key *key);
	bool decrypt(Item *item, Key *key);
#endif
};

#endif /* KEYCRYPTO_H_ */
