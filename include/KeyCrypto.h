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
	bool encrypt(shared_ptr<Item> &item, shared_ptr<Key> &key);
	bool decrypt(shared_ptr<Item> &item, shared_ptr<Key> &key);
};

#endif /* KEYCRYPTO_H_ */
