/*
 * KeyCrypto.h
 *
 *  Created on: Aug 17, 2015
 *      Author: olic
 */

#ifndef KEYCRYPTO_H_
#define KEYCRYPTO_H_

#include <List.h>
#include <Item.h>
#include <native_crypto.h>

class KeyCrypto {
public:
	KeyCrypto();
	virtual ~KeyCrypto();

	EncItem *encrypt(Item *item, Key *key);
	Item *decrypt(EncItem *eitem, Key *key);

private:
	PubKey *pubKey;
	PrivKey *privKey;
	SymKey *symKey;
};

#endif /* KEYCRYPTO_H_ */
