/*
 * Item.h
 *
 *  Created on: Aug 17, 2015
 *      Author: olic
 */

#ifndef ITEM_H_
#define ITEM_H_

#include <memory>
#include <pthread.h>
#include <string.h>

using std::shared_ptr;
using std::dynamic_pointer_cast;

#define CRYPTO_ALG_AES 1
#define CRYPTO_ALG_RSA 2
#define CRYPTO_ALG_ECDH 3

class AbstractItem {
public:
	pthread_mutex_t mutex;

	unsigned char *buffer;
	unsigned int len;
	AbstractItem();
	AbstractItem(unsigned int len);
	virtual ~AbstractItem();

	unsigned char *alloc(ssize_t len);
	void zeroOut();
};

typedef shared_ptr<AbstractItem> Item;

class Key : public AbstractItem {
public:
	int bits;
	int alg;

	Key(int keyLen, int bits, int alg)
	: AbstractItem(keyLen) {
		this->bits = bits;
		this->alg = alg;
	}
	~Key();
};

typedef shared_ptr<Key> SymKey;
typedef shared_ptr<Key> PubKey;
typedef shared_ptr<Key> PrivKey;

class EncKey : public Key {
public:
	unsigned char auth_tag[16];

	EncKey(int keyLen, int bits, int alg)
	: Key(keyLen, bits, alg) {
		memset(auth_tag, 0, 16);
	};
	~EncKey() { }
};

#endif /* ITEM_H_ */
