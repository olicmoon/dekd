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

#define CRYPTO_ITEM_FMT_BIN 1
#define CRYPTO_ITEM_FMT_B64 1

#define CRYPT_ITEM_MAX_LEN 512

class AbstractItem {
public:
	pthread_mutex_t mutex;

	unsigned char *buffer;
	unsigned int len;
	unsigned int format;
	AbstractItem();
	AbstractItem(unsigned int len);
	AbstractItem(const char *buf, unsigned int len);
	virtual ~AbstractItem();

	unsigned char *alloc(ssize_t len);
	void zeroOut();
	void dump(const char* str);

	static void dump(const char *buf, unsigned int len, const char *str);
};

typedef AbstractItem Item;

typedef Item Password;
typedef Item Token;

class Key : public AbstractItem {
public:
	int bits;
	int alg;

	Key(const char *buf, int keyLen, int bits, int alg)
	: AbstractItem(buf, keyLen) {
		this->bits = bits;
		this->alg = alg;
	}

	Key(int keyLen, int bits, int alg)
	: AbstractItem(keyLen) {
		this->bits = bits;
		this->alg = alg;
	}

	Key(int bits, int alg)
	: AbstractItem() {
		this->bits = bits;
		this->alg = alg;
	}
	~Key() { }
};

typedef Key SymKey;
typedef Key PubKey;
typedef Key PrivKey;

class EncItem : public AbstractItem {
public:
	unsigned char auth_tag[16];
	shared_ptr<PubKey> pubKey;
	int alg;

	EncItem(int keyLen, int alg)
	: AbstractItem(keyLen), alg(alg) {
		memset(auth_tag, 0, 16);
	}

	EncItem(const char *buf, int keyLen, int alg)
	: AbstractItem(buf, keyLen), alg(alg) {
		memset(auth_tag, 0, 16);
	}
	~EncItem() {
		memset(auth_tag, 0, 16);
	}
};

typedef EncItem EncKey;

class DhPayload {
public:
	shared_ptr<EncItem> eitem;
	shared_ptr<PubKey> dataPubKey;
	DhPayload(shared_ptr<EncItem> s, shared_ptr<PubKey> d) {
		this->eitem = s;
		this->dataPubKey = d;
	}

	~DhPayload() { }
};

#endif /* ITEM_H_ */
