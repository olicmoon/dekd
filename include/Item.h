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

#define CRYPTO_ALG_PLAIN 0
#define CRYPTO_ALG_AES 1
#define CRYPTO_ALG_RSA 2
#define CRYPTO_ALG_ECDH 3

#define CRYPTO_ITEM_FMT_BIN 0
#define CRYPTO_ITEM_FMT_B64 1

#define CRYPT_ITEM_MAX_LEN 512

class AbstractItem {
protected:
	unsigned char *_buffer;

public:
	pthread_mutex_t mutex;

	unsigned int len = 0;
	unsigned int format = CRYPTO_ITEM_FMT_BIN;
	AbstractItem();
	AbstractItem(unsigned int len);
	AbstractItem(const char *buf, unsigned int len);
	virtual ~AbstractItem();

	virtual shared_ptr<AbstractItem> serialize();
	virtual shared_ptr<AbstractItem> deserialize();
	unsigned char *alloc(ssize_t len);
	void zeroOut();
	void dump(const char* str);

	static void dump(const char *buf, unsigned int len, const char *str);

	unsigned char *getData() {
		return _buffer;
	}
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

static bool inline isAsymAlg(int alg) {
	if((alg == CRYPTO_ALG_RSA) ||
			(alg == CRYPTO_ALG_ECDH))
		return true;
	return false;
}

class EncItem : public AbstractItem {
public:
	unsigned char auth_tag[16];
	int alg;

	EncItem(int keyLen, int alg)
	: AbstractItem(keyLen), alg(alg), _pubKey(NULL) {
		memset(auth_tag, 0, 16);
	}

	EncItem(const char *buf, int keyLen, int alg)
	: AbstractItem(buf, keyLen), alg(alg), _pubKey(NULL) {
		memset(auth_tag, 0, 16);
	}

	EncItem(const char *buf, int keyLen, int alg, PubKey *pk)
	: AbstractItem(buf, keyLen), alg(alg), _pubKey(pk){
		memset(auth_tag, 0, 16);
	}

	void setPubKey(PubKey *pk) {
		_pubKey = pk;
	}

	~EncItem() {
		memset(auth_tag, 0, 16);
		if(_pubKey != NULL)
			delete _pubKey;
	}

	PubKey *getPubKey() {
		return _pubKey;
	}

	/**
	 * Type' 'Item.buffer' 'auth_tag
	 * Type' 'Item.buffer' 'PubKey.buffer
	 */
	virtual shared_ptr<AbstractItem> serialize();
private:
	PubKey *_pubKey;
};

typedef EncItem EncKey;

#endif /* ITEM_H_ */
#include <stdio.h>
