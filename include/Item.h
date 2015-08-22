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
using std::string;

#define CRYPTO_ITEM_FMT_BIN 0
#define CRYPTO_ITEM_FMT_B64 1

#define CRYPT_ITEM_MAX_LEN 512

class SerializedItem;

class AbstractItem {
protected:
	unsigned char *_buffer;

public:
	pthread_mutex_t mutex;

	unsigned int len;
	unsigned int format;
	AbstractItem(unsigned int len);
	AbstractItem(const char *buf, unsigned int len);
	virtual ~AbstractItem();

	virtual shared_ptr<SerializedItem> serialize();
	unsigned char *alloc(ssize_t len);
	void zeroOut();
	void dump(const char* str);

	static void dump(const char *buf, unsigned int len, const char *str);

	unsigned char *getData() {
		return _buffer;
	}
};

typedef AbstractItem Item;

class SerializedItem : public AbstractItem {
public:
	SerializedItem(const char *buf);
	SerializedItem(int alg, const char *data,
			const char *tag, const char *pubKey);

	Item *deserialize();

	int getAlg() { return this->_alg; }
	char *getItem() { return this->_item; }
	char *getAuthTag() { return this->_tag; }
	char *getPubKey() { return this->_pubKey; }

	void dump(const char *str) {
		printf("serialized item[%s] \n", str);
		printf("alg:      %d\n", this->_alg);
		printf("item:     %s\n", this->_item);
		printf("auth-tag: %s\n", this->_tag);
		printf("pubKey:   %s\n", this->_pubKey);
	}

private:
	void init();

	int _alg;
	char *_item;
	char *_tag;
	char *_pubKey;
};

typedef Item Password;
typedef Item Token;

class KeyType {
public:
	static const int SYM = 1;
	static const int PUB = 2;
	static const int PRI = 3;
};

class CryptAlg {
public:
	static const int PLAIN 	= 0;
	static const int AES 		= 1;
	static const int ECDH 		= 2;
};

class Key : public AbstractItem {
public:
	int alg;
	int type;

	Key(const char *buf, int keyLen, int alg, int type)
	: AbstractItem(buf, keyLen) {
		this->alg = alg;
		this->type = type;
	}

	Key(int keyLen, int alg, int type)
	: AbstractItem(keyLen) {
		this->alg = alg;
		this->type = type;
	}

	~Key() { }
};

class KeyName {
public:
	static const int SYM			= 10;
	static const int ECDH_PUB		= 11;
	static const int ECDH_PRI		= 12;

	static const char *getName(int alg, int type) {
		if(alg == CryptAlg::AES)
			return "SYM";

		if(alg == CryptAlg::ECDH)
			return (type == KeyType::PUB) ?
					"ECDH_PUB" : "ECDH_PRI";

		return NULL;
	}

	static const char *getName(Key *key) {
		switch(getType(key)) {
		case SYM:
			return "SYM";
		case ECDH_PUB:
			return "ECDH_PUB";
		case ECDH_PRI:
			return "ECDH_PRI";
		}

		return NULL;
	}

private:
	static int getType(Key *key) {
		if(key->alg == CryptAlg::AES) {
			return KeyName::SYM;
		} else if(key->alg == CryptAlg::ECDH) {
			return (key->type == KeyType::PUB) ?
					KeyName::ECDH_PUB : KeyName::ECDH_PRI;
		}

		printf("unknown KekType : alg[%d] keyType[%d]\n", key->alg, key->type);
		return -1;
	}
};

class SymKey : public Key {
public:
	SymKey(const char *buf, int keyLen)
	: Key(buf, keyLen, CryptAlg::AES, KeyType::SYM) {
	}

	SymKey(int keyLen)
	: Key(keyLen, CryptAlg::AES, KeyType::SYM) {
	}
};

class PubKey : public Key {
public:
	PubKey(const char *buf, int keyLen, int alg)
	: Key(buf, keyLen, alg, KeyType::PUB) {
	}

	PubKey(int keyLen, int alg)
	: Key(keyLen, alg, KeyType::PUB) {
	}
};

class PrivKey : public Key {
public:
	PrivKey(const char *buf, int keyLen, int alg)
	: Key(buf, keyLen, alg, KeyType::PRI) {
	}

	PrivKey(int keyLen, int alg)
	: Key(keyLen, alg, KeyType::PRI) {
	}
};

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
	virtual shared_ptr<SerializedItem> serialize();
private:
	PubKey *_pubKey;
};

typedef EncItem EncKey;

#endif /* ITEM_H_ */
#include <stdio.h>
