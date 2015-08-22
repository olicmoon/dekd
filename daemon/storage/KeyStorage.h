/*
 * KeyStorage.h
 *
 *  Created on: Aug 20, 2015
 *      Author: olic
 */

#ifndef KEYSTORAGE_H_
#define KEYSTORAGE_H_

#include <sqlite3.h>

#include <Item.h>
#include <native_crypto.h>
#include "SqlHelper.h"

class KeyStorage {
public:
	KeyStorage(const char *path);
	virtual ~KeyStorage();

protected:
	sqlite3 *mDb;
	shared_ptr<SqlHelper> mSqlHelper;
};

class KekStorage : KeyStorage {
public:
	KekStorage(const char *path)
	: KeyStorage(path) {

	}
	virtual ~KekStorage() { }

	bool create();
	bool exist(const char *alias, string kekName);
	bool store(const char *alias, Key *kek, Token *tok);

	SymKey *retrieveSymKey(const char *alias, Token *tok) {
		return (SymKey *)retrieve(alias, CryptAlg::AES, KeyType::SYM, tok);
	}
	PubKey *retrievePubKey(const char *alias, int alg) {
		return (PubKey *)retrieve(alias, alg, KeyType::PUB, NULL);
	}
	PrivKey *retrievePrivKey(const char *alias, int alg, Token *tok) {
		return (PrivKey *)retrieve(alias, alg, KeyType::PRI, tok);
	}
private:
	Key *retrieve(const char *alias, int alg, int type, Token *tok);
};
#endif /* KEYSTORAGE_H_ */
