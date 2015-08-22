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

#define KEK_TBL_NAME "KEK"

#define KEK_TBL_COL_ALIAS "ALIAS"
#define KEK_TBL_COL_KEK_NAME "KEK_NAME"
#define KEK_TBL_COL_ENCRYPTED_BY "ENCRYPTED_BY"
#define KEK_TBL_COL_KEY "KEY"
#define KEK_TBL_COL_KEY_AUTH_TAG "KEK_AUTH_TAG"

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

#define EMK_TBL_NAME "EMK"

#define EMK_COL_ALIAS "ALIAS"
#define EMK_COL_VERSION "VERSION"
#define EMK_COL_EMK "EMK"
#define EMK_COL_EMK_AUTH_TAG "EMK_AUTH_TAG"
#define EMK_COL_EMKEK "EMKEK"
#define EMK_COL_EMKEK_AUTH_TAG "EMKEK_AUTH_TAG"
#define EMK_COL_SALT "SALT"

class MkStorage : KeyStorage {
public:
	MkStorage(const char *path)
	: KeyStorage(path) {

	}
	virtual ~MkStorage() { }

	bool create();
	bool exist(const char *alias);
	bool store(const char *alias, Key *kek, Token *tok);
};
#endif /* KEYSTORAGE_H_ */
