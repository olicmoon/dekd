/*
 * KeyStorage.cpp
 *
 *  Created on: Aug 20, 2015
 *      Author: olic
 */

#include "KeyStorage.h"

#include <stdio.h>
#include <stdlib.h>
#include <List.h>

KeyStorage::KeyStorage(const char *path) {
	int rc = sqlite3_open(path, &this->mDb);
	if( rc ){
		printf("Can't open database: %s\n", sqlite3_errmsg(this->mDb));
		sqlite3_close(this->mDb);
		exit(1);
	}

	this->mSqlHelper = shared_ptr<SqlHelper> (new SqlHelper());
}

KeyStorage::~KeyStorage() {
	// TODO Auto-generated destructor stub
	sqlite3_close(this->mDb);
}

bool KekStorage::create() {

	list<shared_ptr<SqlValue>> scheme;
	scheme.push_back(shared_ptr<SqlValue>(new SqlString(KEK_TBL_COL_ALIAS, "TEXT")));
	scheme.push_back(shared_ptr<SqlValue>(new SqlString(KEK_TBL_COL_KEK_NAME, "TEXT")));
	scheme.push_back(shared_ptr<SqlValue>(new SqlString(KEK_TBL_COL_ENCRYPTED_BY, "INTEGER")));
	scheme.push_back(shared_ptr<SqlValue>(new SqlString(KEK_TBL_COL_KEY, "TEXT")));
	scheme.push_back(shared_ptr<SqlValue>(new SqlString(KEK_TBL_COL_KEY_AUTH_TAG, "TEXT")));

	return mSqlHelper->createTbl(mDb, string(KEK_TBL_NAME), scheme);
}

bool KekStorage::exist(const char *alias, string kekName) {
	list<shared_ptr<SqlValue>> where;
	where.push_back(shared_ptr<SqlValue>(new SqlString(KEK_TBL_COL_ALIAS, alias)));
	where.push_back(shared_ptr<SqlValue>(new SqlString(KEK_TBL_COL_KEK_NAME, kekName)));

	list<shared_ptr<SqlValue>> result =
			mSqlHelper->selectRec(mDb, string(KEK_TBL_NAME), where);

	int size = result.size();

	printf("%s : result size %d\n", __func__, size);

	if(size == 0)
		return false;

	return true;
}

bool KekStorage::store(const char *alias, Key *key, Token *tok){
	if(exist(alias, KeyName::getName(key))) {
		printf("Failed to store :: key[%s] already exists for %s\n",
				KeyName::getName(key), alias);
				return false;
	}

	list<shared_ptr<SqlValue>> rec;
	shared_ptr<SerializedItem> sItem;

	if(key->type == KeyType::PUB) {
		// don't encrypt the key
		sItem = key->serialize();

		rec.push_back(shared_ptr<SqlString>(
				new SqlString(KEK_TBL_COL_ALIAS, alias)));
		rec.push_back(shared_ptr<SqlString>(
				new SqlString(KEK_TBL_COL_KEK_NAME, KeyName::getName(key))));
		rec.push_back(shared_ptr<SqlInteger>(
				new SqlInteger(KEK_TBL_COL_ENCRYPTED_BY, CryptAlg::PLAIN)));
		rec.push_back(shared_ptr<SqlString>(
				new SqlString(KEK_TBL_COL_KEY, (const char *)sItem->getItem())));
	} else {
		if(tok->len > 32) {
			printf("Token length cannot be more than 32 bytes [%d]\n", tok->len);
			return false;
		}

		SymKey *symKey = new SymKey(32);
		memcpy(symKey->getData(), tok->getData(), tok->len);

		EncKey *eKey = aes_gcm_encrypt((Item *)key, symKey);
		if(eKey == NULL) {
			printf("Encryption failed!\n");
			delete symKey;
			return false;
		}

		sItem = eKey->serialize();

		rec.push_back(shared_ptr<SqlString>(
				new SqlString(KEK_TBL_COL_ALIAS, alias)));
		rec.push_back(shared_ptr<SqlString>(
				new SqlString(KEK_TBL_COL_KEK_NAME, KeyName::getName(key))));
		rec.push_back(shared_ptr<SqlInteger>(
				new SqlInteger(KEK_TBL_COL_ENCRYPTED_BY, CryptAlg::AES)));
		rec.push_back(shared_ptr<SqlString>(
				new SqlString(KEK_TBL_COL_KEY, (const char *)sItem->getItem())));
		rec.push_back(shared_ptr<SqlString>(
				new SqlString(KEK_TBL_COL_KEY_AUTH_TAG, (const char *)sItem->getAuthTag())));

		delete eKey;
		delete symKey;
	}

	sItem->dump("KekStorage::store - serializedItem");
	return mSqlHelper->insertRec(mDb, KEK_TBL_NAME, rec);
}

Key *KekStorage::retrieve(const char *alias, int alg, int type, Token *tok) {
	const char *kek_name = KeyName::getName(alg, type);
	if(!exist(alias, kek_name)) {
		printf("Failed to retrieve :: key[%s] already exists for %s\n",
				kek_name, alias);
				return NULL;
	}

	list<shared_ptr<SqlValue>> where;
	shared_ptr<SerializedItem> sItem;

	where.push_back(shared_ptr<SqlString> (
			new SqlString(KEK_TBL_COL_ALIAS, alias)));
	where.push_back(shared_ptr<SqlString> (
			new SqlString(KEK_TBL_COL_KEK_NAME, kek_name)));

	list<shared_ptr<SqlValue>> foundRec = mSqlHelper->selectRec(mDb, KEK_TBL_NAME, where);

	string foundItem = "?";
	string foundAuthTag = "?";
	int encryptedBy = CryptAlg::PLAIN;
	for (list<shared_ptr<SqlValue>>::iterator it = foundRec.begin();
			it != foundRec.end(); it++) {
		string key = (*it)->getKey();
		if(key.compare(KEK_TBL_COL_KEY) == 0) {
			foundItem = (dynamic_pointer_cast<SqlString> (*it))->getData();
		} else if(key.compare(KEK_TBL_COL_KEY_AUTH_TAG) == 0) {
			foundAuthTag = (dynamic_pointer_cast<SqlString> (*it))->getData();
		} else if(key.compare(KEK_TBL_COL_ENCRYPTED_BY) == 0) {
			encryptedBy = (dynamic_pointer_cast<SqlInteger> (*it))->getData();
		}
	}

	/**
	 * TODO : we can't use alg from the parameter because it's alg for key type
	 * that can be ECDH or AES. But this serializedItem is only encrypted by AES
	 */
	sItem = shared_ptr<SerializedItem> (
			new SerializedItem(encryptedBy, foundItem.c_str(), foundAuthTag.c_str(), "?"));

	if(encryptedBy == CryptAlg::PLAIN) {
		return (Key *) sItem->deserialize();
	} else if (encryptedBy == CryptAlg::AES) {
		if(tok->len > 32) {
			printf("Token length cannot be more than 32 bytes [%d]\n", tok->len);
			return NULL;
		}

		shared_ptr<SymKey> symKey =
				shared_ptr<SymKey> (new SymKey(32));
		memcpy(symKey->getData(), tok->getData(), tok->len);

		shared_ptr<EncKey>eKey =
				shared_ptr<EncKey> ((EncKey *)sItem->deserialize());

		return (Key *)aes_gcm_decrypt(eKey.get(), symKey.get());
	}

	return NULL;
}

bool MkStorage::create() {

	list<shared_ptr<SqlValue>> scheme;
	scheme.push_back(shared_ptr<SqlValue>(new SqlString(EMK_COL_ALIAS, "TEXT")));
	scheme.push_back(shared_ptr<SqlValue>(new SqlString(EMK_COL_VERSION, "INTEGER")));
	scheme.push_back(shared_ptr<SqlValue>(new SqlString(EMK_COL_EMK, "TEXT")));
	scheme.push_back(shared_ptr<SqlValue>(new SqlString(EMK_COL_EMK_AUTH_TAG, "TEXT")));
	scheme.push_back(shared_ptr<SqlValue>(new SqlString(EMK_COL_EMKEK, "TEXT")));
	scheme.push_back(shared_ptr<SqlValue>(new SqlString(EMK_COL_EMKEK_AUTH_TAG, "TEXT")));
	scheme.push_back(shared_ptr<SqlValue>(new SqlString(EMK_COL_SALT, "TEXT")));

	return mSqlHelper->createTbl(mDb, string(EMK_TBL_NAME), scheme);

	return false;
}

bool MkStorage::exist(const char *alias) {
	list<shared_ptr<SqlValue>> where;
	where.push_back(shared_ptr<SqlValue>(new SqlString(EMK_COL_ALIAS, alias)));

	list<shared_ptr<SqlValue>> result =
			mSqlHelper->selectRec(mDb, string(EMK_TBL_NAME), where);

	int size = result.size();

	printf("%s : result size %d\n", __func__, size);

	if(size == 0)
		return false;

	return true;
}


bool MkStorage::store(const char *alias, Key *kek, Token *tok) {
	if(exist(alias)) {
		printf("Failed to store :: EMK already exists for %s\n",
				alias);
				return false;
	}


	return false;
}






