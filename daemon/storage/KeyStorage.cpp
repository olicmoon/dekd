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

KeyStorage::KeyStorage(string path) {
	printf("%s created :: opening DB %s\n", __func__, path.c_str());
	int rc = sqlite3_open(path.c_str(), &this->mDb);
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

KekStorage *KekStorage::_instance = NULL;

bool KekStorage::create() {

	list<shared_ptr<SqlValue>> scheme;
	scheme.push_back(shared_ptr<SqlValue>(new SqlString(KEK_COL_ALIAS, "TEXT")));
	scheme.push_back(shared_ptr<SqlValue>(new SqlString(KEK_COL_KEK_NAME, "TEXT")));
	scheme.push_back(shared_ptr<SqlValue>(new SqlString(KEK_COL_KEK_TYPE, "INTEGER")));
	scheme.push_back(shared_ptr<SqlValue>(new SqlString(KEK_COL_ENCRYPTED_BY, "INTEGER")));
	scheme.push_back(shared_ptr<SqlValue>(new SqlString(KEK_COL_EKEK, "TEXT")));
	scheme.push_back(shared_ptr<SqlValue>(new SqlString(KEK_COL_AUTH_TAG, "TEXT")));

	return mSqlHelper->createTbl(mDb, string(KEK_TBL_NAME), scheme);
}

bool KekStorage::exist(string alias, string kekName) {
	list<shared_ptr<SqlValue>> where;
	where.push_back(shared_ptr<SqlValue>(new SqlString(KEK_COL_ALIAS, alias)));
	where.push_back(shared_ptr<SqlValue>(new SqlString(KEK_COL_KEK_NAME, kekName)));

	list<shared_ptr<SqlRecord>> result =
			mSqlHelper->selectRec(mDb, string(KEK_TBL_NAME), where);

	int size = result.size();

	printf("%s : result size %d\n", __func__, size);

	if(size == 0)
		return false;

	return true;
}

bool KekStorage::store(string alias, Key *key, Token *tok){
	if(exist(alias, KeyName::getName(key))) {
		printf("Failed to store :: key[%s] already exists for %s\n",
				KeyName::getName(key), alias.c_str());
				return false;
	}

	shared_ptr<SqlRecord> rec(new SqlRecord());
	shared_ptr<SerializedItem> sItem;

	if(key->type == KeyType::PUB) {
		// don't encrypt the key
		sItem = key->serialize();

		rec->push(shared_ptr<SqlString>(
				new SqlString(KEK_COL_ALIAS, alias)));
		rec->push(shared_ptr<SqlString>(
				new SqlString(KEK_COL_KEK_NAME, KeyName::getName(key))));
		rec->push(shared_ptr<SqlInteger>(
				new SqlInteger(KEK_COL_KEK_TYPE, KeyType::PUB)));
		rec->push(shared_ptr<SqlInteger>(
				new SqlInteger(KEK_COL_ENCRYPTED_BY, CryptAlg::PLAIN)));
		rec->push(shared_ptr<SqlString>(
				new SqlString(KEK_COL_EKEK, (string )sItem->getItem())));
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

		rec->push(shared_ptr<SqlString>(
				new SqlString(KEK_COL_ALIAS, alias)));
		rec->push(shared_ptr<SqlString>(
				new SqlString(KEK_COL_KEK_NAME, KeyName::getName(key))));
		rec->push(shared_ptr<SqlInteger>(
				new SqlInteger(KEK_COL_KEK_TYPE, key->type)));
		rec->push(shared_ptr<SqlInteger>(
				new SqlInteger(KEK_COL_ENCRYPTED_BY, CryptAlg::AES)));
		rec->push(shared_ptr<SqlString>(
				new SqlString(KEK_COL_EKEK, (string )sItem->getItem())));
		rec->push(shared_ptr<SqlString>(
				new SqlString(KEK_COL_AUTH_TAG, (string )sItem->getAuthTag())));

		delete eKey;
		delete symKey;
	}

	sItem->dump("KekStorage::store - serializedItem");
	bool rc = mSqlHelper->insertRec(mDb, KEK_TBL_NAME, rec);

	return rc;
}

bool KekStorage::remove(string alias) {
	list<shared_ptr<SqlValue>> where;

	where.push_back(shared_ptr<SqlString> (
			new SqlString(KEK_COL_ALIAS, alias)));
	return mSqlHelper->deleteRec(mDb, KEK_TBL_NAME, where);
}

list<shared_ptr<SqlRecord>> KekStorage::getAllKek() {
	list<shared_ptr<SqlValue>> where;
	list<shared_ptr<SqlRecord>> foundRec =
			mSqlHelper->selectRec(mDb, KEK_TBL_NAME, where);

	return foundRec;
}

Key *KekStorage::retrieve(string alias, int alg, int type, Token *tok) {
	string kek_name = KeyName::getName(alg, type);
	if(!exist(alias, kek_name)) {
		printf("Failed to retrieve :: key[%s] doesn't exist for %s\n",
				kek_name.c_str(), alias.c_str());
				return NULL;
	}

	list<shared_ptr<SqlValue>> where;
	shared_ptr<SerializedItem> sItem;

	where.push_back(shared_ptr<SqlString> (
			new SqlString(KEK_COL_ALIAS, alias)));
	where.push_back(shared_ptr<SqlString> (
			new SqlString(KEK_COL_KEK_NAME, kek_name)));

	list<shared_ptr<SqlRecord>> foundRecords =
			mSqlHelper->selectRec(mDb, KEK_TBL_NAME, where);

	string foundItem = "?";
	string foundAuthTag = "?";
	int encryptedBy = CryptAlg::PLAIN;
	for (list<shared_ptr<SqlRecord>>::iterator it = foundRecords.begin();
			it != foundRecords.end(); it++) {
		list<shared_ptr<SqlValue>> values = (*it)->getValues();
		for (list<shared_ptr<SqlValue>>::iterator it = values.begin();
				it != values.end(); it++) {
			string key = (*it)->getKey();
			if(key.compare(KEK_COL_EKEK) == 0) {
				foundItem = (dynamic_pointer_cast<SqlString> (*it))->getData();
			} else if(key.compare(KEK_COL_AUTH_TAG) == 0) {
				foundAuthTag = (dynamic_pointer_cast<SqlString> (*it))->getData();
			} else if(key.compare(KEK_COL_ENCRYPTED_BY) == 0) {
				encryptedBy = (dynamic_pointer_cast<SqlInteger> (*it))->getData();
			}
		}
	}

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

MkStorage *MkStorage::_instance = NULL;

bool MkStorage::create() {

	list<shared_ptr<SqlValue>> scheme;
	scheme.push_back(shared_ptr<SqlValue>(new SqlString(EMK_COL_ALIAS, "TEXT")));
	scheme.push_back(shared_ptr<SqlValue>(new SqlString(EMK_COL_EMK, "TEXT")));
	scheme.push_back(shared_ptr<SqlValue>(new SqlString(EMK_COL_EMK_AUTH_TAG, "TEXT")));
	scheme.push_back(shared_ptr<SqlValue>(new SqlString(EMK_COL_EMKEK, "TEXT")));
	scheme.push_back(shared_ptr<SqlValue>(new SqlString(EMK_COL_EMKEK_AUTH_TAG, "TEXT")));
	scheme.push_back(shared_ptr<SqlValue>(new SqlString(EMK_COL_SALT, "TEXT")));

	return mSqlHelper->createTbl(mDb, string(EMK_TBL_NAME), scheme);

	return false;
}

bool MkStorage::exist(string alias) {
	list<shared_ptr<SqlValue>> where;
	where.push_back(shared_ptr<SqlValue>(new SqlString(EMK_COL_ALIAS, alias)));

	list<shared_ptr<SqlRecord>> result =
			mSqlHelper->selectRec(mDb, string(EMK_TBL_NAME), where);

	int size = result.size();

	printf("%s : result size %d\n", __func__, size);

	if(size == 0)
		return false;

	return true;
}

bool MkStorage::store(string alias, SymKey *mk, Token *tok) {
	if(exist(alias)) {
		printf("Failed to store :: EMK already exists for %s\n",
				alias.c_str());
				return false;
	}

	EncItem *payload = pbkdf_create_mkek(tok);
	SymKey *mkek = pbkdf_derive_mkek(payload, tok);
	EncKey *emk = aes_gcm_encrypt(mk, mkek);

	shared_ptr<SerializedItem> sEmk = emk->serialize();
	shared_ptr<SerializedItem> sPayload = payload->serialize();
	sEmk->dump("emk");
	sPayload->dump("payload");

	delete payload;
	delete mkek;
	delete emk;

	shared_ptr<SqlRecord> rec(new SqlRecord());
	rec->push(shared_ptr<SqlValue>(new SqlString(EMK_COL_ALIAS, alias)));
	rec->push(shared_ptr<SqlValue>(new SqlString(EMK_COL_EMK, sEmk->getItem())));
	rec->push(shared_ptr<SqlValue>(new SqlString(EMK_COL_EMK_AUTH_TAG, sEmk->getAuthTag())));
	rec->push(shared_ptr<SqlValue>(new SqlString(EMK_COL_EMKEK, sPayload->getItem())));
	rec->push(shared_ptr<SqlValue>(new SqlString(EMK_COL_EMKEK_AUTH_TAG, sPayload->getAuthTag())));
	rec->push(shared_ptr<SqlValue>(new SqlString(EMK_COL_SALT, sPayload->getSalt())));

	return mSqlHelper->insertRec(mDb, EMK_TBL_NAME, rec);
}

SymKey *MkStorage::retrieve(string alias, Token *tok) {
	if(!exist(alias)) {
		printf("Failed to retrieve :: MK doesn't exist for %s\n",
				alias.c_str());
				return NULL;
	}

	list<shared_ptr<SqlValue>> where;

	where.push_back(shared_ptr<SqlString> (
			new SqlString(EMK_COL_ALIAS, alias)));

	list<shared_ptr<SqlRecord>> foundRecords = mSqlHelper->selectRec(mDb, EMK_TBL_NAME, where);

	string foundEmk = "?";
	string foundEmkAuthTag = "?";
	string foundEmkek = "?";
	string foundEmkekAuthTag = "?";
	string foundSalt = "?";
	for (list<shared_ptr<SqlRecord>>::iterator it = foundRecords.begin();
			it != foundRecords.end(); it++) {
		list<shared_ptr<SqlValue>> values = (*it)->getValues();

		for (list<shared_ptr<SqlValue>>::iterator it = values.begin();
				it != values.end(); it++) {
			string key = (*it)->getKey();
			if(key.compare(EMK_COL_EMK) == 0) {
				foundEmk = (dynamic_pointer_cast<SqlString> (*it))->getData();
			} else if(key.compare(EMK_COL_EMK_AUTH_TAG) == 0) {
				foundEmkAuthTag = (dynamic_pointer_cast<SqlString> (*it))->getData();
			} else if(key.compare(EMK_COL_EMKEK) == 0) {
				foundEmkek = (dynamic_pointer_cast<SqlString> (*it))->getData();
			} else if(key.compare(EMK_COL_EMKEK_AUTH_TAG) == 0) {
				foundEmkekAuthTag = (dynamic_pointer_cast<SqlString> (*it))->getData();
			} else if(key.compare(EMK_COL_SALT) == 0) {
				foundSalt = (dynamic_pointer_cast<SqlString> (*it))->getData();
			}
		}
	}

	shared_ptr<SerializedItem> sEmk = shared_ptr<SerializedItem> (
			new SerializedItem(CryptAlg::AES,
					foundEmk.c_str(), foundEmkAuthTag.c_str(), "?"));
	sEmk->dump("retrieved emk");
	shared_ptr<SerializedItem> sEmkek = shared_ptr<SerializedItem> (
			new SerializedItem(CryptAlg::PBKDF,
					foundEmkek.c_str(), foundEmkekAuthTag.c_str(), foundSalt.c_str()));
	sEmkek->dump("retrieved emkek");

	EncItem *emk = (EncItem *)sEmk->deserialize();
	EncItem *emkek = (EncItem *)sEmkek->deserialize();

	SymKey *dk = pbkdf_derive_mkek(emkek, tok);
	SymKey *mk = (SymKey *)aes_gcm_decrypt(emk, dk);

	delete emk;
	delete emkek;
	delete dk;

	return mk;
}

bool MkStorage::remove(string alias) {
	list<shared_ptr<SqlValue>> where;
	where.push_back(shared_ptr<SqlValue>(new SqlString(EMK_COL_ALIAS, alias)));

	return mSqlHelper->deleteRec(mDb, string(EMK_TBL_NAME), where);
}

