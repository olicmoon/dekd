/*
 * main.cpp
 *
 *  Created on: Aug 17, 2015
 *      Author: olic
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <Item.h>

#include "DekdCmdListener.h"

#include "KeyCrypto.h"
#include "storage/SqlHelper.h"
#include "storage/KeyStorage.h"

#define TEST_STRING "he first known standardized use of the encoding"
void test_key_crypto() {
	KeyCrypto *crypto = new KeyCrypto();
	PubKey *devPub = new PubKey(CRYPT_ITEM_MAX_LEN, CryptAlg::ECDH);
	PrivKey *devPri = new PrivKey(CRYPT_ITEM_MAX_LEN, CryptAlg::ECDH);

	SymKey *key = new SymKey(TEST_STRING, strlen(TEST_STRING));

	if(ecdh_gen_keypair(devPub, devPri)) {
		printf("ecdh_GenKeyPair() failed.\n");
		exit(1);
	}

	EncItem *eitem = crypto->encrypt((Item *)key, (Key *)devPub);
	eitem->dump("eitem");
	eitem->getPubKey()->dump("eitem::pubKey");

	shared_ptr<SerializedItem> sItem = eitem->serialize();
	delete eitem;

	sItem->dump("echd encrypted");

	SerializedItem *sItem2 =
			new SerializedItem(sItem->getAlg(), sItem->getItem()
					, sItem->getAuthTag(), sItem->getPubKey());

	EncItem *decodedItem = (EncItem *) sItem2->deserialize();
	decodedItem->dump("decodedItem");
	decodedItem->getPubKey()->dump("decodedItem::pubKey");

	Item *result = crypto->decrypt(decodedItem, devPri);
	result->dump("result");

	delete sItem2;
	delete result;

	delete devPub;
	delete devPri;

	delete crypto;
	delete key;
}

#include <sqlite3.h>

void test_sql_helper() {
	sqlite3 *db;
	int rc = sqlite3_open("./test.db", &db);
	if( rc ){
		printf("Can't open database: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		exit(1);
	}

	SqlHelper *helper = new SqlHelper();

	list<shared_ptr<SqlValue>> scheme;
	scheme.push_back(shared_ptr<SqlValue>(new SqlString("name", "TEXT")));
	scheme.push_back(shared_ptr<SqlValue>(new SqlString("age", "INT")));
	scheme.push_back(shared_ptr<SqlValue>(new SqlString("pic", "BLOB")));

	helper->createTbl(db, string("tbl"), scheme);

	list<shared_ptr<SqlValue>> rec;
	rec.push_back(shared_ptr<SqlValue>(new SqlString("name", "olic")));
	rec.push_back(shared_ptr<SqlValue>(new SqlInteger("age", 33)));
	rec.push_back(shared_ptr<SqlValue>(new SqlBlob("pic", "N/A", 3)));
	helper->insertRec(db, string("tbl"), rec);

	rec.clear();
	rec.push_back(shared_ptr<SqlValue>(new SqlString("name", "jiji")));
	rec.push_back(shared_ptr<SqlValue>(new SqlInteger("age", 32)));
	//rec.push_front(shared_ptr<SqlValue>(new SqlBlob("pic", "N/A", 3)));
	helper->insertRec(db, string("tbl"), rec);

	list<shared_ptr<SqlValue>> where;
	where.push_back(shared_ptr<SqlValue>(new SqlString("name", "jiji")));
	list<shared_ptr<SqlValue>> resultRec = helper->selectRec(db, string("tbl"), where);

	string result = "RESULT : ";
	for (list<shared_ptr<SqlValue>>::iterator it = resultRec.begin();
			it != resultRec.end(); it++) {
		int type = (*it)->getType();
		if(type == SQL_TEXT) {
			shared_ptr<SqlString> value = dynamic_pointer_cast<SqlString>(*it);
			result += value->getData() + " ";
		} else if(type == SQL_INT) {
			shared_ptr<SqlInteger> value = dynamic_pointer_cast<SqlInteger>(*it);

			result += std::to_string(value->getData()) + " ";
		}
	}

	printf("%s\n", result.c_str());

	delete helper;
	sqlite3_close(db);
}

#define TEST_PWD "TEST PASSWORD"
#define TEST_ALIAS "knox_100"

void test_kek_storage() {
	KekStorage *kekStorage = new KekStorage("./kek.db");

	Password *pwd = new Password(TEST_PWD, strlen(TEST_PWD));
	SymKey *symKey = new SymKey(TEST_STRING, strlen(TEST_STRING));
	PubKey *devPub = new PubKey(CRYPT_ITEM_MAX_LEN, CryptAlg::ECDH);
	PrivKey *devPri = new PrivKey(CRYPT_ITEM_MAX_LEN, CryptAlg::ECDH);

	if(!kekStorage->create()) {
		printf("%s %d failed\n", __func__, __LINE__);
	}

	if(ecdh_gen_keypair(devPub, devPri)) {
		printf("ecdh_GenKeyPair() failed.\n");
		exit(1);
	}

	if(!kekStorage->store(TEST_ALIAS, symKey, pwd)) {
		printf("%s %d failed\n", __func__, __LINE__); exit(1);
	}
	symKey->dump("stored symKey");

	if(!kekStorage->store(TEST_ALIAS, devPub, pwd)) {
		printf("%s %d failed\n", __func__, __LINE__); exit(1);
	}
	devPub->dump("stored devPub");

	if(!kekStorage->store(TEST_ALIAS, devPri, pwd)) {
		printf("%s %d failed\n", __func__, __LINE__); exit(1);
	}
	devPri->dump("stored devPri");

	SymKey *symKey2 = kekStorage->retrieveSymKey(TEST_ALIAS, pwd);
	symKey2->dump("retrieved symKey");
	PubKey *devPub2 = kekStorage->retrievePubKey(TEST_ALIAS, CryptAlg::ECDH);
	devPub2->dump("retrieved devPub");
	PrivKey *devPri2 = kekStorage->retrievePrivKey(TEST_ALIAS, CryptAlg::ECDH, pwd);
	devPri2->dump("retrieved devPri");

	delete symKey2;
	delete devPub2;
	delete devPri2;
	delete symKey;
	delete devPub;
	delete devPri;
	delete pwd;
	delete kekStorage;
}

int main(int argc, char **argv) {
	DekdReqCmdListener *reqCl = new DekdReqCmdListener();
	DekdCtlCmdListener *ctlCl = new DekdCtlCmdListener();
	char *sock_path;

	if(argc == 1) {
		//test1();
		//test2();
		test_kek_storage();
		exit(1);
	}

	sock_path = argv[1];

	if (reqCl->startListener(sock_path))
	{
		printf("Unable to start DekdReqCmdListener (%s)\n", strerror(errno) );
		exit(1);
	}

	if (ctlCl->startListener(sock_path))
	{
		printf("Unable to start DekdCtlCmdListener (%s)\n", strerror(errno) );
		exit(1);
	}

	while(1) {
		ctlCl->sendBroadcast(5, "locked", false);
		sleep(10);
	}

	printf("Dekd exiting\n");
	exit(0);
}
