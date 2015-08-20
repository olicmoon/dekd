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

#include "KeyCrypto.h"
#include "DekdCmdListener.h"

#define TEST_STRING "he first known standardized use of the encoding"
void test1() {
	KeyCrypto *crypto = new KeyCrypto();
	PubKey *devPub = new PubKey(CRYPT_ITEM_MAX_LEN, 2048, CRYPTO_ALG_ECDH);
	PrivKey *devPri = new PrivKey(CRYPT_ITEM_MAX_LEN, 2048, CRYPTO_ALG_ECDH);

	SymKey *key = new SymKey(TEST_STRING, strlen(TEST_STRING), 32*8, CRYPTO_ALG_AES);

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

	shared_ptr<EncItem> decodedItem =
			dynamic_pointer_cast<EncItem>(sItem2->deserialize());
	decodedItem->dump("decodedItem");
	decodedItem->getPubKey()->dump("decodedItem::pubKey");

	Item *result = crypto->decrypt(decodedItem.get(), devPri);
	result->dump("result");

	delete sItem2;
	delete result;

	delete devPub;
	delete devPri;

	delete crypto;
	delete key;
}

int main(int argc, char **argv) {
	DekdReqCmdListener *reqCl = new DekdReqCmdListener();
	DekdCtlCmdListener *ctlCl = new DekdCtlCmdListener();
	char *sock_path;

	if(argc == 1) {
		test1();
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
