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

#include <KeyCrypto.h>
#include <Item.h>

#include "DekdCmdListener.h"

void test1() {
	PubKey *devPub = new PubKey(CRYPT_ITEM_MAX_LEN, 2048, CRYPTO_ALG_ECDH);
	PrivKey *devPri = new PrivKey(CRYPT_ITEM_MAX_LEN, 2048, CRYPTO_ALG_ECDH);

	KeyCrypto *crypto = new KeyCrypto();
	SymKey *key = new SymKey("olic", 32, 32*8, CRYPTO_ALG_AES);

	if(ecdh_gen_keypair(devPub, devPri)) {
		printf("ecdh_GenKeyPair() failed.\n");
		exit(1);
	}

	EncItem *eitem = crypto->encrypt((Item *)key, (Key *)devPub);
	eitem->dump("eitem");
	eitem->getPubKey()->dump("eitem::pubKey");

	{
		printf("\n\n=======================================\n");
		PubKey *pk = eitem->getPubKey();

		char *tmp = (char *)malloc(CRYPT_ITEM_MAX_LEN);
		char *tmp2 = (char *)malloc(CRYPT_ITEM_MAX_LEN);
		Item::dump((char *)pk->getData(), pk->len, "plain");

		Base64Encode(pk->getData(), pk->len, &tmp);
		Item::dump(tmp, strlen(tmp), "encoded");
		printf ("encoded : %s\n", tmp);
		int len;
		Base64Decode(tmp, (unsigned char **)&tmp2, (size_t *)&len);
		Item::dump(tmp2, len, "decoded");
	}
	shared_ptr<Item> serializedItem = eitem->serialize();
	delete eitem;

	//serializedItem->dump("serializedItem");

	shared_ptr<EncItem> decodedItem =
			dynamic_pointer_cast<EncItem>(serializedItem->deserialize());
	decodedItem->dump("decodedItem");
	decodedItem->getPubKey()->dump("decodedItem::pubKey");

	Item *result = crypto->decrypt(decodedItem.get(), devPri);
	if(result) result->dump("result");

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
