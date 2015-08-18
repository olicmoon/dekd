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


int main(int argc, char **argv) {
	DekdReqCmdListener *reqCl = new DekdReqCmdListener();
	DekdCtlCmdListener *ctlCl = new DekdCtlCmdListener();
	char *sock_path;

	if(argc < 2) {
		printf("Usage : dekd [sock-path]\n");
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

	KeyCrypto *crypto = new KeyCrypto();
	SymKey *key = new SymKey(32, 32*8, CRYPTO_ALG_AES);
	PubKey *pubKey = new PubKey(512, 2048, CRYPTO_ALG_RSA);
	//shared_ptr<PubKey> pubKey(new PubKey(512, 2048, CRYPTO_ALG_RSA));
	//shared_ptr<SymKey> key(new SymKey(32, 32*8, CRYPTO_ALG_AES));

	crypto->encrypt((Item *)key, (Key *)pubKey);

	while(1) {
		ctlCl->sendBroadcast(5, "locked", false);
		sleep(10);
	}

	printf("Dekd exiting\n");
	exit(0);
}
