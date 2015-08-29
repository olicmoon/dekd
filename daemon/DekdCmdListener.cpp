/*
 * DekdCmdListener.cpp
 *
 *  Created on: Aug 17, 2015
 *      Author: olic
 */

/**
 * [socket] [cmd] [sub-cmd] [args...]
 * response code :
 * 200 : success
 * 400 : error
 */

#include "DekdCmdListener.h"

#include <stdio.h>
#include <string.h>
#include <ResponseCode.h>

void dump_args(int argc, char **argv) {
	char buffer[4096];
	char *p = buffer;

	memset(buffer, 0, sizeof(buffer));
	int i;
	for (i = 0; i < argc; i++) {
		unsigned int len = strlen(argv[i]) + 1; // Account for space
		if (((p - buffer) + len) < (sizeof(buffer)-1)) {
			char tmp[8];
			sprintf(tmp, "[%d]", i);
			strcat(p, tmp);
			p+= strlen(tmp);
			strcpy(p, argv[i]);
			p+= strlen(argv[i]);
			if (i != (argc -1)) {
				*p++ = ' ';
			}
		}
	}
	printf("\n\tCMD > %s \n", buffer);
}

DekdReqCmdListener::DekdReqCmdListener() :
	FrameworkListener("dekd_req", true) {
	registerCmd(new EncCmd());
}

DekdReqCmdListener::EncCmd::EncCmd()
: DekdCommand("enc")
{

}

int DekdReqCmdListener::EncCmd::runCommand(SocketClient *c,
		int argc, char ** argv) {
	dump_args(argc, argv);
	if(argc < 3) {
		printf("Usage : [req] [cmd-code] [alias] ...\n");
		RESPONSE(c, ResponseCode::CommandSyntaxError, "lack of argc");
		return -1;
	}

	int cmdCode = atoi(argv[1]);
	char *alias = argv[2];

	KeyCrypto *kc = KeyCryptoManager::getInstance()->getKeyCrypto(alias);
	if(kc == NULL) {
		RESPONSE(c, ResponseCode::CommandNotFound, "not found");
		return -1;
	}

	switch(cmdCode) {
	case CommandCode::CommandEncrypt:
	{
		if(argc < 5) {
			RESPONSE(c, ResponseCode::CommandSyntaxError, "failed");
			return -1;
		}

		char *tmp;
		size_t len;
		int alg =  atoi(argv[3]);
		char *pItem = argv[4];
		if(!Base64Decode(pItem, (unsigned char **)&tmp, &len)) {
			printf("base64 decode failed pItem::%s \n", pItem);
			RESPONSE(c, ResponseCode::CommandParameterError, "failed");
			return -1;
		}

		shared_ptr<Item> item(new Item(tmp, len));

		shared_ptr<EncItem> eitem(kc->encrypt(item.get()));
		free(tmp);

		shared_ptr<SerializedItem> sItem(eitem->serialize());

		sItem->dump("encrypted item");
		RESPONSE(c, ResponseCode::CommandOkay, sItem->toString().c_str());
		break;
	}
	case CommandCode::CommandDecrypt:
	{
		if(argc < 5) {
			RESPONSE(c, ResponseCode::CommandSyntaxError, "failed");
			return -1;
		}
		int alg =  atoi(argv[3]);
		char *item = argv[4];
		char *tag = NULL;
		char *pubKey = NULL;
		char *salt = NULL;

		shared_ptr<SerializedItem> sItem;
		switch(alg) {
		case CryptAlg::PLAIN:
		{
			RESPONSE(c, ResponseCode::CommandParameterError, "can't decrypt plain text");
			return -1;
		}
		case CryptAlg::AES:
		{
			if(argc < 6) {
				RESPONSE(c, ResponseCode::CommandSyntaxError, "failed");
				return -1;
			}
			tag = argv[5];
			sItem = shared_ptr<SerializedItem> (new SerializedItem(alg, item, tag, "?"));
		}
		case CryptAlg::ECDH:
		{
			if(argc < 7) {
				RESPONSE(c, ResponseCode::CommandSyntaxError, "failed");
				return -1;
			}
			tag = argv[5];
			pubKey = argv[6];
			sItem = shared_ptr<SerializedItem> (new SerializedItem(alg, item, tag, pubKey));
			break;
		}
		case CryptAlg::PBKDF:
		{
			if(argc < 7) {
				RESPONSE(c, ResponseCode::CommandSyntaxError, "failed");
				return -1;
			}

			tag = argv[5];
			salt = argv[6];
			sItem = shared_ptr<SerializedItem> (new SerializedItem(alg, item, tag, salt));
			break;
		}
		default:
			RESPONSE(c, ResponseCode::CommandFailed, "unknown alg");
			break;
		}

		shared_ptr<EncKey> ekey = shared_ptr<EncKey> ((EncKey *) sItem->deserialize());

		Item *result = kc->decrypt(ekey.get());

		if(result == NULL) {
			RESPONSE(c, ResponseCode::CommandFailed, "failed");
		} else {
			shared_ptr<SerializedItem> sResult(result->serialize());
			RESPONSE(c, ResponseCode::CommandOkay, sResult->toString().c_str());
		}
	}

	}

	return 0;
}

DekdCtlCmdListener::DekdCtlCmdListener() :
		FrameworkListener("dekd_ctl", true) {
	registerCmd(new CtlCmd());

	MkStorage::getInstance()->create();
	KekStorage::getInstance()->create();
}

DekdCtlCmdListener::CtlCmd::CtlCmd()
: DekdCommand("ctl") {

}

int DekdCtlCmdListener::CtlCmd::runCommand(SocketClient *c,
		int argc, char ** argv) {
	dump_args(argc, argv);
	if(argc < 3) {
		printf("Usage : [ctl] [cmd-code] [alias] ...\n");
		RESPONSE(c, ResponseCode::CommandSyntaxError, "lack of argc");
		return -1;
	}

	int cmdCode = atoi(argv[1]);
	char *alias = argv[2];

	KeyCryptoManager *keyCryptoManager = KeyCryptoManager::getInstance();
	MkStorage *mkStorage = MkStorage::getInstance();
	KekStorage *kekStorage = KekStorage::getInstance();

	switch(cmdCode) {
	case CommandCode::CommandBoot:
	{
		keyCryptoManager->createKeyCrypto(alias);
		KeyCrypto *kc = keyCryptoManager->getKeyCrypto(alias);
		if(kc == NULL) {
			RESPONSE(c, ResponseCode::CommandNotFound, "not found");
			return -1;
		}

		PubKey *pubKey =
				kekStorage->retrievePubKey(alias, CryptAlg::ECDH);

		kc->setPubKey(pubKey);
		kc->dump();
		RESPONSE(c, ResponseCode::CommandOkay, "booted");
		break;
	}
	case CommandCode::CommandCreateProfile:
	{
		if(keyCryptoManager->exists(alias)) {
			RESPONSE(c, ResponseCode::CommandFailed, "already exists");
			return -1;
		}

		if(argc < 4) {
			printf("Usage : [ctl] [create] [alias] [pwd]\n");
			RESPONSE(c, ResponseCode::CommandSyntaxError, "lack of argc");
			return -1;
		}

		keyCryptoManager->createKeyCrypto(alias);
		KeyCrypto *kc = keyCryptoManager->getKeyCrypto(alias);
		if(kc == NULL) {
			RESPONSE(c, ResponseCode::CommandNotFound, "not found");
			return -1;
		}

		char *pwd = argv[3];

		char *tmp;
		size_t len;
		bool rc = Base64Decode(pwd, (unsigned char **)&tmp, &len);
		if(!rc || len <= 0) {
			printf("base64 decode failed");
			RESPONSE(c, ResponseCode::CommandParameterError, "failed");
			return -1;
		}

		printf("Storing emk...\n");
		shared_ptr<Token> tok = shared_ptr<Token>(new Token(tmp, len));
		shared_ptr<SymKey> mk = shared_ptr<SymKey>(generateSymKey());
		tok->dump("tok");
		mk->dump("mk");
		if(!mkStorage->store(alias, mk.get(), tok.get())) {
			printf("Failed to store EMK");
			RESPONSE(c, ResponseCode::CommandFailed, "failed");
			return -1;
		}

		printf("Storing emkek...\n");
		PubKey *devPub = new PubKey(CRYPT_ITEM_MAX_LEN, CryptAlg::ECDH);
		PrivKey *devPri = new PrivKey(CRYPT_ITEM_MAX_LEN, CryptAlg::ECDH);
		if(ecdh_gen_keypair(devPub, devPri)) {
			printf("ecdh_GenKeyPair() failed.\n");
			exit(1);
		}

		SymKey *symKey = generateSymKey();

		printf("Storing kek...\n");

		if(!kekStorage->store(alias, symKey, mk.get())) {
			printf("%s %d failed\n", __func__, __LINE__); exit(1);
		}
		symKey->dump("stored symKey");

		if(!kekStorage->store(alias, devPub, mk.get())) {
			printf("%s %d failed\n", __func__, __LINE__); exit(1);
		}
		devPub->dump("stored devPub");

		if(!kekStorage->store(alias, devPri, mk.get())) {
			printf("%s %d failed\n", __func__, __LINE__); exit(1);
		}
		devPub->dump("stored devPri");

		kc->setPubKey(devPub);
		kc->dump();
		delete devPri;
		delete symKey;

		RESPONSE(c, ResponseCode::CommandOkay, "added");
		break;
	}
	case CommandCode::CommandDeleteProfile:
	{
		keyCryptoManager->clrKeyCrypto(alias);
		kekStorage->remove(alias);
		mkStorage->remove(alias);
		RESPONSE(c, ResponseCode::CommandOkay, "removed");
		break;
	}
	case CommandCode::CommandLock:
	{
		KeyCrypto *kc = keyCryptoManager->getKeyCrypto(alias);
		if(kc == NULL) {
			RESPONSE(c, ResponseCode::CommandNotFound, "not found");
			return -1;
		}

		kc->clrPrivKey();
		kc->clrSymKey();
		kc->dump();
		RESPONSE(c, ResponseCode::CommandOkay, "locked");
		break;
	}
	case CommandCode::CommandUnlock:
	{
		KeyCrypto *kc = keyCryptoManager->getKeyCrypto(alias);
		if(kc == NULL) {
			RESPONSE(c, ResponseCode::CommandNotFound, "not found");
			return -1;
		}

		if(argc < 4) {
			printf("Usage : [ctl] [unlock] [alias] [pwd]\n");
			RESPONSE(c, ResponseCode::CommandSyntaxError, "lack of argc");
			return -1;
		}

		char *pwd = argv[3];

		char *tmp;
		size_t len;
		bool rc = Base64Decode(pwd, (unsigned char **)&tmp, &len);
		if(!rc || len <= 0) {
			printf("base64 decode failed");
			RESPONSE(c, ResponseCode::CommandParameterError, "failed");
			return -1;
		}

		printf("Storing emk...\n");
		shared_ptr<Token> tok = shared_ptr<Token>(new Token(tmp, len));
		shared_ptr<SymKey> mk = shared_ptr<SymKey>(
				mkStorage->retrieve(alias, tok.get()));
		tok->dump("tok");
		if(mk == NULL) {
			printf("Failed to retrieve MK");
			RESPONSE(c, ResponseCode::CommandFailed, "failed");
			return -1;
		}
		mk->dump("mk");

		PrivKey *privKey =
				kekStorage->retrievePrivKey(alias, CryptAlg::ECDH, mk.get());
		SymKey *symKey =
				kekStorage->retrieveSymKey(alias, mk.get());

		kc->setPrivKey(privKey);
		kc->setSymKey(symKey);
		kc->dump();
		RESPONSE(c, ResponseCode::CommandOkay, "unlocked");
		break;
	}
	default:
		printf("unknown command\n");
		RESPONSE(c, ResponseCode::CommandNotFound, "unknown command");
	}

	return 0;
}
