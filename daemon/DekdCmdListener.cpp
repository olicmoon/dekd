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

DekdReqCmdListener::DekdReqCmdListener(KeyCrypto *kc) :
	FrameworkListener("dekd_req", true) {
	registerCmd(new EncCmd());

	keyCrypto = kc;
}

DekdReqCmdListener::EncCmd::EncCmd()
: DekdCommand("enc")
{

}

int DekdReqCmdListener::EncCmd::runCommand(SocketClient *c,
		int argc, char ** argv) {
	int cmdCode = atoi(argv[1]);
	dump_args(argc, argv);

	if(cmdCode == CommandCode::CommandEncrypt) {
		if(argc != 3) {
			RESPONSE(c, ResponseCode::CommandSyntaxError, "failed");
			return -1;
		}

		char *tmp;
		size_t len;
		if(Base64Decode(argv[2], (unsigned char **)&tmp, &len)) {
			printf("base64 decode failed");
			RESPONSE(c, ResponseCode::CommandParameterError, "failed");
			return -1;
		}

		shared_ptr<Item> item(new Item(tmp, len));

		free(tmp);
		//mKeyCrypto.encrypt(new Item(tmp, len));
	}

	//BROADCAST(c, 55, "some event");
	RESPONSE(c, ResponseCode::CommandOkay, "ping");
	return 0;
}

DekdCtlCmdListener::DekdCtlCmdListener(KeyCrypto *kc) :
		FrameworkListener("dekd_ctl", true) {
	registerCmd(new CtlCmd());

	mKeyCrypto = kc;

	MkStorage::getInstance()->create();
	KekStorage::getInstance()->create();
}

DekdCtlCmdListener::CtlCmd::CtlCmd()
: DekdCommand("ctl") {

}

int DekdCtlCmdListener::CtlCmd::runCommand(SocketClient *c,
		int argc, char ** argv) {
	dump_args(argc, argv);

	int cmdCode = atoi(argv[1]);
	char *alias = argv[2];

	switch(cmdCode) {
		case CommandCode::CommandCreateProfile:
		{
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
			if(!MkStorage::getInstance()->store(alias, mk.get(), tok.get())) {
				printf("base64 decode failed");
				RESPONSE(c, ResponseCode::CommandFailed, "failed");
				return -1;
			}

			printf("Storing emkek...\n");
			shared_ptr<PubKey> devPub = shared_ptr<PubKey> (
					new PubKey(CRYPT_ITEM_MAX_LEN, CryptAlg::ECDH));
			shared_ptr<PrivKey> devPri = shared_ptr<PrivKey> (
					new PrivKey(CRYPT_ITEM_MAX_LEN, CryptAlg::ECDH));
			if(ecdh_gen_keypair(devPub.get(), devPri.get())) {
				printf("ecdh_GenKeyPair() failed.\n");
				exit(1);
			}

			shared_ptr<SymKey> symKey = shared_ptr<SymKey>(generateSymKey());

			printf("Storing kek...\n");

			if(!KekStorage::getInstance()->store(alias, symKey.get(), tok.get())) {
				printf("%s %d failed\n", __func__, __LINE__); exit(1);
			}
			symKey->dump("stored symKey");

			if(!KekStorage::getInstance()->store(alias, devPub.get(), tok.get())) {
				printf("%s %d failed\n", __func__, __LINE__); exit(1);
			}
			devPub->dump("stored devPub");

			if(!KekStorage::getInstance()->store(alias, devPri.get(), tok.get())) {
				printf("%s %d failed\n", __func__, __LINE__); exit(1);
			}
			devPub->dump("stored devPri");

			break;
		}
		case CommandCode::CommandDeleteProfile:
		{
			break;
		}
		case CommandCode::CommandLock:
		{
			break;
		}
		case CommandCode::CommandUnlock:
		{
			break;
		}
	}

	return 0;
}
