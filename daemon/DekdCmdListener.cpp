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
			strcpy(p, argv[i]);
			p+= strlen(argv[i]);
			if (i != (argc -1)) {
				*p++ = ' ';
			}
		}
	}
	printf("\n\nCMD > %s \n", buffer);
}

DekdReqCmdListener::DekdReqCmdListener() :
	FrameworkListener("dekd_req", true) {
	registerCmd(new EncCmd());

	mKeyCrypto = shared_ptr<KeyCrypto> (new KeyCrypto());
}

DekdReqCmdListener::EncCmd::EncCmd()
: DekdCommand("enc") {

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
		//mKeyCrypto.encrypt(new Item(tmp, len));
	}

	//BROADCAST(c, 55, "some event");
	RESPONSE(c, ResponseCode::CommandOkay, "ping");
	return 0;
}

DekdCtlCmdListener::DekdCtlCmdListener() :
		FrameworkListener("dekd_ctl", true) {
	registerCmd(new CtlCmd());
}

DekdCtlCmdListener::CtlCmd::CtlCmd()
: DekdCommand("ctl") {

}

int DekdCtlCmdListener::CtlCmd::runCommand(SocketClient *c,
		int argc, char ** argv) {

	return 0;
}
