/*
 * DekdCmdListener.cpp
 *
 *  Created on: Aug 17, 2015
 *      Author: olic
 */

#include "DekdCmdListener.h"

#include <stdio.h>
#include <string.h>

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
	registerCmd(new ReqCmd());
}

DekdReqCmdListener::ReqCmd::ReqCmd()
: DekdCommand("req") {

}

int DekdReqCmdListener::ReqCmd::runCommand(SocketClient *c,
		int argc, char ** argv) {

	dump_args(argc, argv);
	//BROADCAST(c, 55, "some event");
	RESPONSE(c, 200, "ping");
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
