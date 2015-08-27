/*
 * DekClient.h
 *
 *  Created on: Aug 26, 2015
 *      Author: olic
 */

#ifndef DEKCLIENT_H_
#define DEKCLIENT_H_

#include <sys/socket.h>

#include <Item.h>
#include <string>

using std::string;
using std::shared_ptr;

#include "socket_local_client.h"

class DekClient {
public:
	DekClient(string sockPath);
	virtual ~DekClient() { }

	EncKey *encrypt(string alias, SymKey *key);
	SymKey *decrypt(string alias, EncKey *key);

private:
	int connect();
	string monitor(int sock);
	string _sockPath;
};

#endif /* DEKCLIENT_H_ */
