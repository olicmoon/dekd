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

#include "DaemonConnector.h"

using std::string;
using std::shared_ptr;

class DekClient : public DaemonConnector{
public:
	DekClient(string sockPath);
	virtual ~DekClient() { }

	EncKey *encrypt(string alias, SymKey *key);
	SymKey *decrypt(string alias, EncKey *key);
};

class DekControl : public DaemonConnector{
public:
	DekControl(string sockPath);
	virtual ~DekControl() { }

	bool create(string alias, Password *key);
	bool remove(string alias);
	bool unlock(string alias, Password *key);
	bool lock(string alias);
};

#endif /* DEKCLIENT_H_ */
