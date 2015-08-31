/*
 * DaemonConnector.h
 *
 *  Created on: Aug 28, 2015
 *      Author: olic
 */

#ifndef DAEMONCONNECTOR_H_
#define DAEMONCONNECTOR_H_

#include <DaemonEvent.h>
#include <string>

using std::string;
using std::vector;
using std::shared_ptr;

class DaemonConnector {
public:
	DaemonConnector(string sockPath, int type);
	virtual ~DaemonConnector();

	string makeCommand(int sequenceNumber);
	int doConnect();
	shared_ptr<DaemonEvent> monitor(int sock);

private:
	string _sockPath;
	int _sockType;

	int localClientConnect(int fd);

};

#endif /* DAEMONCONNECTOR_H_ */
