/*
 * DaemonConnector.h
 *
 *  Created on: Aug 28, 2015
 *      Author: olic
 */

#ifndef DAEMONCONNECTOR_H_
#define DAEMONCONNECTOR_H_

#include <string>
#include <vector>
#include <memory>

using std::string;
using std::vector;
using std::shared_ptr;

class DaemonConnector {
public:
	DaemonConnector();
	virtual ~DaemonConnector();

	string makeCommand(int sequenceNumber);
};

class DaemonEvent {
public:
	virtual ~DaemonEvent() { }

	static shared_ptr<DaemonEvent> parseRawEvent(string rawEvent);
	int cmdNumber;
	int code;
	std::vector<std::string> message;

	void dump(const char *msg);

private:
	DaemonEvent(int cmdNumber, int code, std::vector<std::string> message);
};

#endif /* DAEMONCONNECTOR_H_ */
