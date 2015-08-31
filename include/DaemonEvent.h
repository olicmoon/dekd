/*
 * DaemonEvent.h
 *
 *  Created on: Aug 29, 2015
 *      Author: olic
 */

#ifndef DAEMONEVENT_H_
#define DAEMONEVENT_H_

#include <Item.h>
#include <vector>
#include <memory>

using std::shared_ptr;
using std::vector;

class DaemonEvent {
public:
	virtual ~DaemonEvent() {
		for(int i=0; i < message.size(); i++)
			Util::zeroOut(message[i]);
	}

	static shared_ptr<DaemonEvent> parseRawEvent(string rawEvent);
	int cmdNumber;
	int code;
	std::vector<std::string> message;

	void dump(const char *msg);

private:
	DaemonEvent(int cmdNumber, int code, std::vector<std::string> message);
};

#endif /* DAEMONEVENT_H_ */
