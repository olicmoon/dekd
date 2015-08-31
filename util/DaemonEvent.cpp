/*
 * DeamonEvent.cpp
 *
 *  Created on: Aug 29, 2015
 *      Author: olic
 */

#include <DaemonEvent.h>

DaemonEvent::DaemonEvent(int cmdNumber, int code, std::vector<std::string> message) {
	this->cmdNumber = cmdNumber;
	this->code = code;
	this->message = message;
}

void DaemonEvent::dump(const char *msg) {
    printf("code[%d] cmdId[%d]\n", code, cmdNumber);

    for(int i=0; i < message.size(); i++){
    	printf("[%d] %s\n", i, message[i].c_str());
    }
}
//resp :: 200 0 1 PeLudXMhiDPHhkOeOV2/73slfYaE+y+ydMC2jbsIc6c= VNudcJg0uFOyMWWRQgmfFg== ? $

shared_ptr<DaemonEvent> DaemonEvent::parseRawEvent(string rawEvent) {
	vector<std::string> parsed;

	printf("%s :: %s\n", __func__, rawEvent.c_str());
	char deli = ' ';
    string::size_type lastPos = rawEvent.find_first_not_of(deli, 0);
    string::size_type pos     = rawEvent.find_first_of(deli, lastPos);

    while (string::npos != pos || string::npos != lastPos)
    {
        parsed.push_back(rawEvent.substr(lastPos, pos - lastPos));
        lastPos = rawEvent.find_first_not_of(deli, pos);
        pos = rawEvent.find_first_of(deli, lastPos);
    }

    int code = std::stoi(parsed[0]);
    parsed.erase(parsed.begin());
    int cmdId = std::stoi(parsed[0]);
    parsed.erase(parsed.begin());

    return shared_ptr<DaemonEvent> (new DaemonEvent(cmdId, code, parsed));
}
