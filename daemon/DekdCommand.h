/*
 * DekdCommand.h
 *
 *  Created on: Aug 17, 2015
 *      Author: olic
 */

#ifndef DEKDCOMMAND_H_
#define DEKDCOMMAND_H_

#include <FrameworkCommand.h>

class DekdCommand : public FrameworkCommand {
public:
    DekdCommand(const char *cmd);
    virtual ~DekdCommand() {}

	int runCommand(SocketClient *c, int argc, char **argv);
};


#endif /* DEKDCOMMAND_H_ */
