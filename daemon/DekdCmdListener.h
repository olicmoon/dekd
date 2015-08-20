/*
 * DekdDekdCmdListener.h
 *
 *  Created on: Aug 17, 2015
 *      Author: olic
 */

#ifndef DEKDCOMMANDLISTENER_H_
#define DEKDCOMMANDLISTENER_H_
/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _COMMANDLISTENER_H__
#define _COMMANDLISTENER_H__

#include <FrameworkListener.h>
#include "DekdCommand.h"
#include "KeyCrypto.h"

class DekdReqCmdListener : public FrameworkListener {
public:
    DekdReqCmdListener();
    virtual ~DekdReqCmdListener() {}

private:
    shared_ptr<KeyCrypto> mKeyCrypto;
    static void dumpArgs(int argc, char **argv, int argObscure);

    class EncCmd : public DekdCommand {
    public:
    	EncCmd();
        virtual ~EncCmd() {}
        int runCommand(SocketClient *c, int argc, char ** argv);
    };
};

class DekdCtlCmdListener : public FrameworkListener {
public:
	DekdCtlCmdListener();
    virtual ~DekdCtlCmdListener() {}

private:
    static void dumpArgs(int argc, char **argv, int argObscure);

    class CtlCmd : public DekdCommand {
    public:
    	CtlCmd();
        virtual ~CtlCmd() {}
        int runCommand(SocketClient *c, int argc, char ** argv);
    };
};

#endif



#endif /* DEKDCOMMANDLISTENER_H_ */
