/*
 * ResponseCode.h
 *
 *  Created on: Aug 20, 2015
 *      Author: olic
 */

#ifndef RESPONSECODE_H_
#define RESPONSECODE_H_

class CommandCode {
public:
	static const int CommandEncrypt	=	100;
	static const int CommandDecrypt	=	101;

	static const int CommandCreateProfile	=	200;
	static const int CommandDeleteProfile	=	201;
	static const int CommandLock	=	202;
	static const int CommandUnlock	=	203;
};

class ResponseCode {
public:
	static const int CommandOkay              = 200;

    // 500 series - The command was not accepted and the requested
    // action did not take place.
    static const int CommandFailed = 400;
    static const int CommandParameterError = 401;
    static const int CommandNoPermission = 402;
    static const int CommandSyntaxError = 403;

};

#endif /* RESPONSECODE_H_ */
