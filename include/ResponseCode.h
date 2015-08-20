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
};

class ResponseCode {
public:
	static const int CommandOkay              = 200;

    // 500 series - The command was not accepted and the requested
    // action did not take place.
    static const int CommandSyntaxError = 400;
    static const int CommandParameterError = 401;
    static const int CommandNoPermission = 402;

};

#endif /* RESPONSECODE_H_ */
