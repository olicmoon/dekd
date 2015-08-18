/*
 * FrameworkResponse.h
 *
 *  Created on: Aug 17, 2015
 *      Author: olic
 */

#ifndef FRAMEWORKRESPONSE_H_
#define FRAMEWORKRESPONSE_H_

#include <linux/limits.h>
#include <string.h>

#define RESPONSE(cl, code, fmt, ...) { \
	char msg[128+PATH_MAX] = {0}; \
	sprintf(msg, fmt, ##__VA_ARGS__); \
	cl->sendMsg(code, msg, false);\
}

#endif /* FRAMEWORKRESPONSE_H_ */
