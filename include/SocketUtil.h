/*
 * SocketUtil.h
 *
 *  Created on: Aug 16, 2015
 *      Author: olic
 */

#ifndef SOCKET_UTIL_H_
#define SOCKET_UTIL_H_

#define SOCKET_DIR		"/dev/socket"

int create_socket(const char *sock_dir, const char *name, int type, mode_t perm,
		uid_t uid, gid_t gid);

#endif /* SOCKET_UTIL_H_ */
