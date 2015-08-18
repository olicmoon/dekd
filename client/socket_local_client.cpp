/*
 * Copyright (C) 2006 The Android Open Source Project
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

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <sys/types.h>

/**
 * connect to peer named "name" on fd
 * returns same fd or -1 on error.
 * fd is not closed on error. that's your job.
 * 
 * Used by AndroidSocketImpl
 */
int socket_local_client_connect(int fd, const char *sock_path, const char *name)
{
    struct sockaddr_un addr;
    socklen_t alen;
	size_t namelen;
    int err;

	memset (&addr, 0, sizeof(addr));

	namelen = strlen(name) + strlen(sock_path);
	/* unix_path_max appears to be missing on linux */
	if (namelen > sizeof(addr) 
			- offsetof(struct sockaddr_un, sun_path) - 1) {
		return -1;
	}

	strcpy(addr.sun_path, sock_path);
	strcat(addr.sun_path, "/");
	strcat(addr.sun_path, name);

	addr.sun_family = AF_LOCAL;
	alen = namelen + offsetof(struct sockaddr_un, sun_path) + 1;
    if (err < 0) {
        return -1;
    }

    if(connect(fd, (struct sockaddr *) &addr, alen) < 0) {
        return -1;
    }

    return fd;

error:
    return -1;
}

/** 
 * connect to peer named "name"
 * returns fd or -1 on error
 */
int socket_local_client(const char *sock_path, const char *name, int type)
{
    int s;

    s = socket(AF_LOCAL, type, 0);
    if(s < 0) return -1;

    if ( 0 > socket_local_client_connect(s, sock_path, name)) {
        close(s);
        return -1;
    }

    return s;
}
