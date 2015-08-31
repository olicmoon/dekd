/*
 * DaemonConnector.cpp
 *
 *  Created on: Aug 28, 2015
 *      Author: olic
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

#include <DaemonConnector.h>

DaemonConnector::DaemonConnector(string sockPath, int type) {
	this->_sockPath = sockPath;
	this->_sockType = type;
}

DaemonConnector::~DaemonConnector() {
	// TODO Auto-generated destructor stub
}

/**
 * connect to peer named "name" on fd
 * returns same fd or -1 on error.
 * fd is not closed on error. that's your job.
 *
 * Used by AndroidSocketImpl
 */
int DaemonConnector::localClientConnect(int fd)
{
    struct sockaddr_un addr;
    socklen_t alen;
	size_t namelen;
    int err;

	memset (&addr, 0, sizeof(addr));

	namelen = strlen(_sockPath.c_str());
	/* unix_path_max appears to be missing on linux */
	if (namelen > sizeof(addr)
			- offsetof(struct sockaddr_un, sun_path) - 1) {
		return -1;
	}

	strcpy(addr.sun_path, _sockPath.c_str());

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
int DaemonConnector::doConnect()
{
    int s;

    s = socket(AF_LOCAL, this->_sockType, 0);
    if(s < 0) return -1;

    if ( 0 > localClientConnect(s)) {
        close(s);
        return -1;
    }

    return s;
}

shared_ptr<DaemonEvent> DaemonConnector::monitor(int sock) {
	char *buffer = (char *)malloc(4096);

	while(1) {
		fd_set read_fds;
		struct timeval to;
		int rc = 0;

		to.tv_sec = 10;
		to.tv_usec = 0;

		FD_ZERO(&read_fds);
		FD_SET(sock, &read_fds);

		if ((rc = select(sock +1, &read_fds, NULL, NULL, &to)) < 0) {
			fprintf(stderr, "Error in select (%s)\n", strerror(errno));
			free(buffer);
			return NULL;
		} else if (!rc) {
			continue;
			fprintf(stderr, "[TIMEOUT]\n");
			return NULL;
		} else if (FD_ISSET(sock, &read_fds)) {
			memset(buffer, 0, 4096);
			if ((rc = read(sock, buffer, 4096)) <= 0) {
				if (rc == 0)
					fprintf(stderr, "Lost connection - did it crash?\n");
				else
					fprintf(stderr, "Error reading data (%s)\n", strerror(errno));
				free(buffer);

				return NULL;
			}

			int offset = 0;
			int i = 0;

			for (i = 0; i < rc; i++) {
				if (buffer[i] == '\0') {
					int code;
					char tmp[4];

					strncpy(tmp, buffer + offset, 3);
					tmp[3] = '\0';
					code = atoi(tmp);

					string resp = buffer + offset;

					if (code >= 200 && code < 600) {
						free(buffer);
						shared_ptr<DaemonEvent> event(DaemonEvent::parseRawEvent(resp));
						Util::zeroOut(resp);
						return event;
					}

					offset = i + 1;
				}
			}
		}
	}
	free(buffer);
	return NULL;
}
