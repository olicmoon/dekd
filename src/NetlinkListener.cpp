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
#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <string.h>

#include <SocketUtil.h>
#include <NetlinkEvent.h>

#if 1
/* temporary version until we can get Motorola to update their
 * ril.so.  Their prebuilt ril.so is using this private class
 * so changing the NetlinkListener() constructor breaks their ril.
 */
NetlinkListener::NetlinkListener(int socket) :
                            SocketListener(socket, false) {
    mFormat = NETLINK_FORMAT_ASCII;
}
#endif

NetlinkListener::NetlinkListener(int socket, int format) :
                            SocketListener(socket, false), mFormat(format) {
}

/**
 * Like the above, but passes a uid_t in by reference. In the event that this
 * fails due to a bad uid check, the uid_t will be set to the uid of the
 * socket's peer.
 *
 * If this method rejects a netlink message from outside the kernel, it
 * returns -1, sets errno to EIO, and sets "user" to the UID associated with the
 * message. If the peer UID cannot be determined, "user" is set to -1."
 */
ssize_t uevent_kernel_multicast_uid_recv(int socket, void *buffer,
                                         size_t length, uid_t *user)
{
    struct iovec iov = { buffer, length };
    struct sockaddr_nl addr;
    char control[CMSG_SPACE(sizeof(struct ucred))];
    struct msghdr hdr = {
        &addr,
        sizeof(addr),
        &iov,
        1,
        control,
        sizeof(control),
        0,
    };

    *user = -1;
    ssize_t n = recvmsg(socket, &hdr, 0);
    if (n <= 0) {
        return n;
    }

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&hdr);
    struct ucred *cred = (struct ucred *)CMSG_DATA(cmsg);
    *user = cred->uid;

    if (cmsg == NULL || cmsg->cmsg_type != SCM_CREDENTIALS) {
        /* ignoring netlink message with no sender credentials */
        goto out;
    }

    if (cred->uid != 0) {
        /* ignoring netlink message from non-root user */
        goto out;
    }

    if (addr.nl_groups == 0 || addr.nl_pid != 0) {
        /* ignoring non-kernel or unicast netlink message */
        goto out;
    }

    return n;

out:
    /* clear residual potentially malicious data */
    bzero(buffer, length);
    errno = EIO;
    return -1;
}

bool NetlinkListener::onDataAvailable(SocketClient *cli)
{
    int socket = cli->getSocket();
    ssize_t count;
    uid_t uid = -1;

    count = TEMP_FAILURE_RETRY(uevent_kernel_multicast_uid_recv(
                                       socket, mBuffer, sizeof(mBuffer), &uid));
    if (count < 0) {
        printf("recvmsg failed (%s)", strerror(errno));
        return false;
    }

    NetlinkEvent *evt = new NetlinkEvent();
    if (evt->decode(mBuffer, count, mFormat)) {
        onEvent(evt);
    } else if (mFormat != NETLINK_FORMAT_BINARY) {
        // Don't complain if parseBinaryNetlinkMessage returns false. That can
        // just mean that the buffer contained no messages we're interested in.
    	printf("Error decoding NetlinkEvent\n");
    }

    delete evt;
    return true;
}
