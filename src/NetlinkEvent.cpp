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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <NetlinkEvent.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>

#include <linux/if.h>
#include <linux/if_addr.h>
#include <linux/if_link.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter_ipv4/ipt_ULOG.h>
/* From kernel's net/netfilter/xt_quota2.c */
const int QLOG_NL_EVENT  = 112;

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

const int NetlinkEvent::NlActionUnknown = 0;
const int NetlinkEvent::NlActionAdd = 1;
const int NetlinkEvent::NlActionRemove = 2;
const int NetlinkEvent::NlActionChange = 3;
const int NetlinkEvent::NlActionLinkUp = 4;
const int NetlinkEvent::NlActionLinkDown = 5;
const int NetlinkEvent::NlActionAddressUpdated = 6;
const int NetlinkEvent::NlActionAddressRemoved = 7;
const int NetlinkEvent::NlActionRdnss = 8;
const int NetlinkEvent::NlActionRouteUpdated = 9;
const int NetlinkEvent::NlActionRouteRemoved = 10;

NetlinkEvent::NetlinkEvent() : mSeq(0){
    mAction = NlActionUnknown;
    memset(mParams, 0, sizeof(mParams));
    mPath = NULL;
    mSubsystem = NULL;
}

NetlinkEvent::~NetlinkEvent() {
    int i;
    if (mPath)
        free(mPath);
    if (mSubsystem)
        free(mSubsystem);
    for (i = 0; i < NL_PARAMS_MAX; i++) {
        if (!mParams[i])
            break;
        free(mParams[i]);
    }
}

void NetlinkEvent::dump() {
    int i;

    for (i = 0; i < NL_PARAMS_MAX; i++) {
        if (!mParams[i])
            break;
        printf("NL param '%s'\n", mParams[i]);
    }
}

/*
 * Returns the message name for a message in the NETLINK_ROUTE family, or NULL
 * if parsing that message is not supported.
 */
static const char *rtMessageName(int type) {
#define NL_EVENT_RTM_NAME(rtm) case rtm: return #rtm;
    switch (type) {
        NL_EVENT_RTM_NAME(RTM_NEWLINK);
        NL_EVENT_RTM_NAME(RTM_DELLINK);
        NL_EVENT_RTM_NAME(RTM_NEWADDR);
        NL_EVENT_RTM_NAME(RTM_DELADDR);
        NL_EVENT_RTM_NAME(RTM_NEWROUTE);
        NL_EVENT_RTM_NAME(RTM_DELROUTE);
        NL_EVENT_RTM_NAME(RTM_NEWNDUSEROPT);
        NL_EVENT_RTM_NAME(QLOG_NL_EVENT);
        default:
            return NULL;
    }
#undef NL_EVENT_RTM_NAME
}

/*
 * Checks that a binary NETLINK_ROUTE message is long enough for a payload of
 * size bytes.
 */
static bool checkRtNetlinkLength(const struct nlmsghdr *nh, size_t size) {
    if (nh->nlmsg_len < NLMSG_LENGTH(size)) {
    	printf("Got a short %s message\n", rtMessageName(nh->nlmsg_type));
        return false;
    }
    return true;
}

/*
 * Utility function to log errors.
 */
static bool maybeLogDuplicateAttribute(bool isDup,
                                       const char *attributeName,
                                       const char *messageName) {
    if (isDup) {
    	printf("Multiple %s attributes in %s, ignoring\n", attributeName, messageName);
        return true;
    }
    return false;
}

/* If the string between 'str' and 'end' begins with 'prefixlen' characters
 * from the 'prefix' array, then return 'str + prefixlen', otherwise return
 * NULL.
 */
static const char*
has_prefix(const char* str, const char* end, const char* prefix, size_t prefixlen)
{
    if ((end-str) >= (ptrdiff_t)prefixlen && !memcmp(str, prefix, prefixlen))
        return str + prefixlen;
    else
        return NULL;
}

/* Same as strlen(x) for constant string literals ONLY */
#define CONST_STRLEN(x)  (sizeof(x)-1)

/* Convenience macro to call has_prefix with a constant string literal  */
#define HAS_CONST_PREFIX(str,end,prefix)  has_prefix((str),(end),prefix,CONST_STRLEN(prefix))


/*
 * Parse an ASCII-formatted message from a NETLINK_KOBJECT_UEVENT
 * netlink socket.
 */
bool NetlinkEvent::parseAsciiNetlinkMessage(char *buffer, int size) {
    const char *s = buffer;
    const char *end;
    int param_idx = 0;
    int first = 1;

    if (size == 0)
        return false;

    /* Ensure the buffer is zero-terminated, the code below depends on this */
    buffer[size-1] = '\0';

    end = s + size;
    while (s < end) {
        if (first) {
            const char *p;
            /* buffer is 0-terminated, no need to check p < end */
            for (p = s; *p != '@'; p++) {
                if (!*p) { /* no '@', should not happen */
                    return false;
                }
            }
            mPath = strdup(p+1);
            first = 0;
        } else {
            const char* a;
            if ((a = HAS_CONST_PREFIX(s, end, "ACTION=")) != NULL) {
                if (!strcmp(a, "add"))
                    mAction = NlActionAdd;
                else if (!strcmp(a, "remove"))
                    mAction = NlActionRemove;
                else if (!strcmp(a, "change"))
                    mAction = NlActionChange;
            } else if ((a = HAS_CONST_PREFIX(s, end, "SEQNUM=")) != NULL) {
                mSeq = atoi(a);
            } else if ((a = HAS_CONST_PREFIX(s, end, "SUBSYSTEM=")) != NULL) {
                mSubsystem = strdup(a);
            } else if (param_idx < NL_PARAMS_MAX) {
                mParams[param_idx++] = strdup(s);
            }
        }
        s += strlen(s) + 1;
    }
    return true;
}

bool NetlinkEvent::decode(char *buffer, int size, int format) {
	return parseAsciiNetlinkMessage(buffer, size);
}

const char *NetlinkEvent::findParam(const char *paramName) {
    size_t len = strlen(paramName);
    for (int i = 0; i < NL_PARAMS_MAX && mParams[i] != NULL; ++i) {
        const char *ptr = mParams[i] + len;
        if (!strncmp(mParams[i], paramName, len) && *ptr == '=')
            return ++ptr;
    }

    printf("NetlinkEvent::FindParam(): Parameter '%s' not found", paramName);
    return NULL;
}
