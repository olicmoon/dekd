/*
 * Item.cpp
 *
 *  Created on: Aug 17, 2015
 *      Author: olic
 */

#include "Item.h"

AbstractItem::AbstractItem()
:buffer(NULL), len(0), format(CRYPTO_ITEM_FMT_BIN) {

}

AbstractItem::AbstractItem(unsigned int len)
:buffer(NULL), len(len), format(CRYPTO_ITEM_FMT_BIN) {
	if(this->len > 0) {
		buffer = (unsigned char *)malloc(this->len);
		memset(buffer, 0, this->len);
	}
	printf("Item[%p, %d] created\n", this, this->len);
}

AbstractItem::AbstractItem(const char *buf, unsigned int len)
:buffer(NULL), len(len), format(CRYPTO_ITEM_FMT_BIN) {
	if(this->len > 0) {
		buffer = (unsigned char *)malloc(this->len);
		memcpy(buffer, buf, this->len);
	}
	printf("Item[%p, %d] created\n", this, this->len);
}

AbstractItem::~AbstractItem() {
	if(buffer) {
		zeroOut();
		free(buffer);
	}
	printf("Item[%p] removed\n", this);
}

unsigned char *AbstractItem::alloc(ssize_t len) {
	buffer = (unsigned char *)malloc(len);

	return buffer;
}

void AbstractItem::zeroOut() {
	if(buffer && len > 0)
		memset(buffer, 0, len);
}

void AbstractItem::dump(const char* str) {
	unsigned int i;

	if(buffer && len > 0) {
		printf("%s[%p] : len=%d: ", str, this, len);
		for(i=0;i<len;++i) {
			if((i%16) == 0)
				printf("\n");
			printf("%02X ", (unsigned char)buffer[i]);
		}
		printf("\n");
	} else {
		printf("%s[%p] : empty\n", str, this);
	}
}

void AbstractItem::dump(const char *buf,
		unsigned int len, const char *str) {
	unsigned int i;

	if(buf && len > 0) {
		printf("%s[%p] : len=%d: ", str, len);
		for(i=0;i<len;++i) {
			if((i%16) == 0)
				printf("\n");
			printf("%02X ", (unsigned char)buf[i]);
		}
		printf("\n");
	} else {
		printf("%s : empty\n", str);
	}
}
