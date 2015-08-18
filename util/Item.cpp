/*
 * Item.cpp
 *
 *  Created on: Aug 17, 2015
 *      Author: olic
 */

#include "Item.h"

AbstractItem::AbstractItem()
:buffer(NULL), len(0){

}

AbstractItem::AbstractItem(unsigned int len)
:buffer(NULL), len(len){
	buffer = (unsigned char *)malloc(this->len);
}

AbstractItem::~AbstractItem() {
	if(buffer) zeroOut();
}

unsigned char *AbstractItem::alloc(ssize_t len) {
	buffer = (unsigned char *)malloc(len);

	return buffer;
}

void AbstractItem::zeroOut() {
	if(buffer && len > 0)
		memset(buffer, 0, len);
}
