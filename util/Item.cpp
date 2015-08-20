/*
 * Item.cpp
 *
 *  Created on: Aug 17, 2015
 *      Author: olic
 */

#include <Item.h>
#include <native_crypto.h>

AbstractItem::AbstractItem()
:_buffer(NULL), len(0), format(CRYPTO_ITEM_FMT_BIN) {

}

AbstractItem::AbstractItem(unsigned int len)
:_buffer(NULL), len(len), format(CRYPTO_ITEM_FMT_BIN) {
	if(this->len > 0) {
		_buffer = (unsigned char *)malloc(this->len);
		memset(_buffer, 0, this->len);
	}
	printf("Item[%p, %d] created\n", this, this->len);
}

AbstractItem::AbstractItem(const char *buf, unsigned int len)
:_buffer(NULL), len(len), format(CRYPTO_ITEM_FMT_BIN) {
	if(this->len > 0) {
		_buffer = (unsigned char *)malloc(this->len);
		memcpy(_buffer, buf, this->len);
	}
	printf("Item[%p, %d] created\n", this, this->len);
}

AbstractItem::~AbstractItem() {
	if(_buffer) {
		zeroOut();
		free(_buffer);
	}
	printf("Item[%p] removed\n", this);
}

unsigned char *AbstractItem::alloc(ssize_t len) {
	_buffer = (unsigned char *)malloc(len);

	return _buffer;
}

void AbstractItem::zeroOut() {
	if(_buffer && len > 0)
		memset(_buffer, 0, len);
}

void AbstractItem::dump(const char* str) {
	unsigned int i;

	printf("%s(%s) : buffer[%p], format[%d]\n", __func__, str, _buffer, format);
	if(_buffer != NULL && len > 0) {
		printf("%s[%p] : len=%d: ", str, this, len);
		for(i=0;i<len;++i) {
			if((i%16) == 0)
				printf("\n");
			printf("%02X ", (unsigned char)_buffer[i]);
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
		printf("%s : len=%d: ", str, len);
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

shared_ptr<AbstractItem> AbstractItem::serialize() {
	char *tmp = (char *)malloc(CRYPT_ITEM_MAX_LEN);
	char tempBuf[CRYPT_ITEM_MAX_LEN];

	if(this->format == CRYPTO_ITEM_FMT_B64) {
		printf("already base64 item");
		return NULL;
	}

	Base64Encode(this->getData(), this->len, &tmp);
	snprintf(tempBuf, CRYPT_ITEM_MAX_LEN, "0 %s ? $", tmp);
	shared_ptr<Item> serializedItem(new Item(tempBuf, strlen(tempBuf)));
	serializedItem->format = CRYPTO_ITEM_FMT_B64;

	memset(tempBuf, 0, CRYPT_ITEM_MAX_LEN);
	memset(tmp, 0, CRYPT_ITEM_MAX_LEN);
	free(tmp);
	return serializedItem;
}

shared_ptr<AbstractItem> AbstractItem::deserialize() {
	shared_ptr<Item> result;

	if(this->format == CRYPTO_ITEM_FMT_BIN) {
		printf("already binary item");
		return NULL;
	}

	char *tempBuf = strdup((const char *)this->getData());
	const char s[2] = " ";

	char *tok_alg = strtok(tempBuf, s);
	if(tok_alg == NULL)  {
		printf("failed to deserialize %s\n", tempBuf);
		free(tempBuf);
		return NULL;
	}
	int alg = atoi(tok_alg);

	char *tmp = (char *)malloc(CRYPT_ITEM_MAX_LEN);
	int len;
	char *tok1 = strtok(NULL, s);
	if(tok1 == NULL) {
		printf("Failed to deserialize(step:1) %s\n", tempBuf);
		free(tempBuf);
		return NULL;
	}

	char *tok2 = strtok(NULL, s);
	if(tok2 == NULL) {
		printf("Failed to deserialize(step:2) %s\n", tempBuf);
		free(tempBuf);
		return NULL;
	}


	char *tok3 = strtok(NULL, s);
	if(tok3 == NULL || *tok3 != '$') {
		printf("Failed to deserialize(step:3) %s\n", tempBuf);
		free(tempBuf);
		return NULL;
	}

	printf("tok1: %s[%d]\n", tok1, strlen(tok1));
	printf("tok2: %s[%d]\n", tok2, strlen(tok2));
	printf("tok2: %s[%d]\n", tok3, strlen(tok3));
	if(alg == CRYPTO_ALG_PLAIN) {
		Base64Decode(tok1, (unsigned char **)&tmp, (size_t *)&len);
		Item *item = new Item(tmp, len);
		memset(tmp, 0, CRYPT_ITEM_MAX_LEN);
		free(tempBuf);
		return shared_ptr<Item> (item);
	} else if(alg == CRYPTO_ALG_AES) {
		Base64Decode(tok1, (unsigned char **)&tmp, (size_t *)&len);
		EncItem *eitem = new EncItem(tmp, len, alg);
		Base64Decode(tok2, (unsigned char **)&eitem->auth_tag, (size_t *)&len);
		free(tempBuf);
		return shared_ptr<Item> (eitem);
	} else if(alg == CRYPTO_ALG_RSA) {

	} else if(alg == CRYPTO_ALG_ECDH) {

		Base64Decode(tok1, (unsigned char **)&tmp, (size_t *)&len);
		EncItem *eitem = new EncItem(tmp, len, alg);
		Base64Decode(tok2, (unsigned char **)&tmp, (size_t *)&len);
		eitem->setPubKey(new PubKey(tmp, len, 2048, alg));
				fprintf(stderr, "%s:%d\n", __func__, __LINE__);eitem->getPubKey()->dump("tttt");
		free(tempBuf);
		return shared_ptr<Item> (eitem);
	} else {
		printf("failed to deserialize %s\n", tempBuf);
		free(tempBuf);
		return NULL;
	}

	free(tempBuf);
	return NULL;
}

//shared_ptr<AbstractItem> AbstractItem::deserialize() {
//	unsigned char tmp[CRYPT_ITEM_MAX_LEN];
//	int len = 0;
//
//	if(this->format == CRYPTO_ITEM_FMT_BIN) {
//		printf("already binary item");
//		return NULL;
//	}
//
//	base64d(this->getData(), tmp, &len);
//	shared_ptr<Item> item(new Item((const char *)tmp, len));
//
//	return item;
//}

shared_ptr<AbstractItem> EncItem::serialize() {
	char *tmp_eitem = (char *)malloc(CRYPT_ITEM_MAX_LEN);
	char *tempBuf = (char *)malloc(CRYPT_ITEM_MAX_LEN);
	if(this->format == CRYPTO_ITEM_FMT_B64) {
		printf("already base64 item");
		return NULL;
	}

	Base64Encode(this->getData(), this->len, &tmp_eitem);
	//printf("tmp_eitem:%s\n", tmp_eitem);

	if(alg == CRYPTO_ALG_AES) {
		char *tmp_auth_tag = (char *)malloc(CRYPT_ITEM_MAX_LEN);
		Base64Encode(this->auth_tag, 16, &tmp_auth_tag);
		//printf("auth_tag:%s\n", auth_tag);

		sprintf(tempBuf, "%d %s %s $", alg, tmp_eitem, tmp_auth_tag);
	} else if(alg == CRYPTO_ALG_ECDH) {
		char *tmp_dpub = (char *)malloc(CRYPT_ITEM_MAX_LEN);
		PubKey *pk = this->getPubKey();
		if(pk == NULL) {
			printf("%s[ECDH] :: invalid pub key\n", __func__);
			return NULL;
		}
		Base64Encode(pk->getData(), pk->len, &tmp_dpub);
		printf("tmp_dpub:%s[%d]\n", tmp_dpub, strlen((const char *)tmp_dpub));
		sprintf(tempBuf, "%d %s %s $", alg, tmp_eitem, tmp_dpub);
	} else
		sprintf(tempBuf, "%d %s ? $", alg, tmp_eitem);

	printf("%s tempBuf:%s\n", __func__, tempBuf);

	shared_ptr<Item> encodedItem(new Item(tempBuf, strlen(tempBuf)));
	encodedItem->format = CRYPTO_ITEM_FMT_B64;

	//memset(tempBuf, 0, CRYPT_ITEM_MAX_LEN);
	return encodedItem;
}
