/*
 * Item.cpp
 *
 *  Created on: Aug 17, 2015
 *      Author: olic
 */

#include <Item.h>
#include <native_crypto.h>

int Base64Encode2(const unsigned char* buffer, size_t length, char** b64text);
int Base64Decode2(char* b64message, unsigned char** buffer, size_t* length);

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

	Base64Encode2(this->getData(), this->len, &tmp);
	snprintf(tempBuf, CRYPT_ITEM_MAX_LEN, "0 %s ? ? $", tmp);
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
	if(tok3 == NULL) {
		printf("Failed to deserialize(step:3) %s\n", tempBuf);
		free(tempBuf);
		return NULL;
	}

	char *tok4 = strtok(NULL, s);
	if(tok4 == NULL || *tok4 != '$') {
		printf("Failed to deserialize(step:4) %s\n", tempBuf);
		free(tempBuf);
		return NULL;
	}

	unsigned char *tmp;
	unsigned char *tmp_auth_tag;
	unsigned char *tmp_dpub;
	size_t len;

	if(alg == CRYPTO_ALG_PLAIN) {
		Base64Decode2(tok1, &tmp, &len);
		Item *item = new Item((const char *)tmp, len);
		memset(tmp, 0, CRYPT_ITEM_MAX_LEN);

		free(tempBuf); free(tmp);
		return shared_ptr<Item> (item);
	} else if(alg == CRYPTO_ALG_AES) {
		Base64Decode2(tok1, &tmp, &len);
		EncItem *eitem = new EncItem((const char *)tmp, len, alg);

		Base64Decode2(tok2, &tmp_auth_tag, &len);
		memcpy(eitem->auth_tag, tmp_auth_tag, 16);

		free(tempBuf); free(tmp); free(tmp_auth_tag);
		return shared_ptr<Item> (eitem);
	} else if(alg == CRYPTO_ALG_RSA) {

	} else if(alg == CRYPTO_ALG_ECDH) {

		Base64Decode2(tok1, &tmp, &len);
		EncItem *eitem = new EncItem((const char *)tmp, len, alg);

		Base64Decode2(tok2, &tmp_auth_tag, &len);
		if(len != 16) printf("b64 output auth len is not 16 [%d]\n", len);
		memcpy(eitem->auth_tag, tmp_auth_tag, 16);

		Base64Decode2(tok3, &tmp_dpub, &len);
		eitem->setPubKey(new PubKey((const char *)tmp_dpub, len, 2048, alg));

		free(tempBuf); free(tmp); free(tmp_auth_tag); free(tmp_dpub);
		return shared_ptr<Item> (eitem);
	} else {
		printf("failed to deserialize %s\n", tempBuf);
		free(tempBuf);
		return NULL;
	}

	free(tempBuf);
	return NULL;
}

shared_ptr<AbstractItem> EncItem::serialize() {
	char *tmp_eitem;
	char *tmp_eitem_tag;
	char tempBuf[CRYPT_ITEM_MAX_LEN];
	if(this->format == CRYPTO_ITEM_FMT_B64) {
		printf("already base64 item");
		return NULL;
	}

	Base64Encode2(this->getData(), this->len, &tmp_eitem);
	Base64Encode2(this->auth_tag, 16, &tmp_eitem_tag);
//	printf("tmp_eitem:%s\n", tmp_eitem);
	Item::dump(tmp_eitem, strlen(tmp_eitem), "eitem");

	if(alg == CRYPTO_ALG_AES) {
		char *tmp_auth_tag = (char *)malloc(CRYPT_ITEM_MAX_LEN);
		Base64Encode2(this->auth_tag, 16, &tmp_auth_tag);

		sprintf(tempBuf, "%d %s %s ? $", alg, tmp_eitem, tmp_auth_tag);
	} else if(alg == CRYPTO_ALG_ECDH) {
		char *tmp_dpub;
		PubKey *pk = this->getPubKey();
		if(pk == NULL) {
			printf("%s[ECDH] :: invalid pub key\n", __func__);
			return NULL;
		}
		Base64Encode2(pk->getData(), pk->len, &tmp_dpub);
		sprintf(tempBuf, "%d %s %s %s $", alg, tmp_eitem, tmp_eitem_tag, tmp_dpub);
	} else
		sprintf(tempBuf, "%d %s %s ? $", alg, tmp_eitem, tmp_eitem_tag);

	shared_ptr<Item> encodedItem(new Item(tempBuf, strlen(tempBuf)));
	encodedItem->format = CRYPTO_ITEM_FMT_B64;

	memset(tempBuf, 0, CRYPT_ITEM_MAX_LEN);
	return encodedItem;
}

//Decodes Base64
#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <math.h>

size_t calcDecodeLength(const char* b64input) { //Calculates the length of a decoded string
	size_t len = strlen(b64input),
		padding = 0;

	if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
		padding = 2;
	else if (b64input[len-1] == '=') //last char is =
		padding = 1;

	return (len*3)/4 - padding;
}

int Base64Decode2(char* b64message, unsigned char**buffer, size_t* length) { //Decodes a base64 encoded string
	BIO *bio, *b64;

	int decodeLen = calcDecodeLength(b64message);

	*buffer = (unsigned char*)malloc(decodeLen + 1);
	(*buffer)[decodeLen] = '\0';
	bio = BIO_new_mem_buf(b64message, -1);
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
	*length = BIO_read(bio, *buffer, strlen(b64message));
	assert(*length == decodeLen); //length should equal decodeLen, else something went horribly wrong
	BIO_free_all(bio);

	return (0); //success
}

int Base64Encode2(const unsigned char* buffer, size_t length, char** b64text) { //Encodes a string to base64
  BIO *bio, *b64;
  FILE* stream;
  int encodedSize = 4*ceil((double)length/3);
  *b64text = (char *)malloc(encodedSize+1);

  stream = fmemopen(*b64text, encodedSize+1, "w");
  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new_fp(stream, BIO_NOCLOSE);
  bio = BIO_push(b64, bio);
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
  BIO_write(bio, buffer, length);
  BIO_flush(bio);
  BIO_free_all(bio);
  fclose(stream);

  return (0); //success
}
