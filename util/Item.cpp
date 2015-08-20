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
		memset(_buffer, 0, this->len);
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
		printf("%s[%p] : len=%d: ", str, buf, len);
		for(i=0;i<len;++i) {
			if((i%16) == 0)
				printf("\n");
			printf("%02X ", (unsigned char)buf[i]);
		}
		printf("\n");
	} else {
		printf("%s[%p] : empty\n", str, buf);
	}
}

shared_ptr<SerializedItem> AbstractItem::serialize() {
	char *tmp = (char *)malloc(CRYPT_ITEM_MAX_LEN);
	char tempBuf[CRYPT_ITEM_MAX_LEN];

	if(this->format == CRYPTO_ITEM_FMT_B64) {
		printf("already base64 item");
		return NULL;
	}

	Base64Encode(this->getData(), this->len, &tmp);
	snprintf(tempBuf, CRYPT_ITEM_MAX_LEN, "0 %s ? ? $", tmp);
	shared_ptr<SerializedItem> serializedItem(
			new SerializedItem(tempBuf));

	memset(tempBuf, 0, CRYPT_ITEM_MAX_LEN);
	memset(tmp, 0, CRYPT_ITEM_MAX_LEN);
	free(tmp);
	return serializedItem;
}

shared_ptr<SerializedItem> EncItem::serialize() {
	char *tmp_eitem = NULL;
	char *tmp_eitem_tag = NULL;
	char *tmp_dpub = NULL;

	char tempBuf[CRYPT_ITEM_MAX_LEN];
	if(this->format == CRYPTO_ITEM_FMT_B64) {
		printf("already base64 item");
		return NULL;
	}

	Base64Encode(this->getData(), this->len, &tmp_eitem);
	Base64Encode(this->auth_tag, 16, &tmp_eitem_tag);

	if(alg == CRYPTO_ALG_AES) {
		char *tmp_auth_tag = (char *)malloc(CRYPT_ITEM_MAX_LEN);
		Base64Encode(this->auth_tag, 16, &tmp_auth_tag);

		sprintf(tempBuf, "%d %s %s ? $", alg, tmp_eitem, tmp_auth_tag);
	} else if(alg == CRYPTO_ALG_ECDH) {
		PubKey *pk = this->getPubKey();
		if(pk == NULL) {
			printf("%s[ECDH] :: invalid pub key\n", __func__);
			return NULL;
		}
		Base64Encode(pk->getData(), pk->len, &tmp_dpub);
		sprintf(tempBuf, "%d %s %s %s $", alg, tmp_eitem, tmp_eitem_tag, tmp_dpub);
	} else
		sprintf(tempBuf, "%d %s %s ? $", alg, tmp_eitem, tmp_eitem_tag);

	shared_ptr<SerializedItem> encodedItem(
			new SerializedItem(tempBuf));
	encodedItem->format = CRYPTO_ITEM_FMT_B64;

	memset(tempBuf, 0, CRYPT_ITEM_MAX_LEN);

	if(tmp_eitem != NULL) free(tmp_eitem);
	if(tmp_eitem_tag != NULL) free(tmp_eitem_tag);
	if(tmp_dpub != NULL) free(tmp_dpub);
	return encodedItem;
}

void SerializedItem::init() {
	const char s[2] = " ";
	char *terminator;

	char *tok_alg = strtok((char *)_buffer, s);
	if(tok_alg == NULL)  {
		printf("failed to deserialize %s\n", _buffer);
		goto out;
	}
	_alg = atoi(tok_alg);

	_item = strtok(NULL, s);
	if(_item == NULL) {
		printf("failed to serialize::init() : %d\n", __LINE__);
		goto out;
	}
	_tag = strtok(NULL, s);
	if(_tag == NULL) {
		printf("failed to serialize::init() : %d\n", __LINE__);
		goto out;
	}

	_pubKey = strtok(NULL, s);
	if(_pubKey == NULL) {
		printf("failed to serialize::init() : %d\n", __LINE__);
		goto out;
	};

	terminator = strtok(NULL, s);
	if(terminator == NULL || *terminator != '$') {
		printf("failed to serialize::init() : %d\n", __LINE__);
		goto out;
	}

	out:
	return;
}

SerializedItem::SerializedItem(const char *buf)
: AbstractItem(buf, strlen(buf)) {
	format = CRYPTO_ITEM_FMT_B64;

	init();
}

SerializedItem::SerializedItem(int alg, const char *data,
		const char *tag, const char *pubKey)
: AbstractItem(CRYPT_ITEM_MAX_LEN) {
	format = CRYPTO_ITEM_FMT_B64;

	snprintf((char *)_buffer, CRYPT_ITEM_MAX_LEN,
			"%d %s %s %s $", alg,
			(data == NULL) ? "?" : data,
			(tag == NULL) ? "?" : tag,
			(pubKey == NULL) ? "?" : pubKey
	);

	init();
}

shared_ptr<AbstractItem> SerializedItem::deserialize() {
	shared_ptr<Item> result = NULL;

	unsigned char *tmp;
	unsigned char *tmp_auth_tag;
	unsigned char *tmp_dpub;
	size_t len;

	if(_alg == CRYPTO_ALG_PLAIN) {
		Base64Decode(_item, &tmp, &len);
		Item *item = new Item((const char *)tmp, len);
		memset(tmp, 0, CRYPT_ITEM_MAX_LEN);

		result = shared_ptr<Item> (item);
	} else if(_alg == CRYPTO_ALG_AES) {
		Base64Decode(_item, &tmp, &len);
		EncItem *eitem = new EncItem((const char *)tmp, len, _alg);

		Base64Decode(_tag, &tmp_auth_tag, &len);
		memcpy(eitem->auth_tag, tmp_auth_tag, 16);

		result = shared_ptr<Item> (eitem);
	} else if(_alg == CRYPTO_ALG_RSA) {

	} else if(_alg == CRYPTO_ALG_ECDH) {

		Base64Decode(_item, &tmp, &len);
		EncItem *eitem = new EncItem((const char *)tmp, len, _alg);

		Base64Decode(_tag, &tmp_auth_tag, &len);
		if(len != 16) printf("b64 output auth len is not 16 [%d]\n", len);
		memcpy(eitem->auth_tag, tmp_auth_tag, 16);

		Base64Decode(_pubKey, &tmp_dpub, &len);
		eitem->setPubKey(new PubKey((const char *)tmp_dpub, len, 2048, _alg));

		result = shared_ptr<Item> (eitem);
	}

	if(tmp != NULL) free(tmp);
	if(tmp_auth_tag != NULL) free(tmp_auth_tag);
	if(tmp_dpub != NULL) free(tmp_dpub);
	return result;
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
