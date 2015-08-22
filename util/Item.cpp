/*
 * Item.cpp
 *
 *  Created on: Aug 17, 2015
 *      Author: olic
 */

#include <Item.h>
#include <native_crypto.h>

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
		printf("Item[%p] zero-out\n", this);
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
	char *tmp;
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
	memset(tmp, 0, strlen(tmp));
	free(tmp);
	return serializedItem;
}

shared_ptr<SerializedItem> EncItem::serialize() {
	char *tmp_eitem = NULL;
	char *tmp_eitem_tag = NULL;
	char *tmp_dpub = NULL;
	char *tmp_salt = NULL;

	char tempBuf[CRYPT_ITEM_MAX_LEN];
	if(this->format == CRYPTO_ITEM_FMT_B64) {
		printf("already base64 item");
		return NULL;
	}

	Base64Encode(this->getData(), this->len, &tmp_eitem);
	Base64Encode(this->auth_tag, 16, &tmp_eitem_tag);

	if(encBy == CryptAlg::AES) {
		sprintf(tempBuf, "%d %s %s ? $", encBy, tmp_eitem, tmp_eitem_tag);
	} else if(encBy == CryptAlg::ECDH) {
		PubKey *pk = this->getPubKey();
		if(pk == NULL) {
			printf("%s[ECDH] :: invalid pub key\n", __func__);
			return NULL;
		}
		Base64Encode(pk->getData(), pk->len, &tmp_dpub);
		sprintf(tempBuf, "%d %s %s %s $",
				encBy, tmp_eitem, tmp_eitem_tag, tmp_dpub);
	} else if(encBy == CryptAlg::PBKDF) {
		Base64Encode(this->salt, 16, &tmp_salt);

		sprintf(tempBuf, "%d %s %s %s $",
				encBy, tmp_eitem, tmp_eitem_tag, tmp_salt);
	} else
		sprintf(tempBuf, "%d %s %s ? $",
				encBy, tmp_eitem, tmp_eitem_tag);

	shared_ptr<SerializedItem> encodedItem(
			new SerializedItem(tempBuf));
	encodedItem->format = CRYPTO_ITEM_FMT_B64;

	memset(tempBuf, 0, CRYPT_ITEM_MAX_LEN);

	if(tmp_eitem != NULL) free(tmp_eitem);
	if(tmp_eitem_tag != NULL) free(tmp_eitem_tag);
	if(tmp_dpub != NULL) free(tmp_dpub);
	if(tmp_salt != NULL) free(tmp_salt);
	return encodedItem;
}

void SerializedItem::init() {
	const char s[2] = " ";
	char *terminator;

	printf("%s :: %s\n", __func__, _buffer);
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

Item *SerializedItem::deserialize() {
	Item *result = NULL;

	unsigned char *tmp = NULL;
	unsigned char *tmp_auth_tag = NULL;
	unsigned char *tmp_dpub = NULL;
	unsigned char *tmp_salt = NULL;
	size_t len;

	if(_alg == CryptAlg::PLAIN) {
		Base64Decode(_item, &tmp, &len);
		Item *item = new Item((const char *)tmp, len);
		memset(tmp, 0, len);

		result = item;
	} else if(_alg == CryptAlg::AES) {
		Base64Decode(_item, &tmp, &len);
		EncItem *eitem = new EncItem((const char *)tmp, len, _alg);

		Base64Decode(_tag, &tmp_auth_tag, &len);
		memcpy(eitem->auth_tag, tmp_auth_tag, 16);

		result = (Item *) eitem;
	} else if(_alg == CryptAlg::ECDH) {

		Base64Decode(_item, &tmp, &len);
		EncItem *eitem = new EncItem((const char *)tmp, len, _alg);

		Base64Decode(_tag, &tmp_auth_tag, &len);
		if(len != 16) printf("b64 output auth len is not 16 [%d]\n", len);
		memcpy(eitem->auth_tag, tmp_auth_tag, 16);

		Base64Decode(_pubKey, &tmp_dpub, &len);
		eitem->setPubKey(new PubKey((const char *)tmp_dpub, len, _alg));

		result = (Item *) eitem;
	} else if(_alg == CryptAlg::PBKDF) {

		Base64Decode(_item, &tmp, &len);
		EncItem *eitem = new EncItem((const char *)tmp, len, _alg);

		Base64Decode(_tag, &tmp_auth_tag, &len);
		if(len != 16) printf("b64 output auth len is not 16 [%d]\n", len);
		memcpy(eitem->auth_tag, tmp_auth_tag, 16);

		Base64Decode(_salt, &tmp_salt, &len);

		result = (Item *) eitem;
	}

	if(tmp != NULL) free(tmp);
	if(tmp_auth_tag != NULL) free(tmp_auth_tag);
	if(tmp_dpub != NULL) free(tmp_dpub);
	if(tmp_dpub != NULL) free(tmp_dpub);
	return result;
}
