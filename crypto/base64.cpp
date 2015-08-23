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

bool Base64Decode(char* b64message, unsigned char**buffer, size_t* length) { //Decodes a base64 encoded string
	BIO *bio, *b64;

	int decodeLen = calcDecodeLength(b64message);

	*buffer = (unsigned char*)malloc(decodeLen + 1);
	(*buffer)[decodeLen] = '\0';

	bio = BIO_new_mem_buf(b64message, -1);
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
	*length = BIO_read(bio, *buffer, strlen(b64message));
	if(*length != decodeLen) {
		BIO_free_all(bio);
		return false;
	}
	BIO_free_all(bio);

	return true; //success
}

bool Base64Encode(const unsigned char* buffer, size_t length, char** b64text) { //Encodes a string to base64
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

  return true; //success
}
