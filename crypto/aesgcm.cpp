/* Simple AES GCM test program, uses the same NIST data used for the FIPS
 * self test but uses the application level EVP APIs.
 */
#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#include "Item.h"

static const unsigned char gcm_aad[] = {
		0x4d,0x23,0xc3,0xce,0xc3,0x34,0xb4,0x9b,0xdb,0x37,0x0c,0x43,
		0x7f,0xec,0x78,0xde
};

static const unsigned char gcm_iv[] = {
		0x99,0xaa,0x3e,0x68,0xed,0x81,0x73,0xa0,0xee,0xd0,0x66,0x84
};

EncItem *aes_gcm_encrypt(Item *item, SymKey *key)
{
	EVP_CIPHER_CTX *ctx;
	int len;
	int aad_len = sizeof(gcm_aad);

	if(key == NULL || item == NULL) {
		printf("%s :: Invalid input\n", __func__);
		return NULL;
	}

	EncItem *ct = new EncItem(CRYPT_ITEM_MAX_LEN, CryptAlg::AES);
	if(ct == NULL) {
		printf("%s :: no Memory\n", __func__);
		return NULL;
	}

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new()))
	{ printf("error %s:%d\n", __func__, __LINE__); goto err_out; }

	/* Initialise the encryption operation. */
	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
	{ printf("error %s:%d\n", __func__, __LINE__); goto err_out; }

	/* Set IV length if default 12 bytes (96 bits) is not appropriate */
	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
	{ printf("error %s:%d\n", __func__, __LINE__); goto err_out; }

	/* Initialise key and IV */
	if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key->getData(), gcm_iv))
	{ printf("error %s:%d\n", __func__, __LINE__); goto err_out; }

	EVP_CIPHER_CTX_set_padding(ctx, 0);

	/* Provide any AAD data. This can be called zero or more times as
	 * required
	 */
	if(1 != EVP_EncryptUpdate(ctx, NULL, &len, gcm_aad, aad_len))
	{ printf("error %s:%d\n", __func__, __LINE__); goto err_out; }

	/* Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_EncryptUpdate can be called multiple times if necessary
	 */
	if(1 != EVP_EncryptUpdate(ctx, ct->getData(), &len, item->getData(), item->len))
	{ printf("error %s:%d\n", __func__, __LINE__); goto err_out; }
	ct->len = len;

	/* Finalise the encryption. Normally ciphertext bytes may be written at
	 * this stage, but this does not occur in GCM mode
	 */
	if(1 != EVP_EncryptFinal_ex(ctx, ct->getData() + len, &len))
	{ printf("error %s:%d\n", __func__, __LINE__); goto err_out; }
	ct->len += len;

	/* Get the tag */
	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, ct->auth_tag))
	{ printf("error %s:%d\n", __func__, __LINE__); goto err_out; }

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ct;
	err_out:
	delete ct;
	return NULL;
}

Item *aes_gcm_decrypt(EncItem *ct, SymKey *key)
{
	EVP_CIPHER_CTX *ctx;
	int aad_len = sizeof(gcm_aad);
	int len;
	int rc;

	if(key == NULL || ct == NULL) {
		printf("%s :: Invalid input\n", __func__);
		return NULL;
	}

	Item *pt = new Item(CRYPT_ITEM_MAX_LEN);
	if(pt == NULL) {
		printf("%s :: no Memory\n", __func__);
		return NULL;
	}

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new()))
	{ printf("error %s:%d\n", __func__, __LINE__); goto err_out; }

	EVP_CIPHER_CTX_set_padding(ctx, 0);

	/* Initialise the decryption operation. */
	if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
	{ printf("error %s:%d\n", __func__, __LINE__); goto err_out; }

	/* Set IV length. Not necessary if this is 12 bytes (96 bits) */
	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
	{ printf("error %s:%d\n", __func__, __LINE__); goto err_out; }

	/* Initialise key and IV */
	if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key->getData(), gcm_iv))
	{ printf("error %s:%d\n", __func__, __LINE__); goto err_out; }

	/* Set expected tag value. Works in OpenSSL 1.0.1d and later */
	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, ct->auth_tag))
	{ printf("error %s:%d\n", __func__, __LINE__); goto err_out; }

	/* Provide any AAD data. This can be called zero or more times as
	 * required
	 */
	if(!EVP_DecryptUpdate(ctx, NULL, &len, gcm_aad, aad_len))
	{ printf("error %s:%d\n", __func__, __LINE__); goto err_out; }

	/* Provide the message to be decrypted, and obtain the plaintext output.
	 * EVP_DecryptUpdate can be called multiple times if necessary
	 */
	if(!EVP_DecryptUpdate(ctx, pt->getData(), &len, ct->getData(), ct->len))
	{ printf("error %s:%d\n", __func__, __LINE__); goto err_out; }
	pt->len = len;

	/* Set expected tag value. Works in OpenSSL 1.0.1d and later */
	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, ct->auth_tag))
	{ printf("error %s:%d\n", __func__, __LINE__); goto err_out; }

	/* Finalise the decryption. A positive return value indicates success,
	 * anything else is a failure - the plaintext is not trustworthy.
	 */
	rc = EVP_DecryptFinal_ex(ctx, pt->getData() + len, &len);

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	if(rc > 0) { /* Success */
		pt->len += len;
		return pt;
	} else /* Verify failed */
		printf("error %s:%d GCM verify failed\n", __func__, __LINE__);

	err_out:
	delete pt;
	return NULL;
}
