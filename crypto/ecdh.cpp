#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ecdh.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>

#include <Item.h>
#include <native_crypto.h>

static size_t KDF1_SHA256_len = 32;

static void *ecdh_sha256(const void *in, size_t inlen,
		void *out, size_t *outlen)
{
	if (*outlen < 32)
		return NULL;
	else
		*outlen = 32;
	sha256((unsigned char *)out, (const unsigned char *)in, inlen);

	return out;
}

#define ECDH_KEY_MAN_LEN	256

/*
 * ecdh_getDPub() extracts public key from parameter key, put into buf
 * return size of buffer on success or 0 when failed
 */
static int __ecdh_get_dpub(BN_CTX *ctx,
		const EC_KEY * key,
		unsigned char *buf, size_t buf_len) {
	int ret_len = 0;
	BIGNUM *pub_bn = NULL; // Need to free

	memset(buf, 0, buf_len);
	if((ctx == NULL) || (key == NULL) ) {
		printf("%s :: invalid arguments.. ctx:%p pub_key:%p\n",
				__func__, ctx, key);
		return -1;
	}

	pub_bn = EC_POINT_point2bn(
			EC_KEY_get0_group(key),
			EC_KEY_get0_public_key(key),
			EC_KEY_get_conv_form(key),
			NULL, ctx);
	if(pub_bn == NULL) {
		printf("failed to EC_KEY_get0_public_key..\n");
		return -1;
	}

	ret_len = BN_bn2bin(pub_bn, buf);

	BN_free(pub_bn);
	return ret_len;
}

/*
 * ecdh_setDPub() converts buf to public key, set to EC_KEY *key.
 */
static int __ecdh_set_dpub(BN_CTX *ctx, const EC_GROUP *group,
		unsigned char *buf, int buf_len, EC_KEY *key) {
	int rc;
	EC_POINT *point = NULL; // need to be freed
	BIGNUM *pub_bn = NULL; // need to be freed

	if((group == NULL) || (ctx == NULL) || (key == NULL) ) {
		printf("%s :: invalid arguments.. group:%p ctx:%p pub_key:%p\n",
				__func__, group, ctx, key);
		return -1;
	}

	pub_bn = BN_bin2bn((const unsigned char *)buf, buf_len, NULL);
	if(pub_bn == NULL) {
		printf("failed to BN_bin2bn.. \n");
		return -1;
	}

	point = EC_POINT_bn2point(group, pub_bn,
			NULL, ctx);
	if(point == NULL) {
		printf("EC_POINT_bn2point error!\n");
		goto errout;
	}

	rc = EC_KEY_set_group(key, group);
	if(rc != 1) {
		printf("EC_KEY_set_group error!\n");
		goto errout;
	}
	rc = EC_KEY_set_public_key(key, point);
	if(rc != 1) {
		printf("EC_KEY_set_public_key error!\n");
		goto errout;
	}

	EC_POINT_free(point);
	BN_free(pub_bn);
	return 0;
errout:
	printf("%s error..\n", __func__);
	EC_POINT_free(point);
	BN_free(pub_bn);
	return -1;
}

/*
 * ecdh_getDPri() extracts private key from parameter key, put into buf
 * return size of buffer on success or 0 when failed
 */
static int __ecdh_get_dpri(BN_CTX *ctx,
		const EC_KEY * key,
		unsigned char *buf, size_t buf_len) {
	int ret_len = 0;
	const BIGNUM *pri_bn = NULL; // No need to be freed

	memset(buf, 0, buf_len);
	if((ctx == NULL) || (key == NULL) ) {
		printf("%s :: invalid arguments.. ctx:%p pub_key:%p\n",
				__func__, ctx, key);
		return -1;
	}

	pri_bn = EC_KEY_get0_private_key(key);
	if(pri_bn == NULL) {
		printf("failed to EC_KEY_get0_private_key..\n");
		return -1;
	}

	ret_len = BN_bn2bin(pri_bn, buf);

	return ret_len;
}

/*
 * ecdh_setDPri(BN_CTX *ctx,
 *		unsigned char *buf, int buf_len, EC_KEY *pri_key);
 *
 * buf/buf_len : private key to be set in pri_key
 * pri_key : return private key
 *
 * set_prikey() internally creates BIGNUM from given buf(represents
 * private key in byte array) set the BIGNUM object into pri_key.
 *
 * Assigned BIGNUM is freed together while destroying EC_KEY
 *
 * return 0 on success
 */
static int __ecdh_set_dpri(BN_CTX *ctx,
		unsigned char *buf, int buf_len, EC_KEY *pri_key) {
	BIGNUM *pri_bn = NULL; // Need to free

	if((ctx == NULL) || (pri_key == NULL) ) {
		printf("%s :: invalid arguments.. group:%p pub_key:%p\n",
				__func__, ctx, pri_key);
		return -1;
	}

	pri_bn = BN_bin2bn((const unsigned char *)buf, buf_len, NULL);
	if(pri_bn == NULL) {
		printf("failed to BN_bin2bn.. \n");
		return -1;
	}

	if(!EC_KEY_set_private_key(pri_key, pri_bn)) {
		printf("Failed to EC_KEY_set_private_key..\n");
		goto errout;
	}

	BN_free(pri_bn);
	return 0;
errout:
	BN_free(pri_bn);
	return -1;
}

static SymKey *ecdh_compute(PubKey *pubkey,
		PrivKey *prikey) {
	BN_CTX *ctx = NULL;
	const EC_GROUP *group;
	EC_KEY *ec_pub = NULL;
	EC_KEY *ec_pri = NULL;
	char tmpBuf[128] = {0};
	int rc;

	SymKey *sskey = NULL;

	if ((ctx=BN_CTX_new()) == NULL){
		printf("%s : BN_CTX generation failed.\n", __func__);
		return NULL;
	}

	ec_pub = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	ec_pri = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if (ec_pub == NULL || ec_pri == NULL)
		goto errout;
	group = EC_KEY_get0_group(ec_pri);

#if 0
	if ((ec_pub = EC_KEY_new()) == NULL) goto errout;
	if ((ec_pri = EC_KEY_new()) == NULL) goto errout;
#endif

	rc = __ecdh_set_dpub(ctx, group,
			pubkey->getData(), pubkey->len, ec_pub);
	if(rc != 0) {
		printf("%s set_pubkey failed\n", __func__);
		goto errout;
	}

	rc = __ecdh_set_dpri(ctx,
			prikey->getData(), prikey->len, ec_pri);
	if(rc != 0) {
		printf("%s set_prikey failed\n", __func__);
		goto errout;
	}

	rc = ECDH_compute_key(
			(void *)tmpBuf, KDF1_SHA256_len,
			EC_KEY_get0_public_key(ec_pub),
			ec_pri,
			ecdh_sha256);

	sskey = new SymKey(tmpBuf, rc);

	if (ec_pub) EC_KEY_free(ec_pub);
	if (ec_pri) EC_KEY_free(ec_pri);
	if (ctx) BN_CTX_free(ctx);
	return sskey;
errout:
if (ec_pub) EC_KEY_free(ec_pub);
if (ec_pri) EC_KEY_free(ec_pri);
if (ctx) BN_CTX_free(ctx);
return NULL;
}

int ecdh_gen_keypair(PubKey *pub, PrivKey *pri){
	BN_CTX *ctx = NULL;
	EC_KEY *pair = NULL;
	const EC_GROUP *group;
	int len;

	if ((ctx=BN_CTX_new()) == NULL){
		printf("%s : BN_CTX generation failed.\n", __func__);
		return -1;
	}

	if ((pair = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)) == NULL){
		printf("%s ::  EC_KEY_new_by_curve_name failed\n", __func__);
		goto err;
	}

	group = EC_KEY_get0_group(pair);

	if (!EC_KEY_generate_key(pair)) {
		printf("%s :: EC_KEY_generate_key failed\n", __func__);
		goto err;
	}

	len = __ecdh_get_dpub(ctx,
			pair, (pub)->getData(), ECDH_KEY_MAN_LEN);
	if(len <= 0) {
		printf("extract_pub_key failed. [%d]\n", len);
		goto err;
	} else {
		(pub)->len = len;
	}

	len = __ecdh_get_dpri(ctx,
			pair, (pri)->getData(), ECDH_KEY_MAN_LEN);
	if(len <= 0) {
		printf("extract_pub_key failed. [%d]\n", len);
		goto err_free_kek;
	} else {
		(pri)->len = len;
	}

	if (pair) EC_KEY_free(pair);
	if (ctx) BN_CTX_free(ctx);
	return 0;

err_free_kek:
	delete pub;
	delete pri;
err:
	if (pair) EC_KEY_free(pair);
	if (ctx) BN_CTX_free(ctx);
	return -1;
}

EncItem *ecdh_encrypt(Item *item, PubKey *devDpub) {
	if(item == NULL) {
		printf("%s :: Invalid item\n", __func__);
		return NULL;
	}

	PubKey *dataDpub = new PubKey(CRYPT_ITEM_MAX_LEN, CryptAlg::ECDH);
	PrivKey *dataDpri = new PrivKey(CRYPT_ITEM_MAX_LEN, CryptAlg::ECDH);
	//Generate DH Key Pair
	if(ecdh_gen_keypair(dataDpub, dataDpri)) {
		printf("failed to generate new DH-pair\n");
		return NULL;
	}

	SymKey *sskey = ecdh_compute(devDpub, dataDpri);

//	sskey->dump("ecdh_encrypt: sskey");
	//Get session key (SDPpub,DHpri)
	if(sskey == NULL) {
		printf("failed to compute session key");
		return NULL;
	}


	EncItem *eitem = aes_gcm_encrypt(item, sskey);
	delete dataDpri;
	eitem->setPubKey(dataDpub);
	eitem->encBy = CryptAlg::ECDH;

//	eitem->dump("ecdh_encrypt: eitem");
//	Item::dump((const char *)eitem->auth_tag, 16, "ecdh_encrypt: auth-tag");

	delete sskey;

	return eitem;
}

Item *ecdh_decrypt(EncItem *eitem, PrivKey *devDpri) {
	if(eitem == NULL) {
		printf("%s :: Invalid payload\n", __func__);
		return NULL;
	}

	//Get session key (SDPpub,DHpri)
	SymKey *sskey = ecdh_compute(eitem->getPubKey(), devDpri);
//	sskey->dump("ecdh_decrypt: sskey");
//	eitem->dump("eitem");
//	Item::dump((const char *)eitem->auth_tag, 16, "eitem: auth-tag");

	Item *item = aes_gcm_decrypt(eitem, sskey);
//	item->dump("decrypted");

	delete sskey;

	return item;
}

#if 0
PubKey *devPub;
PrivKey *devPri;

#define TEST_STRING "aaoaoaosakloaksdoaksdplqpwdlqwpdkiegmiewqfkpoqwkfpoqwkfopqwkfopqwkfpoqwkfopqkwfopqwkfop"
static int test_ecdh_curve()
{
	printf("\n\n%s() ===================================\n", __func__);
	Item *pt = new Item(TEST_STRING, strlen(TEST_STRING));

	pt->dump("pt");
	EncItem *eitem = ecdh_encrypt(pt, devPub);

	eitem->getPubKey()->dump("data-pub");
	eitem->dump("eitem");

	Item *pt2 = ecdh_decrypt(eitem, devPri);
	pt2->dump("pt2");

	delete pt;
	delete eitem;
	delete pt2;

	return 1;
}

int main(int argc, char *argv[])
{
	int ret=1;
	int cnt=3;

	CRYPTO_malloc_debug_init();
	CRYPTO_dbg_set_options(V_CRYPTO_MDEBUG_ALL);
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

#ifdef OPENSSL_SYS_WIN32
	CRYPTO_malloc_init();
#endif


	devPub = new PubKey(CRYPT_ITEM_MAX_LEN, 2048, CRYPTO_ALG_ECDH);
	devPri = new PrivKey(CRYPT_ITEM_MAX_LEN, 2048, CRYPTO_ALG_ECDH);

	if(ecdh_gen_keypair(devPub, devPri)) {
		printf("ecdh_GenKeyPair() failed.\n");
		exit(1);
	}

	devPub->dump("dev_pub");
	devPri->dump("dev_pri");

#if 0
	/* NIST PRIME CURVES TESTS */
	if (!test_ecdh_curve(NID_X9_62_prime192v1, "NIST Prime-Curve P-192", ctx)) goto err;
	if (!test_ecdh_curve(NID_secp224r1, "NIST Prime-Curve P-224", ctx)) goto err;
	if (!test_ecdh_curve(NID_X9_62_prime256v1, "NIST Prime-Curve P-256", ctx)) goto err;
	if (!test_ecdh_curve(NID_secp384r1, "NIST Prime-Curve P-384", ctx)) goto err;
	if (!test_ecdh_curve(NID_secp521r1, "NIST Prime-Curve P-521", ctx)) goto err;
	/* NIST BINARY CURVES TESTS */
	if (!test_ecdh_curve(NID_sect163k1, "NIST Binary-Curve K-163", ctx)) goto err;
	if (!test_ecdh_curve(NID_sect163r2, "NIST Binary-Curve B-163", ctx)) goto err;
	if (!test_ecdh_curve(NID_sect233k1, "NIST Binary-Curve K-233", ctx)) goto err;
	if (!test_ecdh_curve(NID_sect233r1, "NIST Binary-Curve B-233", ctx)) goto err;
	if (!test_ecdh_curve(NID_sect283k1, "NIST Binary-Curve K-283", ctx)) goto err;
	if (!test_ecdh_curve(NID_sect283r1, "NIST Binary-Curve B-283", ctx)) goto err;
	if (!test_ecdh_curve(NID_sect409k1, "NIST Binary-Curve K-409", ctx)) goto err;
	if (!test_ecdh_curve(NID_sect409r1, "NIST Binary-Curve B-409", ctx)) goto err;
	if (!test_ecdh_curve(NID_sect571k1, "NIST Binary-Curve K-571", ctx)) goto err;
	if (!test_ecdh_curve(NID_sect571r1, "NIST Binary-Curve B-571", ctx)) goto err;
#endif

#if 0
	while(cnt > 0) {
		if (!test_ecdh_curve(NID_X9_62_prime256v1, "NIST Prime-Curve P-256", ctx)) goto err;
		cnt--;
	}
	if (!test_ecdh_curve(NID_secp521r1, "NIST Prime-Curve P-521", ctx)) goto err;
#endif

	while(cnt > 0) {
		if (!test_ecdh_curve()) goto err;
		cnt--;
	}
	ret = 0;

	delete devPub;
	delete devPri;

	err:
	ERR_print_errors_fp(stderr);
	CRYPTO_cleanup_all_ex_data();
	ERR_remove_thread_state(NULL);
	CRYPTO_mem_leaks_fp(stderr);
	return -1;
	return(ret);
}
#endif
