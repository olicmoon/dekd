#include <sdp/dek_common.h>
#include <sdp/rsa.h>

#define	 KEY_TYPE_PUBLIC				1
#define	 KEY_TYPE_PAIR				2

const unsigned int RSA_bits		= KEK_RSA_KEY_BITS;
static void __gen_keypair(kek_t *pair);

int rsa_gen_keypair(kek_t *pub, kek_t *pri) {
	pri->len = RSA_bits;
	pri->type = KEK_TYPE_RSA_PRIV;
	__gen_keypair(pri);

    pub->len = RSA_bits;
    pub->type = KEK_TYPE_RSA_PUB;
	rsa_getPublicKey(pri, pub);

	return 0;
}

static void __gen_keypair(kek_t *pair)
{
    BIGNUM* bn = BN_new();
	unsigned char*	n = NULL;
	unsigned char*	d = NULL;
	unsigned short slen, nlen, dlen;
	unsigned char* p;
	RSA*	key = NULL;

    BN_add_word(bn, RSA_F4);
    key = RSA_new();
    if(key == NULL) {
    	SDP_LOGE("%s, can't create RSA object\n", __func__);
    	return;
    }

	// 512bit key for 64byte block encryption
    RSA_generate_key_ex(key, RSA_bits, bn, NULL);

    n = (unsigned char*)malloc(RSA_bits/2);
    d = (unsigned char*)malloc(RSA_bits/2);
    nlen = BN_bn2bin(key->n, n);
    dlen = BN_bn2bin(key->d, d);
    //SDP_LOGE("N=%s\n", BN_bn2dec(key->n));
    //SDP_LOGE("D=%s\n", BN_bn2dec(key->d));

	slen = ((nlen & 0x00ff) << 8) | ((nlen & 0xff00) >> 8);
	p = pair->buf;
	memcpy(p, &slen, 2);
	p += 2;
	memcpy(p, n, nlen);
	p += nlen;

	slen = ((dlen & 0x00ff) << 8) | ((dlen & 0xff00) >> 8);
	memcpy(p, &slen, 2);
	p += 2;
	memcpy(p, d, dlen);
	p += dlen;
	pair->len = nlen + dlen + 4;

	if(key)	RSA_free(key);
	if (n){
        memset(n, 0, RSA_bits/2);
	    free(n);
    }
	if (d) {
        memset(d, 0, RSA_bits/2);
	    free(d);
    }
}

void rsa_getPublicKey(kek_t *pair, kek_t *pub_key)
{
	short slen;
    unsigned int len;
	unsigned char *p;

	p = (unsigned char*)pair->buf;
	memcpy(&slen, p, 2);
	len = ((slen & 0x00ff) << 8) | ((slen & 0xff00) >> 8);
	p += 2;
    //SDP_LOGE("RSA get pub key len=%d\n", len);
    if (len > pub_key->len)
        return;

	memcpy(pub_key->buf, pair->buf, 2+len);
    pub_key->len = 2+len;
}

static int byteToKey(const unsigned char* byte, unsigned int byteLen, RSA* key, int type)
{
	unsigned short slen;
	unsigned int len;
	unsigned char *p = (unsigned char*)byte;

	memcpy(&slen, p, 2);
	len = ((slen & 0x00ff) << 8) | ((slen & 0xff00) >> 8);
	if (2 + len > byteLen)
		return -1;
	p += 2;

	key->n = BN_new();
	BN_bin2bn(p, len, key->n);
	p += len;
	if (type == KEY_TYPE_PAIR) {
		unsigned int len2;

		if (byteLen < 2 + len)
			return -1;
		memcpy(&slen, p, 2);
		len2 = ((slen & 0x00ff) << 8) | ((slen & 0xff00) >> 8);
		p += 2;
		if (byteLen < 2 + len + 2 + len2)
			return -1;

		key->d = BN_new();
		BN_bin2bn(p, len2, key->d);
	}

	key->e = BN_new();
	BN_add_word(key->e, RSA_F4);
	return 0;
}

int rsa_encrypt_dek(dek_t *in, dek_t *out, kek_t *pub_key)
{
	RSA*	key = NULL;
	unsigned char* buf = NULL;
	int num, rc;
	int ret = -1;

	if (in->len > RSA_bits/8 - 6) {
		SDP_LOGE("RSA enc max block byte is %d\n", RSA_bits/8 - 6);
		out->len = 0;
		goto out;
	}
    key = RSA_new();
	rc = byteToKey(pub_key->buf, pub_key->len, key, KEY_TYPE_PUBLIC);
	if (rc < 0) {
		SDP_LOGE("RSA key format is not correct\n");
		out->len = 0;
		goto out;
	}

	// RSA enc block size must be 64. put byte size on first 2 byte and pad by 0
	buf = (unsigned char*)malloc(RSA_bits/8);
	memset(buf, 0, RSA_bits/8);
	// Put 4 byte tag for detecting wrong key enc/dec TODO:not put constant string
	strncpy((char *)buf, "KNOX", 4);
	buf[4] = 0;
	buf[5] = (unsigned char)in->len;
	memcpy(buf+6, in->buf, in->len);
	num = RSA_public_encrypt(RSA_bits/8, buf, out->buf, key, RSA_NO_PADDING);
    out->len = num;
    out->type = DEK_TYPE_RSA_ENC;

    if(num == -1)
    	ret = -1;
    else
    	ret = 0;

out:
    if (key)
    	RSA_free(key);
    if(buf) {
        memset(buf, 0, RSA_bits/8);
    	free(buf);
    }

    return ret;
}

int rsa_decrypt_edek(dek_t *in, dek_t *out, kek_t *pair)
{
	RSA*	key = NULL;
	unsigned char* buf = NULL;
	int rc;
	int ret = -1;
	//SDP_DUMP((unsigned char *)pair->buf, pair->len, "rsa-dec Rpri");
	//SDP_DUMP((unsigned char *)in->buf, in->len, "rsa-dec edek");
    key = RSA_new();
    rc = byteToKey(pair->buf, pair->len, key, KEY_TYPE_PAIR);
	if (rc < 0) {
		SDP_LOGE("RSA key format is not correct\n");
		out->len = 0;
		goto out;
	}
	buf = (unsigned char*)malloc(RSA_bits/8);
	rc = RSA_private_decrypt(RSA_bits/8, in->buf, buf, key, RSA_NO_PADDING);
	// Check 4 byte tag
	if (strncmp((char *)buf, "KNOX", 4) != 0) {
		SDP_LOGE("RSA Key Pair is not correct\n");
		out->len = 0;
		goto out;
	}

	out->len = (unsigned int)buf[5];
	memcpy(out->buf, buf+6, out->len);
	out->type = DEK_TYPE_PLAIN;

	ret = 0;

	out:
	if (key)
        RSA_free(key);
    if (buf) {
        memset(buf, 0, RSA_bits/8);
    	free(buf);
    }
    return ret;
}
