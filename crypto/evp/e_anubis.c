#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_ANUBIS

#include <openssl/anubis.h>
#include <openssl/evp.h>
#include <openssl/objects.h>

#include "evp_locl.h"
#include "modes_lcl.h"

typedef struct {
	NESSIEstruct ks;
	block128_f block;
	cbc128_f cbc;
} EVP_ANUBIS_KEY;

static int anubis_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
    const unsigned char *in, size_t len);

static int anubis_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
    const unsigned char *iv, int enc);

static const EVP_CIPHER anubis_128_cipher = {
	.nid = NID_anubis_128_cbc,
	.block_size = 16,
	.key_len = 128 / 8,
	.iv_len = 16,
	.flags = EVP_CIPH_CBC_MODE,
	.init = anubis_init,
	.do_cipher = anubis_cipher,
	.ctx_size = sizeof(NESSIEstruct)
};

static const EVP_CIPHER anubis_160_cipher = {
	.nid = NID_anubis_160_cbc,
	.block_size = 16,
	.key_len = 160 / 8,
	.iv_len = 16,
	.flags = EVP_CIPH_CBC_MODE,
	.init = anubis_init,
	.do_cipher = anubis_cipher,
	.ctx_size = sizeof(NESSIEstruct)
};

static const EVP_CIPHER anubis_192_cipher = {
	.nid = NID_anubis_192_cbc,
	.block_size = 16,
	.key_len = 192 / 8,
	.iv_len = 16,
	.flags = EVP_CIPH_CBC_MODE,
	.init = anubis_init,
	.do_cipher = anubis_cipher,
	.ctx_size = sizeof(NESSIEstruct)
};

static const EVP_CIPHER anubis_224_cipher = {
	.nid = NID_anubis_224_cbc,
	.block_size = 16,
	.key_len = 224 / 8,
	.iv_len = 16,
	.flags = EVP_CIPH_CBC_MODE,
	.init = anubis_init,
	.do_cipher = anubis_cipher,
	.ctx_size = sizeof(NESSIEstruct)
};

static const EVP_CIPHER anubis_256_cipher = {
	.nid = NID_anubis_256_cbc,
	.block_size = 16,
	.key_len = 256 / 8,
	.iv_len = 16,
	.flags = EVP_CIPH_CBC_MODE,
	.init = anubis_init,
	.do_cipher = anubis_cipher,
	.ctx_size = sizeof(NESSIEstruct)
};

static const EVP_CIPHER anubis_288_cipher = {
	.nid = NID_anubis_288_cbc,
	.block_size = 16,
	.key_len = 288 / 8,
	.iv_len = 16,
	.flags = EVP_CIPH_CBC_MODE,
	.init = anubis_init,
	.do_cipher = anubis_cipher,
	.ctx_size = sizeof(NESSIEstruct)
};

static const EVP_CIPHER anubis_320_cipher = {
	.nid = NID_anubis_288_cbc,
	.block_size = 16,
	.key_len = 288 / 8,
	.iv_len = 16,
	.flags = EVP_CIPH_CBC_MODE,
	.init = anubis_init,
	.do_cipher = anubis_cipher,
	.ctx_size = sizeof(NESSIEstruct)
};


const EVP_CIPHER *
EVP_anubis_128_cbc(void)
{
	return (&anubis_128_cipher);
}

const EVP_CIPHER *
EVP_anubis_160_cbc(void)
{
	return (&anubis_160_cipher);
}

const EVP_CIPHER *
EVP_anubis_192_cbc(void)
{
	return (&anubis_192_cipher);
}

const EVP_CIPHER *
EVP_anubis_224_cbc(void)
{
	return (&anubis_224_cipher);
}

const EVP_CIPHER *
EVP_anubis_256_cbc(void)
{
	return (&anubis_256_cipher);
}

const EVP_CIPHER *
EVP_anubis_288_cbc(void)
{
	return (&anubis_288_cipher);
}

const EVP_CIPHER *
EVP_anubis_320_cbc(void)
{
	return (&anubis_320_cipher);
}

static int
anubis_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
    const unsigned char *iv, int enc)
{
	int ret, mode;
	EVP_ANUBIS_KEY *dat = (EVP_ANUBIS_KEY *)ctx->cipher_data;
	
	mode = ctx->cipher->flags & EVP_CIPH_MODE;
	if ((mode == EVP_CIPH_CBC_MODE) &&    !enc) {
		ret = NESSIEkeysetup(key, ctx->key_len * 8,
		     &dat->ks);
		//dat->block = (block128_f)NESSIEdecrypt;
		dat->cbc = (cbc128_f)ANUBIS_cbc_encrypt;
	} else {
		ret = NESSIEkeysetup(key, ctx->key_len * 8,
		     &dat->ks);
		//dat->block = (block128_f)NESSIEencrypt;
		dat->cbc = (cbc128_f)ANUBIS_cbc_encrypt;
	}
	
	if (ret < 0) {
		printf("e_anubis.c	->	anubis_init: ret < 0 ERROR");		
		//EVPerr(EVP_F_AESNI_INIT_KEY, EVP_R_AES_KEY_SETUP_FAILED);
		return 0;
	}
	return 1;
}

static int
anubis_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in,
    size_t len)
{
    EVP_ANUBIS_KEY *dat = (EVP_ANUBIS_KEY *)ctx->cipher_data;

    if (dat->cbc){
        (*dat->cbc)(in, out, len, &dat->ks, ctx->iv,ctx->encrypt);
	}
	//~ else if (ctx->encrypt){
		//~ CRYPTO_cbc128_encrypt(in, out, len, &dat->ks, ctx->iv,dat->block);
	//~ }
	//~ else{
		//~ CRYPTO_cbc128_decrypt(in, out, len, &dat->ks, ctx->iv,dat->block);
	//~ }


    return 1;
}

#endif
