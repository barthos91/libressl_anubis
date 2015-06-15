#include <openssl/anubis.h>
#include <openssl/modes.h>

void
ANUBIS_cbc_encrypt(const unsigned char *in, unsigned char *out,
    size_t len, const NESSIEstruct *key, unsigned char *ivec, const int enc)
{

//~ printf("ANUBIS_cbc_encrypt: start\n");
//~ printf("e_anubis.c -> R : %d\n", key->R);
	if (enc)
		CRYPTO_cbc128_encrypt(in, out, len, key, ivec,
		    (block128_f)NESSIEencrypt);
	else
		CRYPTO_cbc128_decrypt(in, out, len, key, ivec,
		    (block128_f)NESSIEdecrypt);
//~ printf("ANUBIS_cbc_encrypt: end\n");
}
