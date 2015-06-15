#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/anubis.h>
#include "anubis_locl.h"

const char *
ANUBIS_options(void)
{
#ifdef FULL_UNROLL
	return "anubis(full)";
#else   
	return "anubis(partial)";
#endif
}
