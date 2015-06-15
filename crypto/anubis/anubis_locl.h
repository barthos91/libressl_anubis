#ifndef HEADER_ANUBIS_LOCL_H
#define HEADER_ANUBIS_LOCL_H

#include <openssl/opensslconf.h>

#ifdef OPENSSL_NO_ANUBIS
#error ANUBIS is disabled.
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GETU32(pt) (((u32)(pt)[0] << 24) ^ ((u32)(pt)[1] << 16) ^ ((u32)(pt)[2] <<  8) ^ ((u32)(pt)[3]))
#define PUTU32(ct, st) { (ct)[0] = (u8)((st) >> 24); (ct)[1] = (u8)((st) >> 16); (ct)[2] = (u8)((st) >>  8); (ct)[3] = (u8)(st); }

typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;

#define MAXKC   (256/32)
#define MAXKB   (256/8)
#define MAXNR   14

/* This controls loop-unrolling in anubis_core.c */
#undef FULL_UNROLL

#endif /* !HEADER_ANUBIS_LOCL_H */
