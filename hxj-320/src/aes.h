/*
 * Copyright 2002-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef AES_OPENSSL_H
# define AES_OPENSSL_H

# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <stdint.h>

#define AES_BLOCK_SIZE 16

typedef uint64_t u64;
# ifdef AES_LONG
typedef unsigned long u32;
# else
typedef unsigned int u32;
# endif
typedef unsigned short u16;
typedef unsigned char u8;


# if defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_AMD64) || defined(_M_X64))
#  define SWAP(x) (_lrotl(x, 8) & 0x00ff00ff | _lrotr(x, 8) & 0xff00ff00)
#  define GETU32(p) SWAP(*((u32 *)(p)))
#  define PUTU32(ct, st) { *((u32 *)(ct)) = SWAP((st)); }
# else
#  define GETU32(pt) (((u32)(pt)[0] << 24) ^ ((u32)(pt)[1] << 16) ^ ((u32)(pt)[2] <<  8) ^ ((u32)(pt)[3]))
#  define PUTU32(ct, st) { (ct)[0] = (u8)((st) >> 24); (ct)[1] = (u8)((st) >> 16); (ct)[2] = (u8)((st) >>  8); (ct)[3] = (u8)(st); }
# endif

# define MAXKC   (256/32)
# define MAXKB   (256/8)
# define MAXNR   14

/* This controls loop-unrolling in aes_core.c */
# undef FULL_UNROLL

/* Complete the AES_KEY structure based on its usage in the code.
   The key schedule (rd_key) must hold up to 60 32-bit words 
   (i.e. 4*(rounds+1) where rounds=14 for 256-bit AES),
   and a field 'rounds' stores the total number of rounds. */
typedef struct {
    int rounds;
    u32 rd_key[60];
} AES_KEY;

int AES_set_encrypt_key(const unsigned char *userKey, const int bits,
                        AES_KEY *key);

int AES_set_decrypt_key(const unsigned char *userKey, const int bits,
                        AES_KEY *key);

void AES_encrypt(const unsigned char *in, unsigned char *out,
                 const AES_KEY *key);

void AES_decrypt(const unsigned char *in, unsigned char *out,
                 const AES_KEY *key);


#endif                          /* !AES_OPENSSL_H */
