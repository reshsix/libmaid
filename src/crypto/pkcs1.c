/*
 *  This file is part of libmaid
 *
 *  Libmaid is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  Libmaid is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *  See the GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with libmaid; if not, see <https://www.gnu.org/licenses/>.
*/

#include <stdlib.h>
#include <string.h>

#include <maid/mem.h>
#include <maid/rsa.h>

#include <maid/sign.h>

enum
{
    PKCS1_v1_5_SHA1,
    PKCS1_v1_5_SHA224,     PKCS1_v1_5_SHA256,
    PKCS1_v1_5_SHA384,     PKCS1_v1_5_SHA512,
    PKCS1_v1_5_SHA512_224, PKCS1_v1_5_SHA512_256,
};

struct pkcs1
{
    size_t words;

    const u8 *der;
    size_t der_s;
    size_t hash_s;

    maid_mp_word *scalar;
    u8 *buffer;

    maid_rsa_public  *pub;
    maid_rsa_private *prv;
};

extern void *
pkcs1_del(void *pkcs1)
{
    if (pkcs1)
    {
        struct pkcs1 *p = pkcs1;

        size_t outl = p->words * sizeof(maid_mp_word);
        maid_mp_mov(p->words, p->scalar, NULL);
        free(p->scalar);
        maid_mem_clear(p->buffer, outl);
        free(p->buffer);

        maid_mem_clear(p, sizeof(struct pkcs1));
    }
    free(pkcs1);

    return NULL;
}

static u8 sha1_der[] = {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
                        0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14};
static u8 sha224_der[] = {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                          0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05,
                          0x00, 0x04, 0x1c};
static u8 sha256_der[] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                          0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
                          0x00, 0x04, 0x20};
static u8 sha384_der[] = {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                          0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
                          0x00, 0x04, 0x30};
static u8 sha512_der[] = {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                          0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
                          0x00, 0x04, 0x40};
static u8 sha512_224_der[] = {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                              0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05, 0x05,
                              0x00, 0x04, 0x1c};
static u8 sha512_256_der[] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                              0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06, 0x05,
                              0x00, 0x04, 0x20};

extern void *
pkcs1_new(u8 version, void *pub, void *prv)
{
    struct pkcs1 *ret = calloc(1, sizeof(struct pkcs1));

    if (ret)
    {
        if (pub && prv)
        {
            ret->words = maid_rsa_size(pub);
            if (ret->words != maid_rsa_size2(prv))
                ret = pkcs1_del(ret);
        }
        else if (pub)
            ret->words = maid_rsa_size(pub);
        else if (prv)
            ret->words = maid_rsa_size(prv);
    }

    if (ret)
    {
        ret->pub = pub;
        ret->prv = prv;

        switch (version)
        {
            case PKCS1_v1_5_SHA1:
                ret->der    = sha1_der;
                ret->der_s  = sizeof(sha1_der);
                ret->hash_s = 20;
                break;
            case PKCS1_v1_5_SHA224:
                ret->der    = sha224_der;
                ret->der_s  = sizeof(sha224_der);
                ret->hash_s = 28;
                break;
            case PKCS1_v1_5_SHA256:
                ret->der    = sha256_der;
                ret->der_s  = sizeof(sha256_der);
                ret->hash_s = 32;
                break;
            case PKCS1_v1_5_SHA384:
                ret->der    = sha384_der;
                ret->der_s  = sizeof(sha384_der);
                ret->hash_s = 48;
                break;
            case PKCS1_v1_5_SHA512:
                ret->der    = sha512_der;
                ret->der_s  = sizeof(sha512_der);
                ret->hash_s = 64;
                break;
            case PKCS1_v1_5_SHA512_224:
                ret->der    = sha512_224_der;
                ret->der_s  = sizeof(sha512_224_der);
                ret->hash_s = 28;
                break;
            case PKCS1_v1_5_SHA512_256:
                ret->der    = sha512_256_der;
                ret->der_s  = sizeof(sha512_256_der);
                ret->hash_s = 32;
                break;
        }

        size_t outl = ret->words * sizeof(maid_mp_word);
        ret->scalar = calloc(1, outl);
        ret->buffer = calloc(1, outl);
        if (!(ret->scalar && ret->buffer))
            ret = pkcs1_del(ret);
    }

    return ret;
}

extern bool
pkcs1_size(void *pkcs1, size_t *hash_s, size_t *sign_s)
{
    bool ret = true;

    struct pkcs1 *p = pkcs1;
    if (hash_s)
        *hash_s = p->hash_s;
    if (sign_s)
        *sign_s = p->words * sizeof(maid_mp_word);

    return ret;
}

extern bool
pkcs1_generate(void *pkcs1, const u8 *hash, u8 *sign)
{
    bool ret = true;

    struct pkcs1 *p = pkcs1;
    size_t outl = p->words * sizeof(maid_mp_word);

    sign[0] = 0x00;
    sign[1] = 0x01;
    for (size_t i = 2; i < outl - p->hash_s - p->der_s - 1; i++)
        sign[i] = 0xFF;

    memcpy(&(sign[outl - p->hash_s - p->der_s]), p->der, p->der_s);
    sign[outl - p->hash_s - p->der_s - 1] = 0x0;
    memcpy(&(sign[outl - p->hash_s]), hash, p->hash_s);

    maid_mp_read(p->words, p->scalar, sign, true);
    if (maid_rsa_decrypt(p->prv, p->scalar))
        maid_mp_write(p->words, p->scalar, sign, true);
    else
        ret = false;

    return ret;
}

extern bool
pkcs1_verify(void *pkcs1, const u8 *hash, const u8 *sign)
{
    volatile bool ret = true;

    struct pkcs1 *p = pkcs1;

    maid_mp_read(p->words, p->scalar, sign, true);
    maid_rsa_encrypt(p->pub, p->scalar);
    maid_mp_write(p->words, p->scalar, p->buffer, true);

    size_t outl = p->words * sizeof(maid_mp_word);
    ret &= (p->buffer[0] == 0x00);
    ret &= (p->buffer[1] == 0x01);
    for (size_t i = 2; i < outl - p->hash_s - p->der_s - 1; i++)
        ret &= (p->buffer[i] == 0xFF);

    for (size_t i = 0; i < p->der_s; i++)
        ret &= (p->buffer[outl - p->hash_s - p->der_s + i] == p->der[i]);
    ret &= (p->buffer[outl - p->hash_s - p->der_s - 1] == 0x0);

    ret &= maid_mem_cmp(hash, &(p->buffer[outl - p->hash_s]), p->hash_s);

    return ret;
}

/* Maid SIGN definitions */

const struct maid_sign_def maid_pkcs1_v1_5_sha1 =
{
    .new      = pkcs1_new,
    .del      = pkcs1_del,
    .size     = pkcs1_size,
    .generate = pkcs1_generate,
    .verify   = pkcs1_verify,
    .version  = PKCS1_v1_5_SHA1
};

const struct maid_sign_def maid_pkcs1_v1_5_sha224 =
{
    .new      = pkcs1_new,
    .del      = pkcs1_del,
    .size     = pkcs1_size,
    .generate = pkcs1_generate,
    .verify   = pkcs1_verify,
    .version  = PKCS1_v1_5_SHA224
};

const struct maid_sign_def maid_pkcs1_v1_5_sha256 =
{
    .new      = pkcs1_new,
    .del      = pkcs1_del,
    .size     = pkcs1_size,
    .generate = pkcs1_generate,
    .verify   = pkcs1_verify,
    .version  = PKCS1_v1_5_SHA256
};

const struct maid_sign_def maid_pkcs1_v1_5_sha384 =
{
    .new      = pkcs1_new,
    .del      = pkcs1_del,
    .size     = pkcs1_size,
    .generate = pkcs1_generate,
    .verify   = pkcs1_verify,
    .version  = PKCS1_v1_5_SHA384
};

const struct maid_sign_def maid_pkcs1_v1_5_sha512 =
{
    .new      = pkcs1_new,
    .del      = pkcs1_del,
    .size     = pkcs1_size,
    .generate = pkcs1_generate,
    .verify   = pkcs1_verify,
    .version  = PKCS1_v1_5_SHA512
};

const struct maid_sign_def maid_pkcs1_v1_5_sha512_224 =
{
    .new      = pkcs1_new,
    .del      = pkcs1_del,
    .size     = pkcs1_size,
    .generate = pkcs1_generate,
    .verify   = pkcs1_verify,
    .version  = PKCS1_v1_5_SHA512_224
};

const struct maid_sign_def maid_pkcs1_v1_5_sha512_256 =
{
    .new      = pkcs1_new,
    .del      = pkcs1_del,
    .size     = pkcs1_size,
    .generate = pkcs1_generate,
    .verify   = pkcs1_verify,
    .version  = PKCS1_v1_5_SHA512_256
};
