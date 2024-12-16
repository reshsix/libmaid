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
#include <maid/pub.h>

#include <maid/import.h>

/* PEM to struct maid_import */

extern struct maid_import *
maid_import_free(struct maid_import *im)
{
    if (im)
    {
        maid_mem_clear(im->data, im->size);
        free(im->data);
    }
    free(im);
    return NULL;
}

extern struct maid_import *
maid_import_pem(const char *input, const char **endptr)
{
    struct maid_import *ret = NULL;

    size_t limit = (input) ? (strlen(input) * 3) / 4 : 0;
    if (limit > 32)
    {
        ret = calloc(1, sizeof(struct maid_import));
        limit -= 32;
    }

    char *label = NULL;
    if (ret)
    {
        label = calloc(1, 49);
        ret->data  = calloc(1, limit);
        if (label && ret->data)
        {
            *endptr = input;
            input = strstr(input, "-----BEGIN ");
        }
    }

    if (*endptr && input && memcmp(input, "-----BEGIN ", 11) == 0)
    {
        const char *a = strchr(&(input[11]), '-');
        if (a && memcmp(a, "-----\n", 6) == 0)
        {
            size_t label_s = a - &(input[11]);
            if (label_s < 49)
            {
                memcpy(label, &(input[11]), label_s);
                label[label_s] = 0;

                const char *b = &(a[6]);
                const char *c = strchr(b, '-');
                if (c && memcmp(c, "-----END ", 9) == 0)
                {
                    const char *d = &(c[9]);
                    if (memcmp(d, label, label_s) == 0 &&
                        memcmp(&(d[label_s]), "-----\n", 6) == 0)
                    {
                        *endptr = &(d[label_s + 6]);

                        u8 *buffer = ret->data;
                        size_t data_s = c - b;
                        while (data_s)
                        {
                            size_t line_s = (data_s < 65) ? data_s : 65;
                            size_t byte_s = ((line_s - 1) * 3) / 4;
                            if (byte_s)
                            {
                                byte_s -= b[line_s - 2] == '=';
                                byte_s -= b[line_s - 3] == '=';
                            }

                            if (maid_mem_import(buffer, limit,
                                                b, line_s - 1) == 0)
                            {
                                *endptr = input;
                                ret->size = 0;
                                break;
                            }
                            b = &(b[line_s]);
                            data_s -= line_s;

                            buffer     = &(buffer[byte_s]);
                            limit     -= byte_s;
                            ret->size += byte_s;
                        }
                    }
                }
            }
        }
    }

    if (ret)
    {
        if (ret->size)
        {
            if      (strcmp(label, "RSA PUBLIC KEY") == 0)
                ret->type = MAID_IMPORT_PUBLIC_RSA;
            else if (strcmp(label, "RSA PRIVATE KEY") == 0)
                ret->type = MAID_IMPORT_PRIVATE_RSA;
            else if (strcmp(label, "PUBLIC KEY") == 0)
                ret->type = MAID_IMPORT_PUBLIC;
            else if (strcmp(label, "PRIVATE KEY") == 0)
                ret->type = MAID_IMPORT_PRIVATE;
            else
                ret->type = MAID_IMPORT_UNKNOWN;
        }
        else
            ret = maid_import_free(ret);
    }

    if (label)
        maid_mem_clear(label, 49);
    free(label);

    return ret;
}

/* ASN.1 parsing */

static u64
maid_asn1_check(u8 id, const u8 *current, size_t remain)
{
    u64 ret = 0;

    if (remain >= 2 && current[0] == id)
    {
        /* Short vs long form */
        u8 octets = (current[1] < 0x80) ? 0x00 : current[1] & ~0x80;

        if (!octets)
            ret = current[1];
        else
        {
            /* Limits long size to 2^64 */
            ret = maid_mem_read(&(current[2]), 0, octets, true);
        }

        /* Rejects invalid long form and out of bounds */
        if (octets == 1 || (ret + octets + 2) > remain)
            ret = 0;
    }

    return ret;
}

static u8 *
maid_asn1_enter(const u8 *current, size_t *remain)
{
    /* Intended to be used only after a succesful check */
    const u8 *new = current;

    if (new[1] < 0x80)
        new = &(new[2]);
    else
    {
        u8 octets = new[1] & ~0x80;
        new = &(new[octets + 2]);
    }
    *remain -= new - current;

    return (u8*)new;
}

static u8 *
maid_asn1_advance(const u8 *current, size_t *remain)
{
    /* Intended to be used only after a succesful check */
    const u8 *new = current;

    if (new[1] < 0x80)
        new = &(new[new[1] + 2]);
    else
    {
        u8 octets = new[1] & ~0x80;
        u64 length = maid_mem_read(&(new[2]), 0, octets, true);
        new = &(new[length + octets + 2]);
    }
    *remain -= new - current;

    return (u8*)new;
}

static maid_mp_word *
maid_asn1_integer(size_t *words, size_t limit,
                  const u8 *buffer, size_t size)
{
    maid_mp_word *ret = NULL;

    u64 bytes = maid_asn1_check(0x02, buffer, size);
    if (bytes)
    {
        bool rejected = false;
        /* Rejects negative and non-DER integers for our purposes */
        u8 *current = maid_asn1_enter(buffer, &size);
        if (current[0] < 0x80)
        {
            if (bytes >= 2 && current[0] == 0x00)
            {
                if (current[1] >= 0x80)
                {
                    current = &(current[1]);
                    bytes -= 1;
                }
                else
                    rejected = true;
            }
        }
        else
            rejected = true;

        size_t words2 = 0, offset = 0, offset2 = 0;
        if (!rejected)
        {
            words2  = maid_mp_words(bytes * 8);
            offset2 = sizeof(maid_mp_word) -
                      ((words2 * sizeof(maid_mp_word)) - bytes);
            if (!limit)
                ret = calloc(sizeof(maid_mp_word), words2);
            else if (words2 <= limit)
            {
                ret = calloc(sizeof(maid_mp_word), limit);
                offset = limit - words2;
                words2 = limit;
            }
        }

        if (ret)
        {
            size_t remain = bytes;
            for (size_t i = 0; i < words2 && remain; i++)
            {
                size_t limit = remain > sizeof(maid_mp_word) ?
                                        sizeof(maid_mp_word) : remain;
                if (i == 0)
                    limit = offset2;

                ret[words2 - i - 1 - offset] =
                    maid_mem_read(current, 0, limit, true);

                current = &(current[limit]);
                remain -= limit;
            }

            if (words)
                *words = words2;
        }
    }

    return ret;
}

static size_t
maid_asn1_oid(u8 **output, const u8 *buffer, size_t size)
{
    size_t ret = 0;

    u64 length = maid_asn1_check(0x06, buffer, size);
    if (length)
    {
        buffer = maid_asn1_enter(buffer, &size);
        if (length <= size)
        {
            *output = (u8*)buffer;
            ret = length;
        }
    }

    return ret;
}

static bool
maid_asn1_null(const u8 *buffer, size_t size)
{
    return (size >= 2) ? buffer[0] == 0x05 && buffer[1] == 0x00 : false;
}

static size_t
maid_asn1_bit_string(u8 **output, const u8 *buffer, size_t size)
{
    size_t ret = 0;

    u64 length = maid_asn1_check(0x03, buffer, size);
    if (length > 1)
    {
        buffer = maid_asn1_enter(buffer, &size);

        /* For our purposes, refuses a bitstring with unused bits */
        if (length <= size && buffer[0] == 0x00)
        {
            *output = (u8*)&(buffer[1]);
            ret = length - 1;
        }
    }

    return ret;
}

static size_t
maid_asn1_octet_string(u8 **output, const u8 *buffer, size_t size)
{
    size_t ret = 0;

    u64 length = maid_asn1_check(0x04, buffer, size);
    if (length)
    {
        buffer = maid_asn1_enter(buffer, &size);
        if (length <= size)
        {
            *output = (u8*)buffer;
            ret = length;
        }
    }

    return ret;
}

/* PKCS parsing */

static maid_pub *
maid_pkcs1_public(struct maid_import *im)
{
    maid_pub *ret = NULL;

    size_t bits = 0;
    struct maid_rsa_key key = {};

    if (maid_asn1_check(0x30, im->data, im->size))
    {
        size_t remain = im->size;
        u8 *current = maid_asn1_enter(im->data, &remain);

        size_t words = 0;

        key.modulo = maid_asn1_integer(&words, words, current, remain);
        if (key.modulo)
        {
            current = maid_asn1_advance(current, &remain);
            key.exponent = maid_asn1_integer(NULL, words, current, remain);
            if (key.exponent)
                current = maid_asn1_advance(current, &remain);
        }

        if (remain == 0)
        {
            bits = words * sizeof(maid_mp_word) * 8;
            ret = maid_pub_new(maid_rsa_public, &key, bits);
        }
    }

    if (bits)
    {
        maid_mem_clear(key.modulo,   bits / 8);
        maid_mem_clear(key.exponent, bits / 8);

        free(key.modulo);
        free(key.exponent);
    }

    return ret;
}

static maid_pub *
maid_pkcs1_private(struct maid_import *im)
{
    maid_pub *ret = NULL;

    size_t bits = 0;
    struct maid_rsa_key key = {};
    maid_mp_word *params[7] = {NULL};

    if (maid_asn1_check(0x30, im->data, im->size))
    {
        size_t remain = im->size;
        u8 *current = maid_asn1_enter(im->data, &remain);

        size_t words = 0;

        /* Only version 0 supported */
        if (maid_asn1_check(0x02, current, remain) &&
            current[1] == 0x01 && current[2] == 0x00)
        {
            current = maid_asn1_advance(current, &remain);
            key.modulo = maid_asn1_integer(&words, words, current, remain);
        }

        if (key.modulo)
        {
            current = maid_asn1_advance(current, &remain);

            for (size_t i = 0; i < sizeof(params)/sizeof(maid_mp_word *); i++)
            {
                if (i == 1)
                {
                    params[i] = maid_asn1_integer(NULL, words,
                                                  current, remain);
                    if (params[i])
                        current = maid_asn1_advance(current, &remain);
                    else
                        break;
                }
                else
                    if (maid_asn1_check(0x02, current, remain))
                        current = maid_asn1_advance(current, &remain);
                    else
                        break;
            }
        }

        if (remain == 0)
        {
            key.exponent = params[1];
            bits = words * sizeof(maid_mp_word) * 8;
            ret = maid_pub_new(maid_rsa_private, &key, bits);
        }
    }

    if (bits)
    {
        maid_mem_clear(key.modulo,   bits / 8);
        maid_mem_clear(key.exponent, bits / 8);

        free(key.modulo);
        free(key.exponent);
    }

    return ret;
}

/* "Public key PKCS8" is actually X.509 SPKI,
 * but it's easier to call it that */
static maid_pub *
maid_pkcs8(struct maid_import *im, bool private)
{
    maid_pub *ret = NULL;

    if (maid_asn1_check(0x30, im->data, im->size))
    {
        size_t remain = im->size;
        u8 *current = maid_asn1_enter(im->data, &remain);

        /* Only version 0 supported (on private key) */
        if (!private || (maid_asn1_check(0x02, current, remain) &&
                         current[1] == 0x01 && current[2] == 0x00))
        {
            if (private)
                current = maid_asn1_advance(current, &remain);

            if (maid_asn1_check(0x30, current, remain))
            {
                current = maid_asn1_enter(current, &remain);

                u8 *oid = NULL;
                size_t oid_s = maid_asn1_oid(&oid, current, remain);
                if (oid_s != 0)
                {
                    current = maid_asn1_advance(current, &remain);

                    struct maid_import im2 = {.type = MAID_IMPORT_UNKNOWN};

                    const u8 rsa_oid[] = {0x2A, 0x86, 0x48, 0x86,
                                          0xF7, 0x0D, 0x01, 0x01, 0x01};
                    if (oid_s == 9 && memcmp(oid, rsa_oid, oid_s) == 0)
                    {
                        if (maid_asn1_null(current, remain))
                        {
                            current = maid_asn1_advance(current, &remain);

                            if (!private)
                            {
                                im2.size = maid_asn1_bit_string
                                               (&(im2.data), current, remain);
                                if (im2.size)
                                {
                                    current = maid_asn1_enter(current,
                                                              &remain);
                                    if (im2.size + 1 == remain)
                                        im2.type = MAID_IMPORT_PUBLIC_RSA;
                                }
                            }
                            else
                            {
                                im2.size = maid_asn1_octet_string
                                               (&(im2.data), current, remain);
                                if (im2.size)
                                {
                                    current = maid_asn1_enter(current,
                                                              &remain);
                                    if (im2.size == remain)
                                        im2.type = MAID_IMPORT_PRIVATE_RSA;
                                }
                            }
                        }
                    }

                    if (im2.type != MAID_IMPORT_UNKNOWN)
                        ret = maid_import_pub(&im2);
                }
            }
        }
    }

    return ret;
}

/* Struct maid_import to Primitives */

extern maid_pub *
maid_import_pub(struct maid_import *im)
{
    maid_pub *ret = NULL;

    if (im)
    {
        switch (im->type)
        {
            case MAID_IMPORT_PUBLIC_RSA:
                ret = maid_pkcs1_public(im);
                break;

            case MAID_IMPORT_PRIVATE_RSA:
                ret = maid_pkcs1_private(im);
                break;

            case MAID_IMPORT_PUBLIC:
                ret = maid_pkcs8(im, false);
                break;

            case MAID_IMPORT_PRIVATE:
                ret = maid_pkcs8(im, true);
                break;

            default:
                break;
        }
    }

    return ret;
}
