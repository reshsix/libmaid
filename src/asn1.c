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

#include <maid/mp.h>
#include <maid/mem.h>

#include <maid/asn1.h>

/* OIDs sequences for SPKI and PKCS8 */

const u8 maid_asn1_seq_rsa[] = {0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
                                0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00};
const u8 maid_asn1_seq_ed25519[] = {0x06, 0x03, 0x2b, 0x65, 0x70};

/* ASN.1 reading */

extern u64
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
        if ((octets && ret == 1) || (ret + octets + 2) > remain)
            ret = 0;
    }

    return ret;
}

extern u8 *
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

extern u8 *
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

extern bool
maid_asn1_is_null(const u8 *buffer, size_t size)
{
    return (size >= 2) ? buffer[0] == 0x05 && buffer[1] == 0x00 : false;
}

extern maid_mp_word *
maid_asn1_from_integer(const u8 *buffer, size_t size, size_t *words)
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
            if (!words || *words == 0)
                ret = calloc(sizeof(maid_mp_word), words2);
            else if (words2 <= *words)
            {
                ret = calloc(sizeof(maid_mp_word), *words);
                offset = *words - words2;
                words2 = *words;
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

            if (words && *words == 0)
                *words = words2;
        }
    }

    return ret;
}

extern size_t
maid_asn1_from_oid(u8 **output, const u8 *buffer, size_t size)
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

extern size_t
maid_asn1_from_bits(u8 **output, const u8 *buffer, size_t size)
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

extern size_t
maid_asn1_from_octets(u8 **output, const u8 *buffer, size_t size)
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

/* ASN.1 writing */

extern size_t
maid_asn1_measure_tag(size_t size)
{
    size_t ret = size;

    if (ret > 0x7F)
    {
        if      (ret < 0xFF)             ret += 1;
        else if (ret < 0xFFFF)           ret += 2;
        else if (ret < 0xFFFFFF)         ret += 3;
        else if (ret < 0xFFFFFFFF)       ret += 4;
        else if (ret < 0xFFFFFFFFFF)     ret += 5;
        else if (ret < 0xFFFFFFFFFFFF)   ret += 6;
        else if (ret < 0xFFFFFFFFFFFFFF) ret += 7;
        else                             ret += 8;
    }

    return ret + 2;
}

extern size_t
maid_asn1_measure_integer(size_t words, maid_mp_word *input)
{
    /* Returns the number of bytes that will be used (except in tag part) */
    size_t ret = 0;

    volatile u8 buf = 0;
    for (size_t i = 0; i < words * sizeof(maid_mp_word); i++)
    {
        /* Inverts order, from highest byte to lowest */
        size_t j = (words * sizeof(maid_mp_word)) - i - 1;
        size_t w = j / sizeof(maid_mp_word);
        size_t z = j % sizeof(maid_mp_word);

        buf = (input[w] >> (z * 8)) & 0xFF;
        if (buf != 0)
        {
            ret = j + 1;
            if (buf & 0x80)
                ret++;
            break;
        }
    }
    buf = 0;

    return ret;
}

extern size_t
maid_asn1_measure_bits(size_t size)
{
    /* A byte for unused bits */
    return 1 + size;
}

extern u8 *
maid_asn1_to_tag(u8 *output, u8 id, size_t size)
{
    u8 *ret = &(output[2]);

    output[0] = id;
    if (size > 0x7F)
    {
        u8 bytes = 0;
        if      (size < 0xFF)             bytes = 1;
        else if (size < 0xFFFF)           bytes = 2;
        else if (size < 0xFFFFFF)         bytes = 3;
        else if (size < 0xFFFFFFFF)       bytes = 4;
        else if (size < 0xFFFFFFFFFF)     bytes = 5;
        else if (size < 0xFFFFFFFFFFFF)   bytes = 6;
        else if (size < 0xFFFFFFFFFFFFFF) bytes = 7;
        else                              bytes = 8;
        output[1] = 0x80 | bytes;

        for (u8 i = 0; i < bytes; i++)
        {
            size_t j = bytes - i - 1;
            output[2 + i] = (size >> (j * 8)) & 0xFF;
        }

        ret = &(ret[bytes]);
    }
    else
        output[1] = size;

    return ret;
}

extern u8 *
maid_asn1_to_integer(u8 *output, size_t words,
                     maid_mp_word *input, size_t size)
{
    if (size > sizeof(maid_mp_word) * words)
    {
        output[0] = 0x00;
        output = &(output[1]);
        size -= 1;
    }

    for (size_t i = 0; i < size; i++)
    {
        size_t j = size - i - 1;
        size_t w = j / sizeof(maid_mp_word);
        size_t z = j % sizeof(maid_mp_word);

        output[i] = (input[w] >> (z * 8)) & 0xFF;
    }

    return &(output[size]);
}

extern u8 *
maid_asn1_to_bits(u8 *output, const u8 *data, size_t size)
{
    output[0] = 0;
    memcpy(&(output[1]), data, size);
    return &(output[size + 1]);
}

extern u8 *
maid_asn1_to_bytes(u8 *output, const u8 *data, size_t size)
{
    memcpy(output, data, size);
    return &(output[size]);
}
