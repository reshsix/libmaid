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

#include <maid/mem.h>
#include <maid/asn1.h>

#include <maid/pkcs8.h>

extern enum maid_pkcs8
maid_pkcs8_import(const u8 *data, size_t size, u8 **stream, size_t *length)
{
    enum maid_pkcs8 ret = MAID_PKCS8_UNKNOWN;

    u8 *seq = NULL;
    size_t seq_s = 0;

    u8 *current = NULL;
    size_t remain = size;
    if (maid_asn1_check(0x30, data, remain))
    {
        current = maid_asn1_enter(data, &remain);

        /* Only version 0 supported */
        if (maid_asn1_check(0x02, current, remain) &&
            current[1] == 0x01 && current[2] == 0x00)
        {
            current = maid_asn1_advance(current, &remain);
            seq_s = maid_asn1_check(0x30, current, remain);
            if (seq_s)
            {
                current = maid_asn1_enter(current, &remain);
                seq = current;

                current = &(current[seq_s]);
                remain -= seq_s;
            }
        }
    }

    if (seq && seq_s)
    {
        if (seq_s == 13 && maid_mem_cmp(seq, maid_asn1_seq_rsa, seq_s))
        {
            *length = maid_asn1_from_octets(stream, current, remain);
            if (*length)
            {
                current = maid_asn1_advance(current, &remain);
                if (remain == 0)
                    ret = MAID_PKCS8_RSA;
            }
        }
        else if (seq_s == 5 && maid_mem_cmp(seq, maid_asn1_seq_ed25519, seq_s))
        {
            if (maid_asn1_from_octets(stream, current, remain) == 34)
            {
                current = maid_asn1_advance(current, &remain);
                if (remain == 0)
                {
                    ret = MAID_PKCS8_ED25519;
                    *length = 34;
                }
            }
        }
    }

    return ret;
}

extern bool
maid_pkcs8_export(enum maid_pkcs8 type, const u8 *data, size_t size,
                  u8 **stream, size_t *length)
{
    bool ret = false;

    if (data && size && stream && length)
    {
        const u8 *seq = NULL;
        size_t sizes[2] = {0, size};
        switch (type)
        {
            case MAID_PKCS8_RSA:
                seq = maid_asn1_seq_rsa;
                sizes[0] = sizeof(maid_asn1_seq_rsa);
                break;
            case MAID_PKCS8_ED25519:
                seq = maid_asn1_seq_ed25519;
                sizes[0] = sizeof(maid_asn1_seq_ed25519);
                break;
            default:
                break;
        }

        if (sizes[0])
        {
            size_t seq_s = 0;
            seq_s += 3;
            seq_s += maid_asn1_measure_tag(sizes[0]);
            seq_s += maid_asn1_measure_tag(sizes[1]);

            *length = maid_asn1_measure_tag(seq_s);
            *stream = calloc(1, *length);
            if (*stream)
            {
                u8 *output = maid_asn1_to_tag(*stream, 0x30, seq_s);
                output[0] = 0x02;
                output[1] = 0x01;
                output[2] = 0x00;
                output = &(output[3]);

                output = maid_asn1_to_tag(output, 0x30, sizes[0]);
                output = maid_asn1_to_bytes(output, seq, sizes[0]);
                output = maid_asn1_to_tag(output, 0x04, sizes[1]);
                output = maid_asn1_to_bytes(output, data, sizes[1]);
                ret = true;
            }
        }

        maid_mem_clear(sizes, sizeof(sizes));
    }

    return ret;
}
