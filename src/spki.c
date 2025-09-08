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

#include <maid/spki.h>

extern enum maid_spki
maid_spki_import(const u8 *data, size_t size, u8 **stream, size_t *length)
{
    enum maid_spki ret = MAID_SPKI_UNKNOWN;

    u8 *seq = NULL;
    size_t seq_s = 0;

    u8 *current = NULL;
    size_t remain = size;
    if (data && size && stream && length)
    {
        if (maid_asn1_check(0x30, data, remain))
        {
            current = maid_asn1_enter(data, &remain);
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
            *length = maid_asn1_from_bits(stream, current, remain);
            if (*length)
            {
                current = maid_asn1_enter(current, &remain);
                if (*length + 1 == remain)
                    ret = MAID_SPKI_RSA;
            }
        }
        else if (seq_s == 5 && maid_mem_cmp(seq, maid_asn1_seq_ed25519, seq_s))
        {
            if (maid_asn1_from_bits(stream, current, remain) == 32)
            {
                *length = 32;
                ret = MAID_SPKI_ED25519;
            }
        }
    }

    return ret;
}

extern bool
maid_spki_export(enum maid_spki type, const u8 *data, size_t size,
                 u8 **stream, size_t *length)
{
    bool ret = false;

    if (data && size && stream && length)
    {
        const u8 *seq = NULL;
        size_t sizes[2] = {0, maid_asn1_measure_bits(size)};
        switch (type)
        {
            case MAID_SPKI_RSA:
                seq = maid_asn1_seq_rsa;
                sizes[0] = sizeof(maid_asn1_seq_rsa);
                break;
            case MAID_SPKI_ED25519:
                seq = maid_asn1_seq_ed25519;
                sizes[0] = sizeof(maid_asn1_seq_ed25519);
                break;
            default:
                break;
        }

        if (sizes[0])
        {
            size_t seq_s = 0;
            seq_s += maid_asn1_measure_tag(sizes[0]);
            seq_s += maid_asn1_measure_tag(sizes[1]);

            *length = maid_asn1_measure_tag(seq_s);
            *stream = calloc(1, *length);
            if (*stream)
            {
                u8 *output = maid_asn1_to_tag(*stream, 0x30, seq_s);
                output = maid_asn1_to_tag(output, 0x30, sizes[0]);
                output = maid_asn1_to_bytes(output, seq, sizes[0]);
                output = maid_asn1_to_tag(output, 0x03, sizes[1]);
                output = maid_asn1_to_bits(output, data, sizes[1]);
                ret = true;
            }
        }

        maid_mem_clear(sizes, sizeof(sizes));
    }

    return ret;
}
