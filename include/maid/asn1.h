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

#ifndef MAID_ASN1_H
#define MAID_ASN1_H

#include <maid/types.h>

#include <maid/mp.h>

u64 maid_asn1_check(u8 id, const u8 *current, size_t remain);
u8 *maid_asn1_enter(const u8 *current, size_t *remain);
u8 *maid_asn1_advance(const u8 *current, size_t *remain);

bool maid_asn1_is_null(const u8 *buffer, size_t size);
maid_mp_word *maid_asn1_from_integer(const u8 *buffer, size_t size,
                                     size_t *words);
size_t maid_asn1_from_oid(u8 **output, const u8 *buffer, size_t size);
size_t maid_asn1_from_bits(u8 **output, const u8 *buffer, size_t size);
size_t maid_asn1_from_octets(u8 **output, const u8 *buffer, size_t size);

size_t maid_asn1_measure_tag(size_t size);
size_t maid_asn1_measure_integer(size_t words, maid_mp_word *input);
size_t maid_asn1_measure_bits(size_t size);
u8 *maid_asn1_to_tag(u8 *output, u8 id, size_t size);
u8 *maid_asn1_to_integer(u8 *output, size_t words,
                         maid_mp_word *input, size_t size);
u8 *maid_asn1_to_bits(u8 *output, const u8 *data, size_t size);
u8 *maid_asn1_to_bytes(u8 *output, const u8 *data, size_t size);

extern const u8 maid_asn1_seq_rsa[13];
extern const u8 maid_asn1_seq_ed25519[5];

#endif
