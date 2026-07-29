/*************************************************************************/
/*                    Copyright (c) 2000-2026 NT KERNEL.                 */
/*                           All Rights Reserved.                        */
/*                          https://www.ntkernel.com                     */
/*                           ndisrd@ntkernel.com                         */
/*                                                                       */
/* Module Name:  inet_checksum.h                                         */
/*                                                                       */
/* Description: Wide (RFC 1071) Internet checksum accumulation           */
/*                                                                       */
/* Environment:                                                          */
/*   User mode                                                           */
/*                                                                       */
/*************************************************************************/

#pragma once

#include <cstdint>
#include <cstring>

namespace inet_checksum
{
    /// <summary>
    /// 16-bit one's-complement sum (NOT complemented) of a byte span, in the
    /// big-endian word domain, i.e. exactly the value the byte-pair loop
    /// <c>sum += (buff[i] &lt;&lt; 8) | buff[i + 1]</c> accumulates and folds.
    /// Callers add their pseudo-header words to it, fold, and complement,
    /// unchanged.
    /// </summary>
    /// <remarks>
    /// The Internet checksum is byte-order independent up to one byte swap of
    /// the folded result (RFC 1071 section 2(B)), so the hot loop accumulates
    /// native little-endian 32-bit words and only the final 16 bits are
    /// swapped. The invariant this rests on: for every span and every length
    /// parity, folding the little-endian sum and swapping equals folding the
    /// big-endian byte-pair sum (with a zero pad byte for odd lengths), and
    /// the 0x0000-versus-0xFFFF folding boundary cannot diverge because a
    /// folded sum is zero only for an all-zero argument in both formulations.
    /// Any change here must keep a differential test against the byte-pair
    /// formulation green across odd/even lengths and all start alignments.
    ///
    /// Accumulating 32-bit loads into 64-bit accumulators needs no carry
    /// handling at all -- a uint64_t absorbs 2^32 such additions, and an IPv4
    /// payload is bounded far below that -- so the loop is portable across
    /// x86, x64 and ARM64 with no intrinsics. Four independent accumulators
    /// break the dependency chain that made the byte-pair loop front-end
    /// bound; measured on one out-of-order x64 core, the cost drops from
    /// 1.1-1.7 cycles/byte to roughly 0.21-0.26.
    ///
    /// An ODD length is handled with a masked tail load. The byte-pair loop
    /// instead wrote a zero pad byte into the packet buffer one past the
    /// payload before reading it back; this function never writes anywhere.
    /// </remarks>
    /// <param name="data">Start of the span. No alignment requirement.</param>
    /// <param name="length">Span length in bytes. Zero yields zero.</param>
    /// <returns>The folded, uncomplemented sum, in [0x0000, 0xFFFF].</returns>
    inline uint16_t sum16_be(const unsigned char* data, const size_t length) noexcept
    {
        uint64_t s0 = 0, s1 = 0, s2 = 0, s3 = 0;
        size_t i = 0;

        for (; i + 16 <= length; i += 16)
        {
            uint32_t w0, w1, w2, w3;
            std::memcpy(&w0, data + i, 4);
            std::memcpy(&w1, data + i + 4, 4);
            std::memcpy(&w2, data + i + 8, 4);
            std::memcpy(&w3, data + i + 12, 4);
            s0 += w0;
            s1 += w1;
            s2 += w2;
            s3 += w3;
        }

        for (; i + 4 <= length; i += 4)
        {
            uint32_t w;
            std::memcpy(&w, data + i, 4);
            s0 += w;
        }

        // Masked tail: up to three bytes. The 4-byte blocks above end on an
        // even offset, so within this final word the byte at relative offset r
        // belongs at little-endian lane r -- which is precisely what building
        // the word with shifts 0/8/16 produces. Never reads past `length`.
        if (i < length)
        {
            uint32_t w = 0;
            unsigned shift = 0;
            for (; i < length; ++i, shift += 8)
                w |= static_cast<uint32_t>(data[i]) << shift;
            s0 += w;
        }

        uint64_t sum = s0 + s1 + s2 + s3;
        while (sum >> 32)
            sum = (sum & 0xFFFFFFFFull) + (sum >> 32);

        uint32_t folded = static_cast<uint32_t>(sum);
        while (folded >> 16)
            folded = (folded & 0xFFFF) + (folded >> 16);

        // Swap into the big-endian word domain the callers accumulate
        // pseudo-header words in.
        return static_cast<uint16_t>(((folded & 0xFF) << 8) | (folded >> 8));
    }
}
