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

// This header is compiled by every project that builds ndisapi.cpp, including
// the legacy VC6/VS2012 ones (ndisapi.vc6/ndisapi.dsp), so it cannot assume
// C++11. <cstdint> arrived with VS2010 (_MSC_VER 1600) and `noexcept` with
// VS2015 (1900); older MSVC gets typedefs onto the compiler's built-in
// __int64 and an empty noexcept macro. The body itself avoids everything VC6
// chokes on: no `ull` literal suffixes, no per-loop redeclaration of the
// index variable.
//
// INET_CHECKSUM_FORCE_LEGACY_COMPAT exists so a modern compiler can be forced
// down the legacy branch, which is how that branch is compile- and
// correctness-tested without a VC6 installation. It changes types and
// spelling only, never values.
// <stddef.h> in both branches: sum16_be's signature uses unqualified size_t,
// and only the C header is guaranteed to place it in the global namespace --
// <cstring>/<cstddef> promise std::size_t, with global injection unspecified.
#include <stddef.h>

#if (defined(_MSC_VER) && _MSC_VER < 1600) || defined(INET_CHECKSUM_FORCE_LEGACY_COMPAT)
#include <string.h>
#define INET_CHECKSUM_MEMCPY ::memcpy
namespace inet_checksum
{
    typedef unsigned __int64 sum_uint64;
    typedef unsigned int sum_uint32;
    typedef unsigned short sum_uint16;
}
#else
#include <cstdint>
#include <cstring>
#define INET_CHECKSUM_MEMCPY ::std::memcpy
namespace inet_checksum
{
    typedef ::std::uint64_t sum_uint64;
    typedef ::std::uint32_t sum_uint32;
    typedef ::std::uint16_t sum_uint16;
}
#endif

#if (defined(_MSC_VER) && _MSC_VER < 1900) || defined(INET_CHECKSUM_FORCE_LEGACY_COMPAT)
#define INET_CHECKSUM_NOEXCEPT
#else
#define INET_CHECKSUM_NOEXCEPT noexcept
#endif

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
    /// handling at all -- a 64-bit accumulator absorbs 2^32 such additions,
    /// and an IPv4 payload is bounded far below that -- so the loop is
    /// portable across x86, x64 and ARM64 with no intrinsics. Four
    /// independent accumulators break the dependency chain that made the
    /// byte-pair loop front-end bound; measured on one out-of-order x64 core,
    /// the cost drops from 1.1-1.7 cycles/byte to roughly 0.21-0.26.
    ///
    /// An ODD length is handled with a masked tail load. The byte-pair loop
    /// instead wrote a zero pad byte into the packet buffer one past the
    /// payload before reading it back; this function never writes anywhere.
    /// </remarks>
    /// <param name="data">Start of the span. No alignment requirement.</param>
    /// <param name="length">Span length in bytes. Zero yields zero.</param>
    /// <returns>The folded, uncomplemented sum, in [0x0000, 0xFFFF].</returns>
    inline sum_uint16 sum16_be(const unsigned char* data, const size_t length) INET_CHECKSUM_NOEXCEPT
    {
        sum_uint64 s0 = 0, s1 = 0, s2 = 0, s3 = 0;
        size_t i = 0;

        for (; i + 16 <= length; i += 16)
        {
            sum_uint32 w0, w1, w2, w3;
            INET_CHECKSUM_MEMCPY(&w0, data + i, 4);
            INET_CHECKSUM_MEMCPY(&w1, data + i + 4, 4);
            INET_CHECKSUM_MEMCPY(&w2, data + i + 8, 4);
            INET_CHECKSUM_MEMCPY(&w3, data + i + 12, 4);
            s0 += w0;
            s1 += w1;
            s2 += w2;
            s3 += w3;
        }

        for (; i + 4 <= length; i += 4)
        {
            sum_uint32 w;
            INET_CHECKSUM_MEMCPY(&w, data + i, 4);
            s0 += w;
        }

        // Masked tail: up to three bytes. The 4-byte blocks above end on an
        // even offset, so within this final word the byte at relative offset r
        // belongs at little-endian lane r -- which is precisely what building
        // the word with shifts 0/8/16 produces. Never reads past `length`.
        if (i < length)
        {
            sum_uint32 w = 0;
            unsigned int shift = 0;
            for (; i < length; ++i, shift += 8)
                w |= static_cast<sum_uint32>(data[i]) << shift;
            s0 += w;
        }

        sum_uint64 sum = s0 + s1 + s2 + s3;
        while (sum >> 32)
            sum = (sum & 0xFFFFFFFFu) + (sum >> 32);

        sum_uint32 folded = static_cast<sum_uint32>(sum);
        while (folded >> 16)
            folded = (folded & 0xFFFF) + (folded >> 16);

        // Swap into the big-endian word domain the callers accumulate
        // pseudo-header words in.
        return static_cast<sum_uint16>(((folded & 0xFF) << 8) | (folded >> 8));
    }
}
