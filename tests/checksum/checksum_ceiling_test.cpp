// Exercises the actual SDK translation unit and wire headers, without opening a driver.
#include "precomp.h"
#include "inet_checksum.h"
#include <cstdio>
#include <cstring>
#include <vector>
#include <cstddef>

static unsigned g_checks = 0;
static unsigned g_failures = 0;
static unsigned g_faults = 0;
static unsigned g_case_count = 0;

static void Check(bool condition, const char* case_id, const char* contract)
{
    ++g_checks;
    if (!condition) ++g_failures;
    std::printf("[%s] %s: %s\n", condition ? "PASS" : "FAIL", case_id, contract);
}

static unsigned Fold(unsigned sum)
{
    while (sum >> 16) sum = (sum & 0xffffu) + (sum >> 16);
    return sum;
}

// Independent byte-pair oracle: it does not call the production accumulator.
static unsigned ReferenceSum(const unsigned char* bytes, size_t length)
{
    unsigned sum = 0;
    size_t i = 0;
    for (; i + 1 < length; i += 2)
        sum += (static_cast<unsigned>(bytes[i]) << 8) | bytes[i + 1];
    if (i < length) sum += static_cast<unsigned>(bytes[i]) << 8;
    return Fold(sum);
}

struct GuardedRegion
{
    unsigned char* allocation;
    unsigned char* boundary;
    size_t accessible;
    size_t page;
    explicit GuardedRegion(size_t bytes) : allocation(NULL), boundary(NULL), accessible(0), page(0)
    {
        SYSTEM_INFO info;
        GetSystemInfo(&info);
        page = info.dwPageSize;
        accessible = ((bytes + page - 1) / page) * page;
        if (!accessible) accessible = page;
        allocation = static_cast<unsigned char*>(VirtualAlloc(NULL, accessible + page,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!allocation) return;
        boundary = allocation + accessible;
        DWORD old_protect = 0;
        if (!VirtualProtect(boundary, page, PAGE_NOACCESS, &old_protect))
        {
            VirtualFree(allocation, 0, MEM_RELEASE);
            allocation = boundary = NULL;
        }
    }
    ~GuardedRegion() { if (allocation) VirtualFree(allocation, 0, MEM_RELEASE); }
private:
    GuardedRegion(const GuardedRegion&);
    GuardedRegion& operator=(const GuardedRegion&);
};

enum ChecksumKind { KindIP, KindICMP, KindTCP, KindUDP };
struct Entry { ChecksumKind kind; bool c_export; const char* name; };
static const Entry entries[] = {
    { KindIP, false, "cpp-ip" }, { KindICMP, false, "cpp-icmp" },
    { KindTCP, false, "cpp-tcp" }, { KindUDP, false, "cpp-udp" },
    { KindIP, true, "c-ip" }, { KindICMP, true, "c-icmp" },
    { KindTCP, true, "c-tcp" }, { KindUDP, true, "c-udp" }
};

static void Invoke(const Entry& entry, PINTERMEDIATE_BUFFER packet)
{
    if (entry.c_export)
    {
        switch (entry.kind)
        {
        case KindIP: ::RecalculateIPChecksum(packet); return;
        case KindICMP: ::RecalculateICMPChecksum(packet); return;
        case KindTCP: ::RecalculateTCPChecksum(packet); return;
        case KindUDP: ::RecalculateUDPChecksum(packet); return;
        }
    }
    else
    {
        switch (entry.kind)
        {
        case KindIP: CNdisApi::RecalculateIPChecksum(packet); return;
        case KindICMP: CNdisApi::RecalculateICMPChecksum(packet); return;
        case KindTCP: CNdisApi::RecalculateTCPChecksum(packet); return;
        case KindUDP: CNdisApi::RecalculateUDPChecksum(packet); return;
        }
    }
}

// Keep SEH in a function without C++ objects that need unwinding. AV is a FAILED
// contract, never accepted as evidence that a malformed request was rejected.
static DWORD InvokeSafely(const Entry& entry, PINTERMEDIATE_BUFFER packet)
{
    __try { Invoke(entry, packet); }
    __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ?
        EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
    {
        return GetExceptionCode();
    }
    return 0;
}

static DWORD SumSafely(const unsigned char* bytes, size_t length, unsigned* value)
{
    __try { *value = inet_checksum::sum16_be(bytes, length); }
    __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ?
        EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
    {
        return GetExceptionCode();
    }
    return 0;
}

static size_t L4Size(ChecksumKind kind)
{
    switch (kind) {
    case KindICMP: return sizeof(icmphdr);
    case KindTCP: return sizeof(tcphdr);
    case KindUDP: return sizeof(udphdr);
    default: return 0;
    }
}

static unsigned char Protocol(ChecksumKind kind)
{
    switch (kind) {
    case KindICMP: return IPPROTO_ICMP;
    case KindTCP: return IPPROTO_TCP;
    case KindUDP: return IPPROTO_UDP;
    default: return 253; // Header-only IPv4 control with an experimental protocol.
    }
}

static size_t ChecksumOffset(ChecksumKind kind, size_t ip_header)
{
    if (kind == KindIP) return sizeof(ether_header) + 10;
    return sizeof(ether_header) + ip_header +
        (kind == KindTCP ? 16 : kind == KindUDP ? 6 : 2);
}

static void FillPacket(PINTERMEDIATE_BUFFER packet, ChecksumKind kind,
    size_t ip_header, size_t payload)
{
    std::memset(packet, 0xa5, sizeof(*packet));
    const size_t l4_size = L4Size(kind);
    packet->m_Length = static_cast<DWORD>(sizeof(ether_header) + ip_header + l4_size + payload);
    unsigned char* frame = packet->m_IBuffer;
    for (size_t i = 0; i < sizeof(packet->m_IBuffer); ++i)
        frame[i] = static_cast<unsigned char>((i * 73u + 29u) & 255u);
    ether_header* ethernet = reinterpret_cast<ether_header*>(frame);
    ethernet->h_proto = htons(ETH_P_IP);
    iphdr* ip = reinterpret_cast<iphdr*>(frame + sizeof(ether_header));
    std::memset(ip, 0, ip_header);
    ip->ip_v = 4;
    ip->ip_hl = static_cast<unsigned char>(ip_header / 4);
    ip->ip_tos = 0x12;
    ip->ip_len = htons(static_cast<unsigned short>(ip_header + l4_size + payload));
    ip->ip_id = htons(0x1234);
    ip->ip_off = htons(IP_DF);
    ip->ip_ttl = 63;
    ip->ip_p = Protocol(kind);
    ip->ip_sum = htons(0x7351);
    const unsigned char source[4] = { 192, 0, 2, 1 };
    const unsigned char dest[4] = { 198, 51, 100, 2 };
    std::memcpy(&ip->ip_src, source, sizeof(source));
    std::memcpy(&ip->ip_dst, dest, sizeof(dest));
    if (ip_header > sizeof(iphdr))
        std::memset(frame + sizeof(ether_header) + sizeof(iphdr), 1, ip_header - sizeof(iphdr));
    unsigned char* transport = frame + sizeof(ether_header) + ip_header;
    if (l4_size) std::memset(transport, 0, l4_size);
    if (kind == KindICMP)
    {
        icmphdr* icmp = reinterpret_cast<icmphdr*>(transport);
        icmp->type = 8;
        icmp->id = htons(0x1357);
        icmp->seq = htons(0x2468);
    }
    else if (kind == KindTCP)
    {
        tcphdr* tcp = reinterpret_cast<tcphdr*>(transport);
        tcp->th_sport = htons(1234);
        tcp->th_dport = htons(5678);
        tcp->th_seq = htonl(0x01234567);
        tcp->th_ack = htonl(0x89abcdef);
        tcp->th_off = 5;
        tcp->th_flags = TH_ACK | TH_PSH;
        tcp->th_win = htons(8192);
    }
    else if (kind == KindUDP)
    {
        udphdr* udp = reinterpret_cast<udphdr*>(transport);
        udp->th_sport = htons(1234);
        udp->th_dport = htons(5678);
        udp->length = htons(static_cast<unsigned short>(l4_size + payload));
    }
    const size_t checksum = ChecksumOffset(kind, ip_header);
    frame[checksum] = 0x13;
    frame[checksum + 1] = 0x57;
}

static unsigned ExpectedChecksum(const INTERMEDIATE_BUFFER& packet, ChecksumKind kind,
    size_t ip_header)
{
    const unsigned char* ip = packet.m_IBuffer + sizeof(ether_header);
    unsigned sum = 0;
    if (kind == KindIP)
        sum = ReferenceSum(ip, ip_header);
    else
    {
        const size_t length = packet.m_Length - sizeof(ether_header) - ip_header;
        sum = ReferenceSum(ip + ip_header, length);
        if (kind == KindTCP || kind == KindUDP)
        {
            sum += ReferenceSum(ip + 12, 8);
            sum += Protocol(kind) + static_cast<unsigned>(length);
        }
    }
    return (~Fold(sum)) & 0xffffu;
}

static void TestOversized(const Entry& entry, DWORD length, unsigned length_case)
{
    char id[120];
    ++g_case_count;
    std::sprintf(id, "ceiling/%s/length-%u/metadata", entry.name, length_case);
    GuardedRegion metadata(offsetof(INTERMEDIATE_BUFFER, m_IBuffer));
    Check(metadata.allocation != NULL, id, "guard allocation succeeds");
    if (!metadata.allocation) return;
    PINTERMEDIATE_BUFFER packet = reinterpret_cast<PINTERMEDIATE_BUFFER>(
        metadata.boundary - offsetof(INTERMEDIATE_BUFFER, m_IBuffer));
    std::memset(packet, 0x5a, offsetof(INTERMEDIATE_BUFFER, m_IBuffer));
    packet->m_Length = length;
    std::vector<unsigned char> before(offsetof(INTERMEDIATE_BUFFER, m_IBuffer));
    std::memcpy(&before[0], packet, before.size());
    DWORD fault = InvokeSafely(entry, packet);
    if (fault) ++g_faults;
    Check(fault == 0, id, "oversized length returns before frame access");
    Check(std::memcmp(&before[0], packet, before.size()) == 0, id, "metadata is unchanged");

    ++g_case_count;
    std::sprintf(id, "ceiling/%s/length-%u/full", entry.name, length_case);
    GuardedRegion full(sizeof(INTERMEDIATE_BUFFER));
    Check(full.allocation != NULL, id, "guard allocation succeeds");
    if (!full.allocation) return;
    packet = reinterpret_cast<PINTERMEDIATE_BUFFER>(full.boundary - sizeof(*packet));
    FillPacket(packet, entry.kind, 20, sizeof(packet->m_IBuffer) - sizeof(ether_header) - 20 - L4Size(entry.kind));
    // A one-byte oversized IP extent defeats the existing captured-length check;
    // the fixed array ends exactly at PAGE_NOACCESS.
    reinterpret_cast<iphdr*>(packet->m_IBuffer + sizeof(ether_header))->ip_len =
        htons(static_cast<unsigned short>(sizeof(packet->m_IBuffer) + 1 - sizeof(ether_header)));
    packet->m_Length = length;
    before.resize(sizeof(*packet));
    std::memcpy(&before[0], packet, before.size());
    fault = InvokeSafely(entry, packet);
    if (fault) ++g_faults;
    Check(fault == 0, id, "oversized length never reads beyond fixed array");
    Check(std::memcmp(&before[0], packet, before.size()) == 0, id, "entire oversized packet is unchanged");
}

static void TestValid(const Entry& entry, size_t ip_header, size_t payload, const char* label)
{
    ++g_case_count;
    char id[120];
    std::sprintf(id, "golden/%s/ip-%u/%s", entry.name, static_cast<unsigned>(ip_header), label);
    GuardedRegion full(sizeof(INTERMEDIATE_BUFFER));
    Check(full.allocation != NULL, id, "guard allocation succeeds");
    if (!full.allocation) return;
    PINTERMEDIATE_BUFFER packet = reinterpret_cast<PINTERMEDIATE_BUFFER>(full.boundary - sizeof(*packet));
    FillPacket(packet, entry.kind, ip_header, payload);
    INTERMEDIATE_BUFFER expected = *packet;
    const size_t checksum = ChecksumOffset(entry.kind, ip_header);
    expected.m_IBuffer[checksum] = expected.m_IBuffer[checksum + 1] = 0;
    const unsigned value = ExpectedChecksum(expected, entry.kind, ip_header);
    expected.m_IBuffer[checksum] = static_cast<unsigned char>(value >> 8);
    expected.m_IBuffer[checksum + 1] = static_cast<unsigned char>(value);
    const DWORD fault = InvokeSafely(entry, packet);
    if (fault) ++g_faults;
    Check(fault == 0, id, "valid guarded packet does not fault");
    Check(packet->m_IBuffer[checksum] == expected.m_IBuffer[checksum] &&
        packet->m_IBuffer[checksum + 1] == expected.m_IBuffer[checksum + 1], id,
        "checksum equals independent byte-pair oracle");
    Check(std::memcmp(packet, &expected, sizeof(expected)) == 0, id,
        "only the intended checksum bytes change; metadata and tail remain intact");
    Check(ExpectedChecksum(*packet, entry.kind, ip_header) == 0, id,
        "complete checksum including pseudo-header has zero complement");
}

static void TestAccumulator()
{
    const size_t lengths[] = { 0, 1, 2, 3, 4, 15, 16, 17, 31, 32, 33,
        MAX_ETHER_FRAME - 1, MAX_ETHER_FRAME };
    GuardedRegion region(MAX_ETHER_FRAME);
    Check(region.allocation != NULL, "accumulator/setup", "guard allocation succeeds");
    if (!region.allocation) return;
    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i)
    {
        ++g_case_count;
        const size_t length = lengths[i];
        unsigned char* data = region.boundary - length;
        for (size_t j = 0; j < length; ++j) data[j] = static_cast<unsigned char>(j * 113u + 0x91u);
        const unsigned expected = ReferenceSum(data, length);
        unsigned actual = 0xdeadbeefu;
        char id[100];
        std::sprintf(id, "accumulator/guarded-length-%u", static_cast<unsigned>(length));
        const DWORD fault = SumSafely(data, length, &actual);
        if (fault) ++g_faults;
        Check(fault == 0, id, "exact guarded span never reads a padding byte");
        Check(actual == expected, id, "real accumulator equals byte-pair oracle");
    }
    // Fixed wire vector pins the reference arithmetic independently of packet generation.
    const unsigned char header[] = { 0x45,0x00,0x00,0x73,0x00,0x00,0x40,0x00,0x40,0x11,
        0x00,0x00,0xc0,0xa8,0x00,0x01,0xc0,0xa8,0x00,0xc7 };
    Check(((~ReferenceSum(header, sizeof(header))) & 0xffffu) == 0xb861u,
        "oracle/fixed-ipv4-vector", "independent golden checksum is 0xb861");
}

int main()
{
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    BOOL wow64 = FALSE;
    Check(IsWow64Process(GetCurrentProcess(), &wow64) != FALSE, "environment", "WOW64 query succeeds");
#ifdef _WIN64
    Check(wow64 == FALSE, "environment", "x64 process is native");
#else
    Check(wow64 != FALSE, "environment", "x86 process is genuinely WOW64");
#endif
    Check(offsetof(INTERMEDIATE_BUFFER, m_IBuffer) + sizeof(((PINTERMEDIATE_BUFFER)0)->m_IBuffer) ==
        sizeof(INTERMEDIATE_BUFFER), "environment", "frame is the final byte-exact object member");
    std::printf("CONFIG pointer_bits=%u wow64=%u frame_capacity=%u legacy_codec=%u\n",
        static_cast<unsigned>(sizeof(void*) * 8), static_cast<unsigned>(wow64),
        static_cast<unsigned>(MAX_ETHER_FRAME),
#ifdef INET_CHECKSUM_FORCE_LEGACY_COMPAT
        1u
#else
        0u
#endif
    );
    const DWORD oversized[] = { static_cast<DWORD>(MAX_ETHER_FRAME + 1), 65535u, MAXDWORD };
    const size_t headers[] = { 20, 24, 60 };
    for (size_t e = 0; e < sizeof(entries) / sizeof(entries[0]); ++e)
    {
        for (unsigned n = 0; n < sizeof(oversized) / sizeof(oversized[0]); ++n)
            TestOversized(entries[e], oversized[n], n);
        for (size_t h = 0; h < sizeof(headers) / sizeof(headers[0]); ++h)
        {
            const size_t maximum = MAX_ETHER_FRAME - sizeof(ether_header) - headers[h] - L4Size(entries[e].kind);
            TestValid(entries[e], headers[h], 0, "zero-payload");
            TestValid(entries[e], headers[h], 1, "odd-payload");
            TestValid(entries[e], headers[h], 2, "even-payload");
            TestValid(entries[e], headers[h], maximum - 1, "max-minus-one-frame");
            TestValid(entries[e], headers[h], maximum, "max-frame");
        }
    }
    TestAccumulator();
    std::printf("SUMMARY cases=%u checks=%u failures=%u access_violations=%u\n",
        g_case_count, g_checks, g_failures, g_faults);
    std::printf("RESULT=%u\n", g_failures ? 1u : 0u);
    return g_failures ? 1 : 0;
}