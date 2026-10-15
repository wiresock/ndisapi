#include "handles_shim.h"
#include "ndisapi.h"

static unsigned checks = 0, failures = 0, guardedFaults = 0;
static const ULONGLONG rawA = 0x1234567887650000ULL;
static const ULONGLONG rawB = 0x2345678998760000ULL;
static const ULONGLONG unknownRaw = 0x34567890ABCDEF00ULL;
static HANDLE handleA = NULL, handleB = NULL;
static void Check(bool value, const std::string& name) {
    ++checks;
    if (!value) { ++failures; printf("[FAIL] %s\n", name.c_str()); }
}
static DWORD TableBytes(unsigned count) {
    return static_cast<DWORD>(offsetof(STATIC_FILTER_TABLE, m_StaticFilters) + count * sizeof(STATIC_FILTER));
}
struct Table {
    std::vector<unsigned char> bytes;
    explicit Table(unsigned capacity) : bytes(TableBytes((std::max)(capacity, 3U)) + 32, 0xA5) {
        get()->m_TableSize = capacity; get()->Padding = 0x6B6B6B6B;
        for (unsigned i = 0; i < (std::max)(capacity, 3U); ++i) {
            memset(&get()->m_StaticFilters[i], 0x30 + static_cast<int>(i), sizeof(STATIC_FILTER));
            get()->m_StaticFilters[i].m_Adapter.QuadPart = 0;
        }
    }
    PSTATIC_FILTER_TABLE get() { return reinterpret_cast<PSTATIC_FILTER_TABLE>(&bytes[0]); }
};
struct GuardedTable {
    unsigned char* base;
    PSTATIC_FILTER_TABLE table;
    GuardedTable() : base(static_cast<unsigned char*>(VirtualAlloc(NULL, 8192, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))), table(NULL) {
        if (!base) abort();
        DWORD oldProtect;
        if (!VirtualProtect(base + 4096, 4096, PAGE_NOACCESS, &oldProtect)) abort();
        table = reinterpret_cast<PSTATIC_FILTER_TABLE>(base + 4096 - TableBytes(1));
        memset(table, 0, TableBytes(1));
        table->m_TableSize = 1;
    }
    ~GuardedTable() { VirtualFree(base, 0, MEM_RELEASE); }
    PSTATIC_FILTER_TABLE get() { return table; }
};
enum OP { SetTable, AddFront, AddBack, Insert, GetTable, GetReset,
    SendOneMstcp, SendOneAdapter, ReadOne, SendManyMstcp, SendManyAdapter, ReadMany,
    SetMode, GetMode, FlushQueue, QueueSize, PacketEvent, OidGet, OidSet, RasLinks,
    HwEvent, HwSet, HwGet };
static const char* OpName(OP op) {
    static const char* names[] = {"SET", "ADD_FRONT", "ADD_BACK", "INSERT", "GET", "GET_RESET",
        "SEND_ONE_MSTCP", "SEND_ONE_ADAPTER", "READ_ONE", "SEND_MANY_MSTCP", "SEND_MANY_ADAPTER", "READ_MANY",
        "SET_MODE", "GET_MODE", "FLUSH_QUEUE", "QUEUE_SIZE", "PACKET_EVENT", "OID_GET", "OID_SET", "RAS_LINKS",
        "HW_EVENT", "HW_SET", "HW_GET"};
    return names[op];
}
struct Call {
    const CNdisApi* api;
    OP op;
    PSTATIC_FILTER_TABLE table;
    HANDLE adapter;
    DWORD error;
};
static BOOL Execute(Call* c) {
    INTERMEDIATE_BUFFER ib = {};
    ib.m_Length = 64;
    ETH_REQUEST one = {};
    one.hAdapterHandle = c->adapter; one.EthPacket.Buffer = &ib;
    ETH_M_REQUEST many = {};
    many.hAdapterHandle = c->adapter; many.dwPacketsNumber = 1; many.EthPacket[0].Buffer = &ib;
    ADAPTER_MODE mode = {}; mode.hAdapterHandle = c->adapter;
    unsigned char oidBytes[sizeof(PACKET_OID_DATA) + 8] = {};
    PPACKET_OID_DATA oid = reinterpret_cast<PPACKET_OID_DATA>(oidBytes);
    oid->hAdapterHandle = c->adapter; oid->Oid = 0xFEDC0123; oid->Length = 4;
    RAS_LINKS links = {};
    DWORD value = 0;
    switch (c->op) {
    case SetTable: return c->api->SetPacketFilterTable(c->table);
    case AddFront: return c->api->AddStaticFilterFront(&c->table->m_StaticFilters[0]);
    case AddBack: return c->api->AddStaticFilterBack(&c->table->m_StaticFilters[0]);
    case Insert: return c->api->InsertStaticFilter(&c->table->m_StaticFilters[0], 7);
    case GetTable: return c->api->GetPacketFilterTable(c->table);
    case GetReset: return c->api->GetPacketFilterTableResetStats(c->table);
    case SendOneMstcp: return c->api->SendPacketToMstcp(&one);
    case SendOneAdapter: return c->api->SendPacketToAdapter(&one);
    case ReadOne: return c->api->ReadPacket(&one);
    case SendManyMstcp: return c->api->SendPacketsToMstcp(&many);
    case SendManyAdapter: return c->api->SendPacketsToAdapter(&many);
    case ReadMany: return c->api->ReadPackets(&many);
    case SetMode: return c->api->SetAdapterMode(&mode);
    case GetMode: return c->api->GetAdapterMode(&mode);
    case FlushQueue: return c->api->FlushAdapterPacketQueue(c->adapter);
    case QueueSize: return c->api->GetAdapterPacketQueueSize(c->adapter, &value);
    case PacketEvent: return c->api->SetPacketEvent(c->adapter, NULL);
    case OidGet: return c->api->NdisrdRequest(oid, FALSE);
    case OidSet: return c->api->NdisrdRequest(oid, TRUE);
    case RasLinks: return c->api->GetRasLinks(c->adapter, &links);
    case HwEvent: return c->api->SetHwPacketFilterEvent(c->adapter, NULL);
    case HwSet: return c->api->SetHwPacketFilter(c->adapter, 0);
    case HwGet: return c->api->GetHwPacketFilter(c->adapter, &value);
    }
    return FALSE;
}
// SEH is a baseline attribution mechanism: an access violation is a failed
// no-fault assertion, never classified as a successful rejection by the SDK.
static DWORD Guarded(Call* c, BOOL* answer) {
    __try { *answer = Execute(c); c->error = GetLastError(); return 0; }
    __except(EXCEPTION_EXECUTE_HANDLER) { *answer = FALSE; c->error = ERROR_NOACCESS; return GetExceptionCode(); }
}
static BOOL Run(Call& c, const std::string& label) {
    BOOL answer = FALSE;
    const DWORD exception = Guarded(&c, &answer);
    if (exception) { ++guardedFaults; printf("[FAULT] %s 0x%08lX\n", label.c_str(), exception); }
    Check(exception == 0, label + ": no access violation");
    return answer;
}
static ULONGLONG SubmittedAdapter(OP op) {
    size_t offset = op == SetTable ? offsetof(STATIC_FILTER_TABLE, m_StaticFilters) + offsetof(STATIC_FILTER, m_Adapter)
        : op == Insert ? offsetof(STATIC_FILTER_WITH_POSITION, m_StaticFilter) + offsetof(STATIC_FILTER, m_Adapter)
        : offsetof(STATIC_FILTER, m_Adapter);
    ULONGLONG result = ~0ULL;
    if (g_Test.capturedInput >= offset + sizeof(result)) memcpy(&result, g_Test.input + offset, sizeof(result));
    return result;
}
static bool Refresh(const CNdisApi& api, unsigned count) {
    TestReset(); g_AdapterCount = count; g_Adapters[0] = rawA; g_Adapters[1] = rawB;
    TCP_AdapterList list = {};
    const BOOL result = api.GetTcpipBoundAdaptersInfo(&list);
    Check(result != FALSE, "enumeration: real API succeeds");
    Check(list.m_nAdapterCount == count, "enumeration: expected adapter count");
    if (count) handleA = list.m_nAdapterHandle[0];
    if (count > 1) handleB = list.m_nAdapterHandle[1];
    return result != FALSE;
}
static ULONGLONG SubmittedServiceAdapter() {
    ULONGLONG raw = ~0ULL;
    if (g_Test.capturedInput >= sizeof(raw)) memcpy(&raw, g_Test.input, sizeof(raw));
    return raw;
}
static void ValidIdentities(const CNdisApi& api, HANDLE adapter, ULONGLONG expectedRaw, const char* group) {
    const unsigned beforeChecks = checks, beforeFailures = failures;
    for (unsigned opValue = SendOneMstcp; opValue <= HwGet; ++opValue) {
        TestReset(); g_Test.validServiceResponse = TRUE;
        const OP op = static_cast<OP>(opValue);
        Call c = { &api, op, NULL, adapter, 0 };
        const std::string label = std::string(group) + "/" + OpName(op);
        const BOOL ok = Run(c, label);
        Check(ok != FALSE, label + ": valid mapped request succeeds");
        Check(g_Test.ioctlCalls == 1 && SubmittedServiceAdapter() == expectedRaw,
            label + ": expected full adapter identity submitted once");
        Check(g_Test.outstandingAllocations == 0, label + ": successful conversion releases storage");
        if (op == OidGet || op == OidSet) {
            const size_t offset = TestWow64() ? offsetof(PACKET_OID_DATA_WOW64, Oid) : offsetof(PACKET_OID_DATA, Oid);
            DWORD submittedOid = 0;
            if (g_Test.capturedInput >= offset + sizeof(submittedOid)) memcpy(&submittedOid, g_Test.input + offset, sizeof(submittedOid));
            Check(submittedOid == 0xFEDC0123UL, label + ": arbitrary generic OID passes through unchanged");
            const DWORD expectedCode = static_cast<DWORD>(op == OidGet ? IOCTL_NDISRD_NDIS_GET_REQUEST : IOCTL_NDISRD_NDIS_SET_REQUEST);
            Check(g_Test.code == expectedCode, label + ": generic query/set operation retained");
        }
    }
    printf("CONTROL %s checks=%u failures=%u\n", group, checks - beforeChecks, failures - beforeFailures);
}
static void Inputs(const CNdisApi& api) {
    for (unsigned opValue = SetTable; opValue <= Insert; ++opValue) {
        const OP op = static_cast<OP>(opValue);
        for (unsigned scenario = 0; scenario != 4; ++scenario) {
            TestReset(); Table table(op == SetTable ? 2 : 1);
            table.get()->m_StaticFilters[0].m_Adapter.QuadPart = reinterpret_cast<ULONG_PTR>(handleA);
            if (op == SetTable) table.get()->m_StaticFilters[1].m_Adapter.QuadPart = 0;
            const std::vector<unsigned char> before = table.bytes;
            g_Test.mode = scenario < 2 ? (scenario == 0 ? TestImmediate : TestFailure) : TestPending;
            g_Test.terminalSuccess = scenario != 3;
            g_Test.delayResponse = TRUE;
            g_Test.cleanupClobbersError = scenario == 1 || scenario == 3;
            Call c = { &api, op, table.get(), NULL, 0 };
            const std::string label = std::string(OpName(op)) + "/mode" + std::to_string(scenario);
            const BOOL ok = Run(c, label);
            Check((ok != FALSE) == (scenario == 0 || scenario == 2), label + ": terminal result");
            Check(table.bytes == before, label + ": caller bytes unchanged");
            Check(g_Test.ioctlCalls == 1, label + ": one submission");
            Check(g_Test.inputPointer != (op == SetTable ? static_cast<void*>(table.get()) : static_cast<void*>(&table.get()->m_StaticFilters[0])), label + ": private input staging");
            Check(SubmittedAdapter(op) == rawA, label + ": full mapped adapter submitted");
            if (op == Insert) {
                unsigned long position = 0; memcpy(&position, g_Test.input, sizeof(position));
                Check(position == 7, label + ": position retained");
            }
            const size_t ruleOffset = op == SetTable ? offsetof(STATIC_FILTER_TABLE, m_StaticFilters)
                : op == Insert ? offsetof(STATIC_FILTER_WITH_POSITION, m_StaticFilter) : 0;
            STATIC_FILTER expected = reinterpret_cast<const STATIC_FILTER_TABLE*>(&before[0])->m_StaticFilters[0];
            expected.m_Adapter.QuadPart = rawA;
            Check(g_Test.capturedInput >= ruleOffset + sizeof(expected) &&
                memcmp(g_Test.input + ruleOffset, &expected, sizeof(expected)) == 0, label + ": every rule field retained");
            if (scenario >= 2) {
                Check(g_Test.completions == 1 && g_Test.waits == 1 && !g_Test.pending, label + ": awaited terminal completion");
                Check(g_Test.freedWhilePending == 0 && g_Test.closedWhilePending == 0 &&
                    g_Test.completionInputChanged == 0, label + ": storage live and stable through completion");
            }
            if (scenario == 1 || scenario == 3)
                Check(c.error == static_cast<DWORD>(scenario == 1 ? ERROR_NOT_SUPPORTED : ERROR_ACCESS_DENIED), label + ": actual error survives cleanup");
            Check(g_Test.outstandingAllocations == 0, label + ": no allocation leak");
            TestAbandonPending();
        }
        TestReset(); Table repeated(1);
        repeated.get()->m_StaticFilters[0].m_Adapter.QuadPart = reinterpret_cast<ULONG_PTR>(handleA);
        Call c = { &api, op, repeated.get(), NULL, 0 };
        const std::vector<unsigned char> before = repeated.bytes;
        Run(c, std::string(OpName(op)) + "/reuse first");
        TestReset(); const BOOL ok = Run(c, std::string(OpName(op)) + "/reuse second");
        Check(ok && SubmittedAdapter(op) == rawA && repeated.bytes == before, std::string(OpName(op)) + ": reusable input");
        TestReset(); Table wildcard(1); c.table = wildcard.get();
        const BOOL wild = Run(c, std::string(OpName(op)) + "/wildcard");
        Check(wild && SubmittedAdapter(op) == 0, std::string(OpName(op)) + ": wildcard zero preserved");
    }
}
static void UnmappedMarkerInputs(const CNdisApi& api) {
    const unsigned beforeChecks = checks, beforeFailures = failures;
    for (unsigned opValue = SetTable; opValue <= Insert; ++opValue) {
        const OP op = static_cast<OP>(opValue);
        TestReset(); Table table(op == SetTable ? 2 : 1);
        table.get()->m_StaticFilters[0].m_Adapter.QuadPart = reinterpret_cast<ULONG_PTR>(handleA);
        table.get()->m_StaticFilters[op == SetTable ? 1 : 0].m_Adapter.QuadPart = STATIC_FILTER_ADAPTER_UNMAPPED;
        const std::vector<unsigned char> before = table.bytes;
        g_Test.cleanupClobbersError = TRUE;
        Call c = { &api, op, table.get(), NULL, 0 };
        const std::string label = std::string(OpName(op)) + "/output-only marker";
        const BOOL ok = Run(c, label);
        Check(!ok && c.error == ERROR_INVALID_HANDLE, label + ": marker rejected on native and WOW64 callers");
        Check(g_Test.ioctlCalls == 0 && g_Test.enumerationCalls == 0, label + ": rejected before any IOCTL");
        Check(table.bytes == before && g_Test.outstandingAllocations == 0, label + ": caller unchanged and no leak");
        if (!TestWow64()) {
            TestReset();
            table.get()->m_StaticFilters[op == SetTable ? 1 : 0].m_Adapter.QuadPart = 0x1FFFFFFFFULL;
            Check(Run(c, label + "/native full identity") && g_Test.ioctlCalls == 1,
                label + ": exact marker check preserves other native 64-bit identities");
        }
    }
    printf("CONTROL output-only marker inputs checks=%u failures=%u\n", checks - beforeChecks, failures - beforeFailures);
}
static void InvalidIdentities(const CNdisApi& api) {
    if (!TestWow64()) return;
    const ULONGLONG bad[] = {3, 33, 0xFFFFFFFFULL, 0x100000001ULL};
    for (unsigned opValue = SetTable; opValue <= Insert; ++opValue) {
        OP op = static_cast<OP>(opValue);
        for (unsigned n = 0; n != 4; ++n) {
            TestReset(); Table table(op == SetTable ? 2 : 1);
            table.get()->m_StaticFilters[0].m_Adapter.QuadPart = reinterpret_cast<ULONG_PTR>(handleA);
            table.get()->m_StaticFilters[op == SetTable ? 1 : 0].m_Adapter.QuadPart = bad[n];
            const std::vector<unsigned char> before = table.bytes;
            Call c = { &api, op, table.get(), NULL, 0 };
            const std::string label = std::string(OpName(op)) + "/invalid" + std::to_string(n);
            const BOOL ok = Run(c, label);
            Check(!ok && c.error == ERROR_INVALID_HANDLE, label + ": meaningful invalid handle");
            Check(g_Test.ioctlCalls == 0, label + ": rejected before submission");
            Check(table.bytes == before, label + ": no partial caller translation");
            Check(g_Test.outstandingAllocations == 0, label + ": no allocation leak");
        }
    }
    for (unsigned opValue = SendOneMstcp; opValue <= HwGet; ++opValue) {
        for (unsigned n = 0; n != 3; ++n) {
            TestReset(); g_Test.mode = TestFailure;
            Call c = { &api, static_cast<OP>(opValue), NULL, reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(bad[n])), 0 };
            const std::string label = std::string(OpName(c.op)) + "/invalid" + std::to_string(n);
            const BOOL ok = Run(c, label);
            Check(!ok && c.error == ERROR_INVALID_HANDLE, label + ": meaningful invalid handle");
            Check(g_Test.ioctlCalls == 0, label + ": rejected before submission");
            Check(g_Test.outstandingAllocations == 0, label + ": no conversion allocation leak");
        }
    }
}
static void Response(unsigned returnedCount, DWORD returnedBytes, DWORD capacity, ULONGLONG first, ULONGLONG second) {
    Table table((std::max)(returnedCount, 3U)); table.get()->m_TableSize = returnedCount;
    table.get()->Padding = 0;
    table.get()->m_StaticFilters[0].m_Adapter.QuadPart = first;
    table.get()->m_StaticFilters[1].m_Adapter.QuadPart = second;
    table.get()->m_StaticFilters[0].m_PacketsIn.QuadPart = 101;
    table.get()->m_StaticFilters[0].m_BytesIn.QuadPart = 10001;
    table.get()->m_StaticFilters[0].m_PacketsOut.QuadPart = 202;
    table.get()->m_StaticFilters[0].m_BytesOut.QuadPart = 20002;
    table.get()->m_StaticFilters[0].m_LastReset = 12345;
    g_Test.writeResponse = TRUE;
    g_Test.responseLength = TableBytes(capacity);
    memcpy(g_Test.response, &table.bytes[0], g_Test.responseLength);
    g_Test.immediateBytes = returnedBytes; g_Test.terminalBytes = returnedBytes;
}
static void Getters(const CNdisApi& api) {
    for (unsigned opValue = GetTable; opValue <= GetReset; ++opValue) {
        OP op = static_cast<OP>(opValue);
        for (unsigned scenario = 0; scenario != 12; ++scenario) {
            TestReset(); Table table(2); const std::vector<unsigned char> before = table.bytes;
            const bool pending = scenario == 1 || scenario == 7 || scenario == 9;
            const bool success = scenario == 0 || scenario == 1 || scenario == 2 || scenario == 10 || scenario == 11;
            DWORD count = scenario == 2 || scenario == 11 ? 0 : scenario == 3 ? 3 : scenario == 10 ? 1 : 2;
            DWORD bytes = scenario == 4 ? 0 : scenario == 5 ? TableBytes(2) - 1 :
                scenario == 6 ? TableBytes(2) + 1 : scenario == 10 ? TableBytes(1) : scenario == 11 ? TableBytes(0) : TableBytes(2);
            Response(count, bytes, 2, rawA, 0);
            g_Test.mode = scenario == 8 ? TestFailure : pending ? TestPending : TestImmediate;
            g_Test.terminalSuccess = scenario != 9;
            g_Test.delayResponse = TRUE;
            if (scenario == 1) g_Test.immediateBytes = 0;
            if (scenario == 7) { g_Test.terminalBytes = 0; g_Test.immediateBytes = TableBytes(2); }
            if (scenario == 8 || scenario == 9) g_Test.cleanupClobbersError = TRUE;
            Call c = { &api, op, table.get(), NULL, 0 };
            const std::string label = std::string(OpName(op)) + "/response" + std::to_string(scenario);
            const BOOL ok = Run(c, label);
            Check((ok != FALSE) == success, label + ": validate terminal response");
            Check(g_Test.outLength == TableBytes(2), label + ": captured output capacity");
            Check(g_Test.outputPointer != table.get(), label + ": private output staging");
            if (success) {
                Check(table.get()->m_TableSize == count, label + ": result count published");
                std::vector<unsigned char> expected(g_Test.response, g_Test.response + TableBytes(count));
                if (count) reinterpret_cast<PSTATIC_FILTER_TABLE>(&expected[0])->m_StaticFilters[0].m_Adapter.QuadPart = reinterpret_cast<ULONG_PTR>(handleA);
                Check(memcmp(&table.bytes[0], &expected[0], expected.size()) == 0, label + ": all returned rule fields preserved");
                if (count) {
                    Check(table.get()->m_StaticFilters[0].m_Adapter.QuadPart == reinterpret_cast<ULONG_PTR>(handleA), label + ": mapped result");
                    if (count > 1) Check(table.get()->m_StaticFilters[1].m_Adapter.QuadPart == 0, label + ": returned wildcard remains zero");
                }
                Check(memcmp(&table.bytes[TableBytes(2)], &before[TableBytes(2)], table.bytes.size() - TableBytes(2)) == 0,
                    label + ": bytes beyond capacity unchanged");
                Check(api.GetBytesReturned() == bytes, label + ": terminal byte count retained");
            } else {
                Check(table.bytes == before, label + ": failed output wholly unpublished");
                if (scenario < 8) Check(c.error == ERROR_INVALID_DATA, label + ": malformed success has meaningful error");
                if (scenario >= 8) Check(c.error == static_cast<DWORD>(scenario == 8 ? ERROR_NOT_SUPPORTED : ERROR_ACCESS_DENIED), label + ": terminal error preserved");
            }
            if (pending) {
                Check(g_Test.completions == 1 && g_Test.waits == 1 && !g_Test.pending, label + ": waits for actual completion");
                Check(g_Test.freedWhilePending == 0 && g_Test.closedWhilePending == 0, label + ": response storage retained");
            }
            Check(g_Test.outstandingAllocations == 0, label + ": no allocation leak");
            TestAbandonPending();
        }
        TestReset(); DWORD dummy = 0; g_Test.immediateBytes = TableBytes(2);
        api.DeviceIoControl(0xDEADBEEFUL, NULL, 0, &dummy, sizeof(dummy));
        TestReset(); Table fresh(2); const std::vector<unsigned char> freshBefore = fresh.bytes;
        Response(2, 0, 2, rawA, 0);
        Call freshCall = { &api, op, fresh.get(), NULL, 0 };
        const BOOL freshOk = Run(freshCall, std::string(OpName(op)) + "/fresh bytes");
        Check(!freshOk && fresh.bytes == freshBefore, std::string(OpName(op)) + ": old byte count cannot validate new response");
        TestReset(); Table empty(0); Response(0, TableBytes(0), 0, 0, 0);
        Call emptyCall = { &api, op, empty.get(), NULL, 0 };
        const BOOL emptyOk = Run(emptyCall, std::string(OpName(op)) + "/empty");
        Check(emptyOk && g_Test.outLength == TableBytes(0) && empty.get()->m_TableSize == 0,
            std::string(OpName(op)) + ": empty header-only response");
        if (TestWow64()) {
            TestReset(); Table unknown(2); const std::vector<unsigned char> before = unknown.bytes;
            Response(2, TableBytes(2), 2, rawA, unknownRaw);
            Call c = { &api, op, unknown.get(), NULL, 0 };
            const BOOL ok = Run(c, std::string(OpName(op)) + "/unknown reverse mapping");
            Check(ok && unknown.get()->m_StaticFilters[0].m_Adapter.QuadPart == reinterpret_cast<ULONG_PTR>(handleA) &&
                unknown.get()->m_StaticFilters[1].m_Adapter.QuadPart == 0xFFFFFFFFULL,
                std::string(OpName(op)) + ": known and unmapped nonzero rows remain readable");
            Check(g_Test.ioctlCalls == 1 && g_Test.enumerationCalls == 1 && api.GetBytesReturned() == TableBytes(2),
                std::string(OpName(op)) + ": one table request and one refresh preserve bytes");
            Check(memcmp(&unknown.bytes[TableBytes(2)], &before[TableBytes(2)], before.size() - TableBytes(2)) == 0,
                std::string(OpName(op)) + ": marker output stays inside returned extent");
            if (op == GetReset) Check(g_Test.resetStatsSideEffects == 1, "GET_RESET: driver reset side effect occurs once");
        }
    }
}
static void ArithmeticAndAllocation(const CNdisApi& api) {
    const unsigned maxIntCount = (0x7FFFFFFFU - TableBytes(0)) / sizeof(STATIC_FILTER);
    const unsigned counts[] = {0xFFFFFFFFU, 0x80000000U, maxIntCount + 1};
    for (unsigned opIndex = 0; opIndex != 3; ++opIndex) {
        const OP op = opIndex == 0 ? SetTable : opIndex == 1 ? GetTable : GetReset;
        for (unsigned n = 0; n != 3; ++n) {
            TestReset(); GuardedTable table; table.get()->m_TableSize = counts[n];
            const std::vector<unsigned char> before(reinterpret_cast<unsigned char*>(table.get()), reinterpret_cast<unsigned char*>(table.get()) + TableBytes(1));
            g_Test.mode = TestFailure; g_Test.captureInputLimit = TableBytes(1);
            Call c = { &api, op, table.get(), NULL, 0 };
            const std::string label = std::string(OpName(op)) + "/size overflow" + std::to_string(n);
            const BOOL ok = Run(c, label);
            Check(!ok && c.error == ERROR_ARITHMETIC_OVERFLOW, label + ": signed IOCTL byte boundary rejected");
            Check(g_Test.ioctlCalls == 0 && g_Test.allocationCalls == 0, label + ": reject before copy/allocation/submission");
            Check(memcmp(table.get(), &before[0], before.size()) == 0, label + ": caller unchanged");
        }
        TestReset(); GuardedTable largest; largest.get()->m_TableSize = maxIntCount;
        g_Test.failAllocationAt = 1; g_Test.captureInputLimit = TableBytes(1);
        Call largestCall = { &api, op, largest.get(), NULL, 0 };
        const BOOL largestOk = Run(largestCall, std::string(OpName(op)) + "/largest signed size");
        Check(!largestOk && largestCall.error == ERROR_NOT_ENOUGH_MEMORY && g_Test.allocationCalls == 1 && g_Test.ioctlCalls == 0,
            std::string(OpName(op)) + ": largest representable size reaches allocation without fixed rule cap");
        TestReset(); Table table(1); table.get()->m_StaticFilters[0].m_Adapter.QuadPart = reinterpret_cast<ULONG_PTR>(handleA);
        const std::vector<unsigned char> before = table.bytes; g_Test.failAllocationAt = 1;
        Call c = { &api, op, table.get(), NULL, 0 };
        const BOOL ok = Run(c, std::string(OpName(op)) + "/allocation failure");
        Check(!ok && c.error == ERROR_NOT_ENOUGH_MEMORY, std::string(OpName(op)) + ": allocation error reported");
        Check(g_Test.ioctlCalls == 0 && table.bytes == before && g_Test.outstandingAllocations == 0,
            std::string(OpName(op)) + ": failed allocation leaves caller and driver untouched");
    }
    TestReset(); Table table(16385); g_Test.captureInputLimit = TableBytes(1);
    Call c = { &api, SetTable, table.get(), NULL, 0 };
    const BOOL ok = Run(c, "SET/above default driver cap");
    Check(ok && g_Test.ioctlCalls == 1 && g_Test.inLength == TableBytes(16385), "SET: SDK imposes no fixed driver rule cap");
}
static void RoundTripAndRefresh(const CNdisApi& api) {
    TestReset(); Table table(2); Response(2, TableBytes(2), 2, rawA, 0);
    Call c = { &api, GetTable, table.get(), NULL, 0 };
    const BOOL got = Run(c, "GET-to-SET/get");
    TestReset(); c.op = SetTable;
    const std::vector<unsigned char> before = table.bytes;
    const BOOL set = Run(c, "GET-to-SET/set");
    Check(got && set && table.bytes == before && SubmittedAdapter(SetTable) == rawA,
        "GET-to-SET: handle identity survives a reusable round trip");
    if (!TestWow64()) return;
    const HANDLE removed = handleB;
    Refresh(api, 1);
    TestReset(); g_Test.mode = TestFailure;
    Call stale = { &api, FlushQueue, NULL, removed, 0 };
    const BOOL staleOk = Run(stale, "mapping/removal");
    Check(!staleOk && stale.error == ERROR_INVALID_HANDLE && g_Test.ioctlCalls == 0,
        "mapping: removed adapter is no longer accepted");
    TestReset(); Table oldResult(1);
    Response(1, TableBytes(1), 1, rawB, 0);
    Call reverse = { &api, GetTable, oldResult.get(), NULL, 0 };
    const BOOL reverseOk = Run(reverse, "mapping/removed reverse");
    Check(reverseOk && oldResult.get()->m_StaticFilters[0].m_Adapter.QuadPart == 0xFFFFFFFFULL &&
        g_Test.enumerationCalls == 1 && g_Test.ioctlCalls == 1,
        "mapping: removed adapter remains readable as an output-only marker");
    const HANDLE retained = handleA;
    Refresh(api, 0);
    TestReset(); stale.adapter = retained;
    const BOOL emptyOk = Run(stale, "mapping/empty refresh");
    Check(!emptyOk && stale.error == ERROR_INVALID_HANDLE && g_Test.ioctlCalls == 0,
        "mapping: empty refresh invalidates all previous identities");
    Refresh(api, 2);
}
static void StableAndFullMappings(const CNdisApi& api) {
    const unsigned beforeChecks = checks, beforeFailures = failures;
    const HANDLE originalA = handleA, originalB = handleB;
    // Reordering enumeration must not rewrite previously returned live identities.
    TestReset(); g_AdapterCount = 2; g_Adapters[0] = rawB; g_Adapters[1] = rawA;
    TCP_AdapterList reordered = {};
    Check(api.GetTcpipBoundAdaptersInfo(&reordered) != FALSE, "mapping/reorder: enumeration succeeds");
    Check(reordered.m_nAdapterCount == 2 && reordered.m_nAdapterHandle[0] == originalB &&
        reordered.m_nAdapterHandle[1] == originalA, "mapping/reorder: both existing identities survive order change");
    ValidIdentities(api, originalB, rawB, "reordered survivor B");
    // Keep only B, originally at index 2: compaction into slot 1 is incorrect.
    TestReset(); g_AdapterCount = 1; g_Adapters[0] = rawB;
    TCP_AdapterList surviving = {};
    Check(api.GetTcpipBoundAdaptersInfo(&surviving) != FALSE, "mapping/head removal: enumeration succeeds");
    Check(surviving.m_nAdapterCount == 1 && surviving.m_nAdapterHandle[0] == originalB,
        "mapping/head removal: B retains its previously returned identity");
    ValidIdentities(api, originalB, rawB, "head-removal survivor B");
    TestReset(); Table reverse(1); Response(1, TableBytes(1), 1, rawB, 0);
    Call reverseCall = { &api, GetTable, reverse.get(), NULL, 0 };
    const BOOL reverseOk = Run(reverseCall, "mapping/surviving B reverse");
    Check(reverseOk && reverse.get()->m_StaticFilters[0].m_Adapter.QuadPart == reinterpret_cast<ULONG_PTR>(originalB),
        "mapping/head removal: reverse lookup preserves B's original identity");
    Refresh(api, 2);
    // Populate every legal slot, locating returned index 32 rather than assuming
    // the implementation allocates newly discovered adapters in a specific order.
    TestReset(); g_AdapterCount = ADAPTER_LIST_SIZE;
    g_Adapters[0] = rawA; g_Adapters[1] = rawB;
    for (unsigned i = 2; i < ADAPTER_LIST_SIZE; ++i) g_Adapters[i] = 0x4567000012340000ULL + i * 0x1000ULL;
    TCP_AdapterList full = {};
    Check(api.GetTcpipBoundAdaptersInfo(&full) != FALSE && full.m_nAdapterCount == ADAPTER_LIST_SIZE,
        "mapping/full: every supported adapter is enumerated");
    HANDLE lastHandle = NULL; ULONGLONG lastRaw = 0;
    for (unsigned i = 0; i < ADAPTER_LIST_SIZE; ++i) {
        Check(full.m_nAdapterHandle[i] != NULL, "mapping/full: mapped identity is nonzero");
        for (unsigned j = 0; j < i; ++j)
            Check(full.m_nAdapterHandle[i] != full.m_nAdapterHandle[j], "mapping/full: mapped identities are distinct");
        if ((TestWow64() && reinterpret_cast<ULONG_PTR>(full.m_nAdapterHandle[i]) == ADAPTER_LIST_SIZE) ||
            (!TestWow64() && i == ADAPTER_LIST_SIZE - 1)) {
            lastHandle = full.m_nAdapterHandle[i]; lastRaw = g_Adapters[i];
        }
    }
    Check(lastHandle != NULL, "mapping/full: last legal index 32 is represented");
    if (lastHandle) {
        ValidIdentities(api, lastHandle, lastRaw, "last legal mapping");
        for (unsigned opValue = SetTable; opValue <= Insert; ++opValue) {
            TestReset(); Table table(1); table.get()->m_StaticFilters[0].m_Adapter.QuadPart = reinterpret_cast<ULONG_PTR>(lastHandle);
            const OP op = static_cast<OP>(opValue);
            Call c = { &api, op, table.get(), NULL, 0 };
            const BOOL ok = Run(c, std::string("last legal mapping/") + OpName(op));
            Check(ok && SubmittedAdapter(op) == lastRaw, std::string(OpName(op)) + ": final valid slot translates forward");
        }
        for (unsigned opValue = GetTable; opValue <= GetReset; ++opValue) {
            TestReset(); Table table(1); Response(1, TableBytes(1), 1, lastRaw, 0);
            Call c = { &api, static_cast<OP>(opValue), table.get(), NULL, 0 };
            const BOOL ok = Run(c, std::string("last legal mapping/") + OpName(c.op));
            Check(ok && table.get()->m_StaticFilters[0].m_Adapter.QuadPart == reinterpret_cast<ULONG_PTR>(lastHandle),
                std::string(OpName(c.op)) + ": final valid slot translates in reverse");
        }
    }
    Refresh(api, 2);
    printf("CONTROL stable/full mappings checks=%u failures=%u\n", checks - beforeChecks, failures - beforeFailures);
}
static void StaleTableRefresh(const CNdisApi& api) {
    const unsigned beforeChecks = checks, beforeFailures = failures;
    for (unsigned opValue = GetTable; opValue <= GetReset; ++opValue) {
        const OP op = static_cast<OP>(opValue);
        for (unsigned scenario = 0; scenario != 12; ++scenario) {
            Refresh(api, scenario == 10 ? 2 : 1);
            const HANDLE retainedA = handleA;
            TestReset();
            g_AdapterCount = 2; g_Adapters[0] = rawA; g_Adapters[1] = rawB;
            if (scenario == 2) { g_Adapters[0] = rawB; g_Adapters[1] = rawA; }
            if (scenario == 11) g_AdapterCount = 0;
            const DWORD count = scenario == 0 ? 1 : 3;
            Table caller(3); const std::vector<unsigned char> before = caller.bytes;
            Response(count, TableBytes(count), 3, scenario == 0 ? rawB : rawA,
                scenario == 5 || scenario == 11 ? unknownRaw : rawB);
            if (scenario == 6)
                reinterpret_cast<PSTATIC_FILTER_TABLE>(g_Test.response)->m_StaticFilters[2].m_Adapter.QuadPart = unknownRaw;
            if (scenario == 3) g_Test.enumerationMode = TestFailure;
            if (scenario == 4 || scenario == 7) g_Test.enumerationMode = TestPending;
            if (scenario == 4) g_Test.enumerationTerminalSuccess = FALSE;
            if (scenario == 8) { g_Test.mode = TestPending; g_Test.delayResponse = TRUE; g_Test.immediateBytes = 0; }
            if (scenario == 9) g_Test.enumerationBytes = 0;
            g_Test.cleanupClobbersError = TRUE;
            Call c = { &api, op, caller.get(), NULL, 0 };
            const std::string label = std::string(OpName(op)) + "/stale-map" + std::to_string(scenario);
            const BOOL ok = Run(c, label);
            Check(ok != FALSE, label + ": table remains readable after refresh attempt");
            Check(g_Test.ioctlCalls == 1, label + ": table IOCTL submitted exactly once");
            Check(g_Test.enumerationCalls == (TestWow64() && scenario != 10 ? 1U : 0U),
                label + ": one refresh only for a WOW64 miss");
            Check(api.GetBytesReturned() == TableBytes(count), label + ": original table byte accounting survives refresh");
            Check(g_Test.resetStatsSideEffects == (op == GetReset ? 1U : 0U), label + ": RESET side effect occurs exactly once");
            std::vector<unsigned char> expected(g_Test.response, g_Test.response + TableBytes(count));
            PSTATIC_FILTER_TABLE expectedTable = reinterpret_cast<PSTATIC_FILTER_TABLE>(&expected[0]);
            if (TestWow64()) {
                if (scenario == 0) expectedTable->m_StaticFilters[0].m_Adapter.QuadPart = 2;
                else {
                    expectedTable->m_StaticFilters[0].m_Adapter.QuadPart = scenario == 11 ? 0xFFFFFFFFULL : reinterpret_cast<ULONG_PTR>(retainedA);
                    expectedTable->m_StaticFilters[1].m_Adapter.QuadPart =
                        scenario == 3 || scenario == 4 || scenario == 5 || scenario == 9 || scenario == 11 ? 0xFFFFFFFFULL : 2;
                    if (scenario == 6) expectedTable->m_StaticFilters[2].m_Adapter.QuadPart = 0xFFFFFFFFULL;
                }
            }
            Check(memcmp(&caller.bytes[0], &expected[0], expected.size()) == 0,
                label + ": mixed raw identities and all other fields publish correctly");
            Check(memcmp(&caller.bytes[TableBytes(count)], &before[TableBytes(count)], before.size() - TableBytes(count)) == 0,
                label + ": bytes beyond original table result remain unchanged");
            if (count > 2 && scenario != 6)
                Check(caller.get()->m_StaticFilters[2].m_Adapter.QuadPart == 0, label + ": wildcard remains zero");
            Check(caller.get()->m_StaticFilters[0].m_PacketsIn.QuadPart == 101 &&
                caller.get()->m_StaticFilters[0].m_BytesIn.QuadPart == 10001 &&
                caller.get()->m_StaticFilters[0].m_PacketsOut.QuadPart == 202 &&
                caller.get()->m_StaticFilters[0].m_BytesOut.QuadPart == 20002 &&
                caller.get()->m_StaticFilters[0].m_LastReset == 12345,
                label + ": original pre-reset counters remain readable");
            if (TestWow64() && (scenario == 4 || scenario == 7))
                Check(g_Test.enumerationCompletions == 1 && !g_Test.enumerationPending,
                    label + ": refresh reaches terminal completion exactly once");
            if (scenario == 8)
                Check(g_Test.completions == 1 && !g_Test.pending, label + ": table reaches terminal completion exactly once");
            Check(g_Test.outstandingAllocations == 0 && g_Test.freedWhilePending == 0 && g_Test.closedWhilePending == 0,
                label + ": staging remains live until completion and is released");
        }
    }
    Refresh(api, 2);
    printf("CONTROL stale table refresh checks=%u failures=%u\n", checks - beforeChecks, failures - beforeFailures);
}
#if defined(_USING_V110_SDK71_)
static const CNdisApi* concurrentApi = NULL;
static BOOL concurrentEnumeration = FALSE;
static DWORD concurrentWait = WAIT_FAILED;
static DWORD WINAPI ConcurrentRefreshWorker(void*) {
    TCP_AdapterList adapters = {};
    concurrentEnumeration = concurrentApi->GetTcpipBoundAdaptersInfo(&adapters);
    return 0;
}
static void FinishConcurrentMapUpdate() {
    HANDLE worker = CreateThread(NULL, 0, ConcurrentRefreshWorker, NULL, 0, NULL);
    if (!worker) { concurrentWait = WAIT_FAILED; return; }
    concurrentWait = WaitForSingleObject(worker, 5000);
    CloseHandle(worker);
    if (concurrentWait != WAIT_OBJECT_0) {
        printf("SETUP_FAILED: concurrent map update did not finish within five seconds\n");
        ExitProcess(2);
    }
}
static unsigned snapshotUnlocks = 0;
static void UpdateAfterSnapshot() {
    if (--snapshotUnlocks) { g_AfterMapUnlock = UpdateAfterSnapshot; return; }
    g_AdapterCount = 1; g_Adapters[0] = rawA;
    FinishConcurrentMapUpdate();
}
static void ConsistentSnapshot(const CNdisApi& api) {
    if (!TestWow64()) return;
    CNdisApi updateApi;
    concurrentApi = &updateApi;
    const unsigned beforeChecks = checks, beforeFailures = failures;
    for (unsigned opValue = GetTable; opValue <= GetReset; ++opValue) {
        for (unsigned fallback = 0; fallback != 2; ++fallback) {
            Refresh(api, 2);
            const HANDLE originalA = handleA, originalB = handleB;
            TestReset(); g_AdapterCount = 2; g_Adapters[0] = rawA; g_Adapters[1] = rawB;
            const DWORD count = fallback ? 3 : 2;
            Table caller(count); Response(count, TableBytes(count), count, rawA, rawB);
            if (fallback) reinterpret_cast<PSTATIC_FILTER_TABLE>(g_Test.response)->m_StaticFilters[2].m_Adapter.QuadPart = unknownRaw;
            // Fallback unlocks: initial snapshot, map refresh, then final snapshot.
            snapshotUnlocks = fallback ? 3 : 1;
            g_AfterMapUnlock = UpdateAfterSnapshot;
            concurrentEnumeration = FALSE; concurrentWait = WAIT_FAILED;
            Call c = { &api, static_cast<OP>(opValue), caller.get(), NULL, 0 };
            const std::string label = std::string(OpName(c.op)) + "/concurrent map snapshot" + (fallback ? "/unmapped" : "/known");
            const BOOL ok = Run(c, label);
            g_AfterMapUnlock = NULL;
            Check(concurrentWait == WAIT_OBJECT_0 && concurrentEnumeration, label + ": actual concurrent enumeration finishes at unlock");
            Check(ok && caller.get()->m_StaticFilters[0].m_Adapter.QuadPart == reinterpret_cast<ULONG_PTR>(originalA) &&
                caller.get()->m_StaticFilters[1].m_Adapter.QuadPart == reinterpret_cast<ULONG_PTR>(originalB),
                label + ": both known rows use one snapshot despite removing B");
            if (fallback) Check(caller.get()->m_StaticFilters[2].m_Adapter.QuadPart == 0xFFFFFFFFULL,
                label + ": unknown row is marked from the same final snapshot");
            Check(g_Test.enumerationCalls == (fallback ? 2U : 1U) && g_Test.ioctlCalls == 1,
                label + ": only the expected refresh and concurrent enumeration are issued");
            Check(api.GetBytesReturned() == TableBytes(count), label + ": updater instance cannot change caller byte accounting");
            Check(g_Test.resetStatsSideEffects == (c.op == GetReset ? 1U : 0U), label + ": reset is issued once");
            TestReset();
            Call removed = { &api, FlushQueue, NULL, originalB, 0 };
            Check(!Run(removed, label + "/removed mapping") && removed.error == ERROR_INVALID_HANDLE && g_Test.ioctlCalls == 0,
                label + ": concurrent update really removed B from live map");
        }
    }
    Refresh(api, 2);
    printf("CONTROL consistent snapshot checks=%u failures=%u\n", checks - beforeChecks, failures - beforeFailures);
}
#endif
int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    TestReset();
    printf("Task12a actual SDK handles/tables baseline\narchitecture=%zu WOW64=%s\n", sizeof(void*) * 8, TestWow64() ? "TRUE" : "FALSE");
#ifndef _WIN64
    if (!TestWow64()) { printf("SETUP_FAILED: x86 test requires genuine WOW64\n"); return 2; }
#endif
    CNdisApi api;
    if (!api.IsDriverLoaded()) { printf("SETUP_FAILED: shim device did not open\n"); return 2; }
    if (!Refresh(api, 2)) return 2;
    Check(handleA != NULL && handleB != NULL && handleA != handleB, "enumeration: genuine API supplied two distinct handles");
    Check(!TestWow64() || (reinterpret_cast<ULONG_PTR>(handleA) <= ADAPTER_LIST_SIZE &&
        reinterpret_cast<ULONG_PTR>(handleB) <= ADAPTER_LIST_SIZE), "enumeration: real WOW64 map produced indexed handles");
    ValidIdentities(api, handleA, rawA, "initial valid mapping");
    Inputs(api);
    UnmappedMarkerInputs(api);
    InvalidIdentities(api);
    Getters(api);
    ArithmeticAndAllocation(api);
    RoundTripAndRefresh(api);
    StableAndFullMappings(api);
    StaleTableRefresh(api);
#if defined(_USING_V110_SDK71_)
    ConsistentSnapshot(api);
#endif
    TestAbandonPending();
    printf("checks=%u failures=%u guarded_baseline_faults=%u\nRESULT=%u\n", checks, failures, guardedFaults, failures ? 1U : 0U);
    return failures ? 1 : 0;
}