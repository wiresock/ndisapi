// Executes the complete shipping fastio_packet_filter.h worker, not a copied reader.
// OS/adapter/API glue, atomic scheduling, and copy bounds are substituted explicitly.
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <ws2ipdef.h>
#include <winioctl.h>
#include <tchar.h>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <functional>
#include <atomic>
#include <thread>
#include <chrono>
#include <string>
#include <vector>
#include <type_traits>
#include <new>
#include <algorithm>
#include <iostream>
#include "Common.h"

// Test allocations retain their requested extent and end at a protected page.
// The original overlong copy is rejected BEFORE touching these guard pages.
struct Allocation { void* pointer; void* base; size_t requested; };
static Allocation allocations[8192]{};
static size_t requested_size(const void* pointer)
{
    for (const auto& entry : allocations) if (entry.pointer == pointer) return entry.requested;
    return 0;
}
static void* guarded_allocate(size_t size, size_t alignment)
{
    if (!size) size = 1;
    if (alignment < 16) alignment = 16;
    const size_t rounded = (size + alignment - 1) & ~(alignment - 1);
    const size_t accessible = (rounded + 4095) & ~size_t(4095);
    if (alignment > 4096 || accessible > SIZE_MAX - 4096) throw std::bad_alloc();
    auto* base = static_cast<unsigned char*>(VirtualAlloc(nullptr, accessible + 4096,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!base) throw std::bad_alloc();
    DWORD old_protection = 0;
    if (!VirtualProtect(base + accessible, 4096, PAGE_NOACCESS, &old_protection))
    { VirtualFree(base, 0, MEM_RELEASE); throw std::bad_alloc(); }
    void* pointer = base + accessible - rounded;
    for (auto& entry : allocations) if (!entry.pointer)
    { entry = {pointer, base, size}; return pointer; }
    VirtualFree(base, 0, MEM_RELEASE);
    throw std::bad_alloc();
}
static void guarded_free(void* pointer) noexcept
{
    if (!pointer) return;
    for (auto& entry : allocations) if (entry.pointer == pointer)
    { VirtualFree(entry.base, 0, MEM_RELEASE); entry = {}; return; }
    std::abort();
}
void* operator new(size_t size) { return guarded_allocate(size, 16); }
void* operator new[](size_t size) { return guarded_allocate(size, 16); }
void operator delete(void* p) noexcept { guarded_free(p); }
void operator delete[](void* p) noexcept { guarded_free(p); }
void operator delete(void* p, size_t) noexcept { guarded_free(p); }
void operator delete[](void* p, size_t) noexcept { guarded_free(p); }
void* operator new(size_t size, std::align_val_t a) { return guarded_allocate(size, static_cast<size_t>(a)); }
void* operator new[](size_t size, std::align_val_t a) { return guarded_allocate(size, static_cast<size_t>(a)); }
void operator delete(void* p, std::align_val_t) noexcept { guarded_free(p); }
void operator delete[](void* p, std::align_val_t) noexcept { guarded_free(p); }
void operator delete(void* p, size_t, std::align_val_t) noexcept { guarded_free(p); }
void operator delete[](void* p, size_t, std::align_val_t) noexcept { guarded_free(p); }

namespace fixture {
enum class schedule { stable, late_complete, late_busy, late_multiple, tail_after_copy,
    late_invalid, late_regress, stop_busy, zero_busy, zero_complete, stop_copy, notify_reader, claim_window };
struct controlled_bounds {};
struct bounded_poll {};
struct context {
    schedule scheduling = schedule::stable;
    PFAST_IO_SECTION sections[4]{};
    INTERMEDIATE_BUFFER* packet_storage = nullptr;
    PINTERMEDIATE_BUFFER* adapter_storage = nullptr;
    PINTERMEDIATE_BUFFER* mstcp_storage = nullptr;
    size_t packet_bytes = 0, adapter_bytes = 0, mstcp_bytes = 0;
    size_t physical = 0;
    std::vector<INTERMEDIATE_BUFFER> golden;
    std::vector<DWORD> adapter_ids, mstcp_ids;
    std::function<void()> stop;
    size_t atomic_calls = 0, copy_calls = 0, copied_packets = 0, reset_attempts = 0;
    size_t busy_reads = 0, waits = 0, event_resets = 0;
    size_t queue_reads = 0, send_calls = 0;
    bool enabled = false, injected = false, pending_completion = false;
    bool copy_bounds_fault = false, polling_exhausted = false, output_valid = true;
    bool writer_prechecked = false, reset_busy_header = false;
    size_t writer_reservations = 0, writer_completions = 0, writer_requeues = 0;
};
static context* current = nullptr;
static DWORD raw_load(volatile DWORD* pointer)
{ return static_cast<DWORD>(::InterlockedCompareExchange(reinterpret_cast<volatile LONG*>(pointer), 0, 0)); }
static DWORD raw_exchange(volatile DWORD* pointer, DWORD value)
{ return static_cast<DWORD>(::InterlockedExchange(reinterpret_cast<volatile LONG*>(pointer), static_cast<LONG>(value))); }
static bool is_write(const volatile DWORD* pointer)
{
    return current && current->enabled && current->sections[0] &&
        pointer == &current->sections[0]->fast_io_header.fast_io_write_union.union_.join;
}
static void complete_pending_writer()
{
    auto& c = *current;
    auto* word = &c.sections[0]->fast_io_header.fast_io_write_union.union_.join;
    const DWORD reserved = 0x10003UL;
    const DWORD observed = static_cast<DWORD>(::InterlockedCompareExchange(
        reinterpret_cast<volatile LONG*>(word), 3, static_cast<LONG>(reserved)));
    if (observed == reserved) ++c.writer_completions;
    else ++c.writer_requeues; // Matches the real writer's failed-completion ownership rule.
    c.pending_completion = false;
}
static void reserve_late_writer(bool leave_pending)
{
    auto& c = *current;
    auto* word = &c.sections[0]->fast_io_header.fast_io_write_union.union_.join;
    const DWORD observed = static_cast<DWORD>(::InterlockedCompareExchange(
        reinterpret_cast<volatile LONG*>(word), 0x10003L, 2));
    if (!c.writer_prechecked || observed != 2) { c.output_valid = false; return; }
    ++c.writer_reservations;
    // The writer checked the reader flag before the claim, then resumes here.
    // Reserve -> copy the appended slot -> completion CAS is the public protocol.
    std::memcpy(&c.sections[0]->fast_io_packets[2], &c.golden[2], sizeof(INTERMEDIATE_BUFFER));
    c.injected = true;
    c.pending_completion = true;
    if (!leave_pending) complete_pending_writer();
}
static void before_reset(volatile DWORD* pointer)
{
    if (!is_write(pointer)) return;
    auto& c = *current;
    ++c.reset_attempts;
    auto inject = [&](DWORD count, bool busy) {
        c.injected = true;
        raw_exchange(pointer, count | (busy ? 0x10000UL : 0));
    };
    switch (c.scheduling) {
    case schedule::late_complete: if (!c.injected) reserve_late_writer(false); break;
    case schedule::late_busy:
        if (!c.injected) reserve_late_writer(true);
        break;
    case schedule::late_multiple:
        if (c.reset_attempts <= 3) inject(static_cast<DWORD>(2 + c.reset_attempts), false);
        break;
    case schedule::late_invalid: if (!c.injected) inject(static_cast<DWORD>(c.physical + 1), false); break;
    case schedule::late_regress: if (!c.injected) inject(1, false); break;
    default: break;
    }
}
static DWORD compare_exchange(volatile DWORD* pointer, DWORD exchange, DWORD comparand)
{
    auto* c = current;
    if (c && c->enabled) {
        if (++c->atomic_calls > 128) { c->polling_exhausted = true; throw bounded_poll{}; }
        if (is_write(pointer) && exchange == 0 && comparand != 0) before_reset(pointer);
        if (is_write(pointer) && exchange == 0 && comparand == 0) {
            const DWORD value = raw_load(pointer);
            const bool claimed = raw_load(&c->sections[0]->fast_io_header.read_in_progress_flag) != 0;
            if (!claimed) c->writer_prechecked = true;
            if ((value >> 16) && claimed) {
                ++c->busy_reads;
                if (c->scheduling == schedule::stop_busy || c->scheduling == schedule::zero_busy) c->stop();
                if (c->scheduling == schedule::zero_complete) raw_exchange(pointer, 0);
                if (c->pending_completion && c->busy_reads >= 2) {
                    complete_pending_writer();
                }
            }
        }
    }
    return static_cast<DWORD>(::InterlockedCompareExchange(reinterpret_cast<volatile LONG*>(pointer),
        static_cast<LONG>(exchange), static_cast<LONG>(comparand)));
}
static DWORD exchange(volatile DWORD* pointer, DWORD value)
{
    if (current && current->enabled) {
        if (++current->atomic_calls > 128) { current->polling_exhausted = true; throw bounded_poll{}; }
        if (is_write(pointer) && value == 0) {
            before_reset(pointer);
            if (raw_load(pointer) >> 16) current->reset_busy_header = true;
        }
        if (current->scheduling == schedule::claim_window && !current->injected && value == 1 &&
            pointer == &current->sections[0]->fast_io_header.read_in_progress_flag) {
            current->injected = true;
            raw_exchange(&current->sections[0]->fast_io_header.fast_io_write_union.union_.join, 5);
        }
    }
    const DWORD previous = raw_exchange(pointer, value);
    if (is_write(pointer) && value == 0 && current->pending_completion) complete_pending_writer();
    return previous;
}
static void* copy(void* destination, const void* source, size_t bytes)
{
    if (!current || !current->enabled) return std::memmove(destination, source, bytes);
    auto& c = *current;
    ++c.copy_calls;
    const auto begin = reinterpret_cast<uintptr_t>(c.packet_storage);
    const auto address = reinterpret_cast<uintptr_t>(destination);
    bool valid = address >= begin && address - begin <= c.packet_bytes &&
        bytes <= c.packet_bytes - (address - begin) && bytes % sizeof(INTERMEDIATE_BUFFER) == 0;
    bool valid_source = false;
    for (auto section : c.sections) {
        const auto first = reinterpret_cast<uintptr_t>(&section->fast_io_packets[0]);
        const auto src = reinterpret_cast<uintptr_t>(source);
        const size_t extent = c.physical * sizeof(INTERMEDIATE_BUFFER);
        if (src >= first && src - first <= extent && bytes <= extent - (src - first)) valid_source = true;
    }
    if (!valid || !valid_source) { c.copy_bounds_fault = true; throw controlled_bounds{}; }
    c.copied_packets += bytes / sizeof(INTERMEDIATE_BUFFER);
    void* result = std::memmove(destination, source, bytes);
    if (!c.injected && c.scheduling == schedule::tail_after_copy) {
        c.injected = true;
        raw_exchange(&c.sections[0]->fast_io_header.fast_io_write_union.union_.join, 5);
    }
    if (!c.injected && c.scheduling == schedule::stop_copy) { c.injected = true; c.stop(); }
    if (!c.injected && c.scheduling == schedule::notify_reader) {
        c.injected = true;
        raw_exchange(&c.sections[0]->fast_io_header.read_in_progress_flag, 2);
    }
    return result;
}
static BOOL submit(PINTERMEDIATE_BUFFER* pointers, DWORD count, PDWORD returned, bool adapter)
{
    auto& c = *current;
    ++c.send_calls;
    const size_t bytes = adapter ? c.adapter_bytes : c.mstcp_bytes;
    auto expected_pointer = adapter ? c.adapter_storage : c.mstcp_storage;
    if (pointers != expected_pointer || count > bytes / sizeof(*pointers)) {
        c.output_valid = false;
        throw controlled_bounds{};
    }
    auto& output = adapter ? c.adapter_ids : c.mstcp_ids;
    for (DWORD i = 0; i < count; ++i) {
        const uintptr_t pointer = reinterpret_cast<uintptr_t>(pointers[i]);
        const uintptr_t start = reinterpret_cast<uintptr_t>(c.packet_storage);
        if (pointer < start || pointer - start > c.packet_bytes - sizeof(INTERMEDIATE_BUFFER) ||
            (pointer - start) % sizeof(INTERMEDIATE_BUFFER)) { c.output_valid = false; continue; }
        const DWORD id = pointers[i]->m_FilterID;
        if (id == 0 || id > c.golden.size() || std::memcmp(pointers[i], &c.golden[id - 1], sizeof(INTERMEDIATE_BUFFER)))
            c.output_valid = false;
        output.push_back(id);
    }
    *returned = count;
    return TRUE;
}
}

// Only the API and network/event boundary is substituted; this does not implement a reader.
class CNdisApi {
public:
    virtual ~CNdisApi() = default;
    BOOL GetTcpipBoundAdaptersInfo(PTCP_AdapterList list) const { list->m_nAdapterCount = 0; return TRUE; }
    static BOOL ConvertWindows2000AdapterName(const char*, char* name, DWORD size)
    { if (size) name[0] = '\0'; return TRUE; }
    BOOL InitializeFastIo(PFAST_IO_SECTION section, DWORD size) const
    { std::memset(section, 0, size); return TRUE; }
    BOOL AddSecondaryFastIo(PFAST_IO_SECTION section, DWORD size) const
    { std::memset(section, 0, size); return TRUE; }
    BOOL SendPacketsToAdaptersUnsorted(PINTERMEDIATE_BUFFER* p, DWORD n, PDWORD r) const
    { return fixture::submit(p, n, r, true); }
    BOOL SendPacketsToMstcpUnsorted(PINTERMEDIATE_BUFFER* p, DWORD n, PDWORD r) const
    { return fixture::submit(p, n, r, false); }
    BOOL ReadPacketsUnsorted(PINTERMEDIATE_BUFFER*, DWORD, PDWORD) const
    { ++fixture::current->queue_reads; return FALSE; }
};
namespace ndisapi {
class network_adapter {
public:
    network_adapter() = default;
    network_adapter(CNdisApi*, HANDLE, unsigned char*, std::string, std::string, uint32_t, uint16_t) {}
    bool set_packet_event() const { return true; }
    void set_mode(unsigned) {}
    void release() {}
    const std::string& get_friendly_name() const { static std::string name("fixture"); return name; }
    unsigned wait_event(unsigned milliseconds) const {
        if (milliseconds != INFINITE) fixture::current->output_valid = false;
        ++fixture::current->waits;
        fixture::current->stop();
        return WAIT_OBJECT_0;
    }
    bool reset_event() const { ++fixture::current->event_resets; return true; }
};
}

// All standard/Windows declarations above are untouched. Only actual-header calls are redirected.
#undef InterlockedCompareExchange
#undef InterlockedExchange
#define InterlockedCompareExchange fixture::compare_exchange
#define InterlockedExchange fixture::exchange
#define memmove fixture::copy
#define private public
#include "fastio_packet_filter.h"
#undef private
#undef memmove
#undef InterlockedExchange
#undef InterlockedCompareExchange

static unsigned checks = 0, failures = 0;
static void check(bool condition, const char* scenario, const char* property)
{
    ++checks;
    if (!condition) ++failures;
    std::printf("[%s] %s: %s\n", condition ? "PASS" : "FAIL", scenario, property);
}
static size_t physical_capacity()
{ return (ndisapi::fast_io_size - sizeof(FAST_IO_SECTION_HEADER)) / sizeof(INTERMEDIATE_BUFFER); }
static DWORD packet_count(size_t value) { return static_cast<DWORD>(value); }
static void fill_packet(INTERMEDIATE_BUFFER& packet, DWORD id, bool incoming)
{
    std::memset(&packet, static_cast<unsigned char>((id * 17) & 255), sizeof(packet));
    packet.m_hAdapter = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(0x1234));
    packet.m_dwDeviceFlags = incoming ? PACKET_FLAG_ON_RECEIVE : PACKET_FLAG_ON_SEND;
    packet.m_Length = 64;
    packet.m_FilterID = id;
}
static void run_case(const char* name, fixture::schedule schedule, size_t per_section,
    unsigned sections_used, bool incoming, bool mixed, bool revert, DWORD expected_header,
    size_t expected_count, bool initially_busy = false, bool invalid_initial = false)
{
    fixture::context c;
    c.scheduling = schedule;
    c.physical = physical_capacity();
    fixture::current = &c;
    ndisapi::fastio_packet_filter filter(nullptr, nullptr, true);
    filter.network_interfaces_.push_back(std::make_unique<ndisapi::network_adapter>());
    check(filter.init_filter(), name, "actual init_filter succeeds");
    c.packet_storage = filter.packet_buffer_.get();
    c.adapter_storage = reinterpret_cast<PINTERMEDIATE_BUFFER*>(filter.write_adapter_request_ptr_.get());
    c.mstcp_storage = reinterpret_cast<PINTERMEDIATE_BUFFER*>(filter.write_mstcp_request_ptr_.get());
    c.packet_bytes = requested_size(c.packet_storage);
    c.adapter_bytes = requested_size(c.adapter_storage);
    c.mstcp_bytes = requested_size(c.mstcp_storage);
    c.stop = [&] { filter.filter_state_ = ndisapi::fastio_packet_filter::filter_state::stopping; };
    for (size_t i = 0; i < 4; ++i)
        c.sections[i] = reinterpret_cast<PFAST_IO_SECTION>(&filter.fast_io_ptr_.get()[i]);
    const size_t seed_per_section = (std::max)(per_section, size_t(5));
    c.golden.resize(seed_per_section * sections_used);
    std::vector<DWORD> expected_adapter, expected_mstcp;
    for (unsigned s = 0; s < sections_used; ++s) {
        for (size_t i = 0; i < seed_per_section && i < c.physical; ++i) {
            const DWORD id = packet_count(s * seed_per_section + i + 1);
            const bool is_incoming = mixed ? ((id % 2) == 0) : incoming;
            auto& packet = c.sections[s]->fast_io_packets[i];
            fill_packet(packet, id, is_incoming);
            c.golden[id - 1] = packet;
            if (i < expected_count / sections_used) {
                const bool reverse = revert && (id % 3) == 0;
                const bool to_adapter = reverse ? is_incoming : !is_incoming;
                (to_adapter ? expected_adapter : expected_mstcp).push_back(id);
            }
        }
        const DWORD count = invalid_initial ? packet_count(c.physical + 1) : packet_count(per_section);
        c.sections[s]->fast_io_header.fast_io_write_union.union_.join = count | (initially_busy ? 0x10000UL : 0);
    }
    if (revert) {
        auto action = [](HANDLE, INTERMEDIATE_BUFFER& p) {
            return p.m_FilterID % 3 == 0 ? ndisapi::fastio_packet_filter::packet_action::revert :
                ndisapi::fastio_packet_filter::packet_action::pass;
        };
        filter.filter_incoming_packet_ = action;
        filter.filter_outgoing_packet_ = action;
    }
    bool returned = false;
    c.enabled = true;
    try { filter.filter_working_thread(); returned = true; }
    catch (const fixture::controlled_bounds&) {}
    catch (const fixture::bounded_poll&) {}
    c.enabled = false;
    filter.filter_state_ = ndisapi::fastio_packet_filter::filter_state::stopped;
    check(returned, name, "worker returns normally within bounded schedule");
    check(!c.copy_bounds_fault, name, "all copies stay inside real source and destination allocations");
    check(!c.polling_exhausted, name, "stop is observed without exhausting atomic-operation budget");
    check(c.output_valid, name, "every output pointer and complete packet payload is valid");
    check(c.adapter_ids == expected_adapter, name, "adapter output has exact packet identities once in order");
    check(c.mstcp_ids == expected_mstcp, name, "MSTCP output has exact packet identities once in order");
    check(c.sections[0]->fast_io_header.fast_io_write_union.union_.join == expected_header,
        name, "only fully consumed header state is cleared");
    bool claims_released = true;
    for (auto section : c.sections) if (section->fast_io_header.read_in_progress_flag != 0) claims_released = false;
    check(claims_released, name, "all reader claims are released");
    check(c.queue_reads == 0, name, "no queue fallback is introduced");
    check(!c.reset_busy_header, name, "reset never clears an incomplete writer snapshot");
    check(c.waits == c.event_resets, name, "event waiting retains paired resets");
    if (schedule == fixture::schedule::late_complete) {
        check(c.writer_prechecked && c.writer_reservations == 1 && c.writer_completions == 1 && c.writer_requeues == 0,
            name, "late writer reserved and completed after prechecking reader flag");
    }
    if (schedule == fixture::schedule::late_busy) {
        check(c.writer_reservations == 1 && c.writer_completions == 1 && c.writer_requeues == 0,
            name, "reader waits for pending completion instead of forcing writer requeue");
    }
    std::printf("TRACE %s atomics=%zu copies=%zu copied=%zu resets=%zu busy_reads=%zu wait=%zu sends=%zu writer=%zu/%zu/requeued=%zu\n",
        name, c.atomic_calls, c.copy_calls, c.copied_packets, c.reset_attempts, c.busy_reads, c.waits, c.send_calls,
        c.writer_reservations, c.writer_completions, c.writer_requeues);
    fixture::current = nullptr;
}
static void capacities()
{
    fixture::context c;
    fixture::current = &c;
    ndisapi::fastio_packet_filter filter(nullptr, nullptr, true);
    filter.network_interfaces_.push_back(std::make_unique<ndisapi::network_adapter>());
    check(filter.init_filter(), "capacity", "actual init_filter succeeds");
    const size_t total = 4 * (std::min)(physical_capacity(), size_t(65535));
    check(ndisapi::maximum_packet_block == total, "capacity", "one logical bound equals four usable section capacities");
    check(requested_size(filter.packet_buffer_.get()) >= total * sizeof(INTERMEDIATE_BUFFER),
        "capacity", "actual packet allocation covers every section slot");
    check(requested_size(filter.write_adapter_request_ptr_.get()) >= total * sizeof(PINTERMEDIATE_BUFFER),
        "capacity", "actual adapter pointer allocation covers every section slot");
    check(requested_size(filter.write_mstcp_request_ptr_.get()) >= total * sizeof(PINTERMEDIATE_BUFFER),
        "capacity", "actual MSTCP pointer allocation covers every section slot");
    std::printf("LAYOUT pointer=%zu frame=%u IB=%zu physical=%zu aggregate=%zu logical=%zu packet_bytes=%zu adapter_bytes=%zu mstcp_bytes=%zu\n",
        sizeof(void*), unsigned(MAX_ETHER_FRAME), sizeof(INTERMEDIATE_BUFFER), physical_capacity(), total,
        ndisapi::maximum_packet_block, requested_size(filter.packet_buffer_.get()),
        requested_size(filter.write_adapter_request_ptr_.get()), requested_size(filter.write_mstcp_request_ptr_.get()));
    fixture::current = nullptr;
}
#ifndef FASTIO_WORKER_ONLY
// Directly exercise the same production helper called by the real worker.
// Its caller may offer less than one physical section's capacity.
static void run_helper_case(const char* name, size_t capacity, bool append_late, bool accept)
{
    fixture::context c;
    c.scheduling = append_late ? fixture::schedule::late_complete : fixture::schedule::stable;
    c.physical = physical_capacity();
    fixture::current = &c;
    ndisapi::fastio_packet_filter filter(nullptr, nullptr, true);
    filter.network_interfaces_.push_back(std::make_unique<ndisapi::network_adapter>());
    check(filter.init_filter(), name, "actual init_filter succeeds");
    c.packet_storage = filter.packet_buffer_.get();
    // Limit the copy interception to the offered destination subspan, which is
    // deliberately smaller than the allocation. The immediately following packet
    // is a canary; no ablation may write it before the interception rejects a copy.
    c.packet_bytes = capacity * sizeof(INTERMEDIATE_BUFFER);
    c.stop = [&] { filter.filter_state_ = ndisapi::fastio_packet_filter::filter_state::stopping; };
    for (size_t i = 0; i < 4; ++i)
        c.sections[i] = reinterpret_cast<PFAST_IO_SECTION>(&filter.fast_io_ptr_.get()[i]);
    c.golden.resize(3);
    for (DWORD i = 0; i < 3; ++i) {
        fill_packet(c.golden[i], i + 1, false);
        c.sections[0]->fast_io_packets[i] = c.golden[i];
    }
    INTERMEDIATE_BUFFER canary;
    std::memset(&canary, 0xa5, sizeof(canary));
    c.packet_storage[capacity] = canary;
    c.sections[0]->fast_io_header.fast_io_write_union.union_.join = 2;
    filter.filter_state_ = ndisapi::fastio_packet_filter::filter_state::running;
    DWORD published_count = 0;
    bool returned = false;
    c.enabled = true;
    try {
        published_count = filter.read_fast_io_section(c.sections[0], c.packet_storage, capacity);
        returned = true;
    }
    catch (const fixture::controlled_bounds&) {}
    catch (const fixture::bounded_poll&) {}
    c.enabled = false;
    filter.filter_state_ = ndisapi::fastio_packet_filter::filter_state::stopped;
    check(returned, name, "helper returns normally");
    check(published_count == (accept ? 2UL : 0UL), name, "only an accepted snapshot publishes its count");
    check(!c.copy_bounds_fault, name, "helper rejects before any over-capacity copy attempt");
    check(c.copied_packets == (capacity == 1 ? 0U : 2U), name, "only the bounded complete prefix is copied");
    check(c.copy_calls == (capacity == 1 ? 0U : 1U), name, "no excess-tail copy is attempted after reset contention");
    check(c.sections[0]->fast_io_header.fast_io_write_union.union_.join ==
        (accept ? 0UL : (append_late ? 3UL : 2UL)), name, "unconsumed header is preserved");
    check(c.sections[0]->fast_io_header.read_in_progress_flag == 0, name, "reader claim is released");
    check(std::memcmp(&c.packet_storage[capacity], &canary, sizeof(canary)) == 0,
        name, "destination beyond offered capacity is unchanged");
    check(!c.polling_exhausted, name, "helper finishes within the bounded schedule");
    check(c.send_calls == 0 && c.queue_reads == 0, name, "private staging is not sent or queued by the helper");
    if (append_late) {
        check(c.writer_prechecked && c.writer_reservations == 1 && c.writer_completions == 1 &&
            c.writer_requeues == 0, name, "completed late writer stays within the physical section");
        check(c.reset_attempts == 1, name, "count is revalidated immediately after the failed reset CAS");
    }
    std::printf("HELPER %s capacity=%zu published=%lu copies=%zu copied=%zu resets=%zu header=%lu\n",
        name, capacity, published_count, c.copy_calls, c.copied_packets, c.reset_attempts,
        c.sections[0]->fast_io_header.fast_io_write_union.union_.join);
    fixture::current = nullptr;
}
#endif

int main()
{
    capacities();
#ifndef FASTIO_WORKER_ONLY
    run_helper_case("helper-initial-insufficient", 1, false, false);
    run_helper_case("helper-exact-fit", 2, false, true);
    run_helper_case("helper-late-over-remaining", 2, true, false);
#endif
    const size_t full = physical_capacity();
    using s = fixture::schedule;
    run_case("one-send", s::stable, 1, 1, false, false, false, 0, 1);
    run_case("one-receive", s::stable, 1, 1, true, false, false, 0, 1);
    run_case("zero", s::stable, 0, 1, false, false, false, 0, 0);
    run_case("full-four-send", s::stable, full, 4, false, false, false, 0, full * 4);
    run_case("full-four-receive", s::stable, full, 4, true, false, false, 0, full * 4);
    run_case("full-four-mixed-revert", s::stable, full, 4, false, true, true, 0, full * 4);
    run_case("claim-window", s::claim_window, 2, 1, false, false, false, 0, 5);
    run_case("late-complete", s::late_complete, 2, 1, false, false, false, 0, 3);
    run_case("late-busy-complete", s::late_busy, 2, 1, false, false, false, 0, 3);
    run_case("late-multiple", s::late_multiple, 2, 1, false, false, false, 0, 5);
    run_case("full-new-tail", s::tail_after_copy, 2, 1, false, false, false, 0, 5);
    run_case("late-invalid", s::late_invalid, 2, 1, false, false, false, packet_count(full + 1), 0);
    run_case("late-regress", s::late_regress, 2, 1, false, false, false, 1, 0);
    run_case("invalid-initial", s::stable, 2, 1, false, false, false, packet_count(full + 1), 0, false, true);
    run_case("stop-busy", s::stop_busy, 2, 1, false, false, false, 0x10002UL, 0, true);
    run_case("zero-busy-stop", s::zero_busy, 0, 1, false, false, false, 0x10000UL, 0, true);
    run_case("zero-busy-complete", s::zero_complete, 0, 1, false, false, false, 0, 0, true);
    run_case("stop-after-copy", s::stop_copy, 2, 1, false, false, false, 2, 0);
    run_case("writer-notification", s::notify_reader, 2, 1, false, false, false, 0, 2);
    std::printf("%u checks, %u failures\nRESULT=%u\n", checks, failures, failures ? 1U : 0U);
    return failures ? 1 : 0;
}