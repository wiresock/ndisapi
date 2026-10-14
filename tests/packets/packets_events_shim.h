#ifndef SDK_PACKETS_EVENTS_SHIM_H
#define SDK_PACKETS_EVENTS_SHIM_H
// Event tests use a separate bounded, synchronized state; the original packet
// oracle remains single-threaded. Real kernel event operations are retained.
struct PACKET_EVENT_STATS {
    DWORD creates, createFailures, resets, resetFailures, closes, live, peakLive;
    DWORD ioctls, completions, activeRequests, peakRequests, identityConflicts;
    DWORD earlyResetOrClose, changedInput, signaledOnSubmit, waitFailures, closeFailures;
};
void PacketEventsBegin();
void PacketEventsConfigure(bool pending, bool success, DWORD error, bool clobber);
void PacketEventsFailCreate();
void PacketEventsFailReset();
PACKET_EVENT_STATS PacketEventsStats();
bool PacketEventsWaitActive(DWORD count);
void PacketEventsRelease();
void PacketEventsFinish(unsigned checks, unsigned failures);
HANDLE WINAPI PacketCreateEvent(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCTSTR);
BOOL WINAPI PacketResetEvent(HANDLE);
bool PacketEventsEnabled();
BOOL PacketEventsIoctl(void*, DWORD, DWORD*, OVERLAPPED*);
BOOL PacketEventsCompletion(OVERLAPPED*, DWORD*, BOOL);
void PacketEventsObserveClose(HANDLE, BOOL);
#endif