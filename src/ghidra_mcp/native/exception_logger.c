/* ghidra_mcp exception logger: VEH-first inside the target, no debugger attached.
 *
 * DllMain(ATTACH) installs a first-chance vectored exception handler and logs every
 * exception (code, faulting address, AV target, thread id) to %TEMP%\exclog_<pid>.log.
 * The target runs at full speed; anti-debug that checks IsDebuggerPresent or debug
 * registers sees nothing, because there is nothing to see - the logger lives in-process.
 *
 * The handler avoids the CRT (hand-rolled hex, kernel32 only) because it can fire on
 * any thread at any moment, including inside CRT startup where CRT state is broken.
 *
 * Exports:
 *   exc_count   - exceptions logged so far
 *   exc_stop    - remove the handler (call before unload if the process keeps running)
 *   exc_version - "ghidra-mcp-exclog-1"
 */

#include <windows.h>

#define LOG_MAX_LINE 160

static volatile LONG g_count = 0;
static volatile LONG g_active = 0;
static HANDLE g_log = NULL;
static char g_log_path[MAX_PATH];
static CRITICAL_SECTION g_lock;

/* --- minimal formatting: no CRT in the handler ----------------------------- */

static char *hex32(char *out, unsigned long value) {
    static const char digits[] = "0123456789abcdef";
    int shift;
    char *p = out;
    int started = 0;
    for (shift = 28; shift >= 0; shift -= 4) {
        unsigned nibble = (value >> shift) & 0xF;
        if (nibble || started || shift == 0) {
            *p++ = digits[nibble];
            started = 1;
        }
    }
    *p = 0;
    return p;
}

static char *copy_str(char *out, const char *text) {
    while (*text) *out++ = *text++;
    *out = 0;
    return out;
}

static void append_line(const char *line, unsigned len) {
    DWORD written = 0;
    if (!g_log) return;
    EnterCriticalSection(&g_lock);
    WriteFile(g_log, line, len, &written, NULL);
    FlushFileBuffers(g_log);
    LeaveCriticalSection(&g_lock);
}

/* --- the vectored exception handler ---------------------------------------- */

static void log_marker(const char *text);

static LONG CALLBACK exc_handler(PEXCEPTION_POINTERS info) {    EXCEPTION_RECORD *record = info->ExceptionRecord;
    char line[LOG_MAX_LINE];
    char *p = line;
    unsigned long code = record->ExceptionCode;
    unsigned long long at = (unsigned long long)(uintptr_t)record->ExceptionAddress;
    unsigned long long target = 0;
    static volatile LONG first = 0;
    unsigned tid = GetCurrentThreadId();

    if (code == 0x10006133) return EXCEPTION_CONTINUE_SEARCH; /* our sentinel, if ever needed */

    if (!InterlockedExchange(&first, 1)) log_marker("first exc hit\r\n");

    /* first parameter of an access violation is the unreadable/writable address */
    if ((code & 0xFFFFFFFFUL) == 0xC0000005UL && record->NumberParameters >= 2) {
        target = (unsigned long long)(uintptr_t)record->ExceptionInformation[1];
    }

    InterlockedIncrement(&g_count);

    p = copy_str(p, "exc code=");
    p = hex32(p, code);
    p = copy_str(p, " at=0x");
    p = hex32(p, (unsigned long)at);
    if (target) {
        p = copy_str(p, " target=0x");
        p = hex32(p, (unsigned long)target);
    }
    p = copy_str(p, " tid=");
    p = hex32(p, tid);
    *p++ = '\r';
    *p++ = '\n';
    append_line(line, (unsigned)(p - line));

    return EXCEPTION_CONTINUE_SEARCH; /* first chance: let the target handle it as usual */
}

/* process-wide tap for exceptions nothing else handled: every native crash ends
 * here, even when no VEH is visible on the faulting thread */
static LONG CALLBACK uef_handler(PEXCEPTION_POINTERS info) {
    exc_handler(info); /* same log line */
    return EXCEPTION_CONTINUE_SEARCH; /* let WER/crash reporting do its normal thing */
}

/* --- lifecycle -------------------------------------------------------------- */

static void build_log_path(void) {
    char temp[MAX_PATH];
    g_log_path[0] = 0;
    if (!GetTempPathA(MAX_PATH - 40, temp)) return;
    wsprintfA(g_log_path, "%sexclog_%lu.log", temp, (unsigned long)GetCurrentProcessId());
}

static void start_logger(void) {
    if (InterlockedExchange(&g_active, 1)) return;
    build_log_path();
    g_log = CreateFileA(g_log_path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    InitializeCriticalSection(&g_lock);
    if (g_log == INVALID_HANDLE_VALUE) g_log = NULL;
}

static void log_marker(const char *text) {
    if (!g_log) return;
    DWORD written = 0;
    DWORD len = 0;
    while (text[len] && len < 120) len++;
    EnterCriticalSection(&g_lock);
    WriteFile(g_log, text, len, &written, NULL);
    LeaveCriticalSection(&g_lock);
}

/* VEH visibility on this Windows build is restricted: a handler registered during
 * loader initialization (an APC-loaded DLL's DllMain) never fires, and one registered
 * on a secondary thread only fires for that thread. The working pattern is
 * "register on thread T, outside the loader, for thread T" - so DllMain queues a
 * self-APC that registers the VEH on the main thread, before target code runs. */
static void start_logger(void);
static void log_marker(const char *text);

static void NTAPI attach_apc(ULONG_PTR arg) {
    (void)arg;
    start_logger();
    /* Two taps, because this Windows build restricts VEH visibility to the
     * registering thread: the VEH still catches first-chance exceptions on the
     * thread that registered it, and the unhandled-exception filter is
     * process-wide - for native targets most crashes land there. */
    if (AddVectoredExceptionHandler(1, exc_handler))
        log_marker("veh attached (apc)\r\n");
    SetUnhandledExceptionFilter(uef_handler);
    log_marker("uef attached (apc)\r\n");
}

__declspec(dllexport) void __stdcall exc_attach(void) {
    attach_apc(0); /* callable from the injector side (debugger .call) per thread */
}

static void stop_logger(void) {
    if (!InterlockedExchange(&g_active, 0)) return;
    RemoveVectoredExceptionHandler(exc_handler);
    if (g_log) { CloseHandle(g_log); g_log = NULL; }
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)instance; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(instance);
        start_logger();
        /* registration must happen OUTSIDE loader context: queue a self-APC; at
         * process start it runs on the main thread before target code. */
        QueueUserAPC(attach_apc, GetCurrentThread(), 0);
    } else if (reason == DLL_PROCESS_DETACH) {
        stop_logger();
    }
    return TRUE;
}

__declspec(dllexport) unsigned long __stdcall exc_count(void) { return (unsigned long)g_count; }

__declspec(dllexport) void __stdcall exc_test(void) {
    /* deliberate access violation: if the VEH is registered in THIS process, it logs */
    *(volatile int *)1 = 42;
}

__declspec(dllexport) void __stdcall exc_stop(void) { stop_logger(); }

__declspec(dllexport) const char *__stdcall exc_version(void) { return "ghidra-mcp-exclog-1"; }

__declspec(dllexport) const char *__stdcall exc_log_path(void) { return g_log_path; }
