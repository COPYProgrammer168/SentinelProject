/*
 * Sentinel Status — Windhawk mod
 *
 * Reflects Sentinel's current severity in the Windows taskbar.
 *
 * Status file: C:\ProgramData\Sentinel\status.txt
 * Expected values: NORMAL | WARNING | CRITICAL
 *
 * NORMAL  -> default taskbar color (no tint)
 * WARNING -> subtle amber tint
 * CRITICAL -> subtle red tint with slow pulse (~1.5s)
 *
 * Safety:
 * - Missing/empty/invalid status file -> NORMAL
 * - Mod never crashes Explorer; falls back to original color on error
 * - Polls file every 1-2 seconds; only redraws when color actually changes
 *
 * Build:
 *   Requires Visual Studio Build Tools / MSVC with Windows SDK.
 *   cl /EHsc /DUNICODE /D_UNICODE sentinel-status.cpp /link user32.lib gdi32.lib dwmapi.lib
 */

#include <Windows.h>
#include <dwmapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "dwmapi.lib")

/* ===== Windhawk mod metadata header ===== */
WH_MOD_METADATA_BEGIN()
WH_MOD_METADATA_NAME("Sentinel Status Reactive Taskbar")
WH_MOD_METADATA_DESCRIPTION("Tints the Windows taskbar based on Sentinel's current severity status read from C:\\ProgramData\\Sentinel\\status.txt.")
WH_MOD_METADATA_AUTHOR("Sentinel")
WH_MOD_METADATA_VERSION("1.0")
WH_MOD_METADATA_MIN_REQUIRED_WINDHAWK_BUILD(3360)
WH_MOD_METADATA_TAGS("taskbar", "sentinel", "security", "status")
WH_MOD_METADATA_IS_BETA(false)
WH_MOD_METADATA_URL("https://github.com/SentinelProject/sentinel")
WH_MOD_METADATA_END()

/* ===== Constants ===== */
#define STATUS_FILE_PATH "C:\\ProgramData\\Sentinel\\status.txt"
#define POLL_INTERVAL_MS 1500
#define PULSE_INTERVAL_MS 750

/* NORMAL = no tint; use default colorization color */
static const DWORD COLOR_NORMAL_ARGB = 0x00000000;

/* WARNING = subtle amber tint applied on top of current color */
static const DWORD COLOR_WARNING_TINT = 0x1AFFAA00; /* alpha=0x1A, amber */

/* CRITICAL = subtle red tint; actual color set dynamically for pulse */
static DWORD COLOR_CRITICAL_TINT = 0x1AFF0000;

/* ===== State ===== */
static HANDLE g_pollTimer = NULL;
static HANDLE g_pulseTimer = NULL;
static HWND g_taskbarWnd = NULL;
static DWORD g_currentStatusHash = 0;
static int g_pulseState = 0;

/* ===== Original function pointer ===== */
static HRESULT(WINAPI * Real_DwmGetColorizationColor)(DWORD *, BOOL *) = DwmGetColorizationColor;

/* ===== Helpers ===== */

static DWORD Fnv1aHash(const char *str) {
    DWORD hash = 2166136261u;
    while (*str) {
        hash ^= (unsigned char)*str++;
        hash *= 16777619u;
    }
    return hash;
}

static BOOL ReadStatusFile(char *buffer, DWORD bufferSize) {
    HANDLE hFile = CreateFileA(STATUS_FILE_PATH, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    DWORD read = 0;
    BOOL result = ReadFile(hFile, buffer, bufferSize - 1, &read, NULL);
    CloseHandle(hFile);
    if (!result || read == 0) {
        return FALSE;
    }
    buffer[read] = '\0';
    /* Trim whitespace/newlines */
    char *end = buffer + read - 1;
    while (end >= buffer && (*end == '\n' || *end == '\r' || *end == ' ' || *end == '\t')) {
        *end-- = '\0';
    }
    return TRUE;
}

static BOOL IsCriticalPulseActive() {
    return (GetTickCount64() / PULSE_INTERVAL_MS) % 2 == 0;
}

static DWORD ApplyTint(DWORD baseColor, DWORD tint) {
    /* Simple alpha blend: result = base * (1 - alpha/255) + tint * alpha/255 */
    DWORD baseA = (baseColor >> 24) & 0xFF;
    DWORD baseR = (baseColor >> 16) & 0xFF;
    DWORD baseG = (baseColor >> 8) & 0xFF;
    DWORD baseB = baseColor & 0xFF;

    DWORD tintA = (tint >> 24) & 0xFF;
    DWORD tintR = (tint >> 16) & 0xFF;
    DWORD tintG = (tint >> 8) & 0xFF;
    DWORD tintB = tint & 0xFF;

    float factor = (float)tintA / 255.0f;
    BYTE r = (BYTE)(baseR * (1.0f - factor) + tintR * factor);
    BYTE g = (BYTE)(baseG * (1.0f - factor) + tintG * factor);
    BYTE b = (BYTE)(baseB * (1.0f - factor) + tintB * factor);

    return (baseA << 24) | (r << 16) | (g << 8) | b;
}

/* ===== Hook: DwmGetColorizationColor ===== */

static HRESULT WINAPI Hook_DwmGetColorizationColor(DWORD *color, BOOL *alphaBlend) {
    char status[64] = {0};
    if (!ReadStatusFile(status, sizeof(status))) {
        return Real_DwmGetColorizationColor(color, alphaBlend);
    }

    DWORD hash = Fnv1aHash(status);
    if (hash != g_currentStatusHash) {
        g_currentStatusHash = hash;
        /* Status changed; force a taskbar repaint */
        if (g_taskbarWnd && IsWindow(g_taskbarWnd)) {
            InvalidateRect(g_taskbarWnd, NULL, TRUE);
            UpdateWindow(g_taskbarWnd);
        }
    }

    if (strcmp(status, "CRITICAL") == 0) {
        if (IsCriticalPulseActive()) {
            COLOR_CRITICAL_TINT = 0x1AFF0000; /* red pulse high */
        } else {
            COLOR_CRITICAL_TINT = 0x0DFF0000; /* red pulse low */
        }
        HRESULT hr = Real_DwmGetColorizationColor(color, alphaBlend);
        if (SUCCEEDED(hr) && color) {
            *color = ApplyTint(*color, COLOR_CRITICAL_TINT);
        }
        return hr;
    }

    if (strcmp(status, "WARNING") == 0) {
        HRESULT hr = Real_DwmGetColorizationColor(color, alphaBlend);
        if (SUCCEEDED(hr) && color) {
            *color = ApplyTint(*color, COLOR_WARNING_TINT);
        }
        return hr;
    }

    /* NORMAL or unknown -> default */
    return Real_DwmGetColorizationColor(color, alphaBlend);
}

/* ===== Window enumeration helper ===== */

static BOOL CALLBACK EnumTaskbarProc(HWND hwnd, LPARAM lparam) {
    char className[64] = {0};
    GetClassNameA(hwnd, className, sizeof(className));
    if (strcmp(className, "Shell_TrayWnd") == 0) {
        *((HWND *)lparam) = hwnd;
        return FALSE; /* stop enumeration */
    }
    return TRUE;
}

static HWND FindTaskbarWnd() {
    HWND taskbar = NULL;
    EnumWindows(EnumTaskbarProc, (LPARAM)&taskbar);
    return taskbar;
}

/* ===== Timer callbacks ===== */

static VOID CALLBACK PollTimerProc(HWND hwnd, UINT msg, UINT_PTR id, DWORD time) {
    UNREFERENCED_PARAMETER(hwnd);
    UNREFERENCED_PARAMETER(msg);
    UNREFERENCED_PARAMETER(id);
    UNREFERENCED_PARAMETER(time);

    char status[64] = {0};
    if (!ReadStatusFile(status, sizeof(status))) {
        return;
    }

    DWORD hash = Fnv1aHash(status);
    if (hash != g_currentStatusHash) {
        g_currentStatusHash = hash;
        g_taskbarWnd = FindTaskbarWnd();
        if (g_taskbarWnd && IsWindow(g_taskbarWnd)) {
            InvalidateRect(g_taskbarWnd, NULL, TRUE);
            UpdateWindow(g_taskbarWnd);
        }
    }
}

static VOID CALLBACK PulseTimerProc(HWND hwnd, UINT msg, UINT_PTR id, DWORD time) {
    UNREFERENCED_PARAMETER(hwnd);
    UNREFERENCED_PARAMETER(msg);
    UNREFERENCED_PARAMETER(id);
    UNREFERENCED_PARAMETER(time);

    char status[64] = {0};
    if (!ReadStatusFile(status, sizeof(status))) {
        return;
    }

    if (strcmp(status, "CRITICAL") == 0) {
        g_pulseState = !g_pulseState;
        g_taskbarWnd = FindTaskbarWnd();
        if (g_taskbarWnd && IsWindow(g_taskbarWnd)) {
            InvalidateRect(g_taskbarWnd, NULL, TRUE);
            UpdateWindow(g_taskbarWnd);
        }
    }
}

/* ===== Windhawk lifecycle ===== */

BOOL WhModInit(PWH_MOD_MODULE_CONTEXT moduleContext) {
    UNREFERENCED_PARAMETER(moduleContext);

    /* Ensure status directory exists */
    CreateDirectoryA("C:\\ProgramData", NULL);
    CreateDirectoryA("C:\\ProgramData\\Sentinel", NULL);

    /* Create status file if missing so the mod has something to read */
    HANDLE hFile = CreateFileA(STATUS_FILE_PATH, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        WriteFile(hFile, "NORMAL\n", 6, &written, NULL);
        CloseHandle(hFile);
    }

    g_taskbarWnd = FindTaskbarWnd();

    /* Hook DwmGetColorizationColor */
    if (!Wh_SetFunctionHook((void *)DwmGetColorizationColor, (void *)Hook_DwmGetColorizationColor, (void **)&Real_DwmGetColorizationColor)) {
        return FALSE;
    }

    /* Start polling timer */
    g_pollTimer = SetTimer(NULL, 0, POLL_INTERVAL_MS, PollTimerProc);
    if (!g_pollTimer) {
        Wh_UnsetFunctionHook((void *)DwmGetColorizationColor);
        return FALSE;
    }

    /* Start pulse timer for CRITICAL state */
    g_pulseTimer = SetTimer(NULL, 0, PULSE_INTERVAL_MS, PulseTimerProc);
    if (!g_pulseTimer) {
        KillTimer(NULL, g_pollTimer);
        Wh_UnsetFunctionHook((void *)DwmGetColorizationColor);
        return FALSE;
    }

    return TRUE;
}

void WhModUninit(PWH_MOD_MODULE_CONTEXT moduleContext) {
    UNREFERENCED_PARAMETER(moduleContext);

    if (g_pollTimer) {
        KillTimer(NULL, g_pollTimer);
        g_pollTimer = NULL;
    }
    if (g_pulseTimer) {
        KillTimer(NULL, g_pulseTimer);
        g_pulseTimer = NULL;
    }

    Wh_UnsetFunctionHook((void *)DwmGetColorizationColor);
    Real_DwmGetColorizationColor = DwmGetColorizationColor;

    g_taskbarWnd = NULL;
    g_currentStatusHash = 0;
}
