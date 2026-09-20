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

#include <Windows.h>
#include <dwmapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ===== Constants ===== */
#define STATUS_FILE_PATH "C:\\ProgramData\\Sentinel\\status.txt"
#define STATUS_JSON_PATH "C:\\ProgramData\\Sentinel\\status.json"
#define DATA_BIN_PATH "C:\\ProgramData\\Sentinel\\sentinel_data.bin"
#define POLL_INTERVAL_MS 1500
#define PULSE_INTERVAL_MS 750
#define DATA_BIN_MAGIC "SENTINEL"
#define DATA_BIN_VERSION 1

/* NORMAL = no tint; use default colorization color */
static const DWORD COLOR_NORMAL_ARGB = 0x00000000;

/* WARNING = subtle amber tint applied on top of current color */
static const DWORD COLOR_WARNING_TINT = 0x1AFFAA00; /* alpha=0x1A, amber */

/* CRITICAL = subtle red tint; actual color set dynamically for pulse */
static DWORD COLOR_CRITICAL_TINT = 0x1AFF0000;

/* ===== State ===== */
static UINT_PTR g_pollTimer = 0;
static UINT_PTR g_pulseTimer = 0;
static HWND g_taskbarWnd = NULL;
static DWORD g_currentStatusHash = 0;
static int g_pulseState = 0;

/* ===== Data structures for full status payload ===== */
typedef struct _SENTINEL_STATUS_DATA {
    char status; /* 0=NORMAL, 1=WARNING, 2=CRITICAL */
    DWORD alerts_total;
    DWORD alerts_critical;
    DWORD flagged_network_events;
    char last_updated[20]; /* ISO timestamp string */
} SENTINEL_STATUS_DATA;

static SENTINEL_STATUS_DATA g_statusData = {0};

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

static BOOL ReadFileAll(const char *path, char *buffer, DWORD bufferSize) {
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
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

/* ===== JSON parsing helpers ===== */

static const char *JsonFindString(const char *json, const char *key, char *out, DWORD outSize) {
    char search[128];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *p = strstr(json, search);
    if (!p) return NULL;
    p += strlen(search);
    while (*p == ' ' || *p == ':' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p != '"') return NULL;
    p++;
    DWORD i = 0;
    while (*p && *p != '"' && i < outSize - 1) {
        if (*p == '\\' && *(p+1)) {
            p++;
        }
        out[i++] = *p++;
    }
    out[i] = '\0';
    return out;
}

static DWORD JsonFindUint(const char *json, const char *key) {
    char search[128];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *p = strstr(json, search);
    if (!p) return 0;
    p += strlen(search);
    while (*p == ' ' || *p == ':' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    return (DWORD)strtoul(p, NULL, 10);
}

static void ParseStatusJson(const char *json, SENTINEL_STATUS_DATA *data) {
    char status[32] = {0};
    if (JsonFindString(json, "status", status, sizeof(status))) {
        if (strcmp(status, "CRITICAL") == 0) {
            data->status = 2;
        } else if (strcmp(status, "WARNING") == 0) {
            data->status = 1;
        } else {
            data->status = 0;
        }
    }
    data->alerts_total = JsonFindUint(json, "alerts_total");
    data->alerts_critical = JsonFindUint(json, "alerts_critical");
    data->flagged_network_events = JsonFindUint(json, "flagged_network_events");
    char updated[64] = {0};
    if (JsonFindString(json, "updated", updated, sizeof(updated))) {
        strncpy(data->last_updated, updated, sizeof(data->last_updated) - 1);
        data->last_updated[sizeof(data->last_updated) - 1] = '\0';
    }
}

static void WriteDataBin(const SENTINEL_STATUS_DATA *data) {
    HANDLE hFile = CreateFileA(DATA_BIN_PATH, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return;
    }
    DWORD written = 0;
    char header[9] = DATA_BIN_MAGIC;
    BYTE version = DATA_BIN_VERSION;
    WriteFile(hFile, header, 8, &written, NULL);
    WriteFile(hFile, &version, 1, &written, NULL);
    WriteFile(hFile, &data->status, 1, &written, NULL);
    WriteFile(hFile, &data->alerts_total, 4, &written, NULL);
    WriteFile(hFile, &data->alerts_critical, 4, &written, NULL);
    WriteFile(hFile, &data->flagged_network_events, 4, &written, NULL);
    WriteFile(hFile, data->last_updated, 20, &written, NULL);
    CloseHandle(hFile);
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

    /* Update full status data from JSON */
    char json[4096] = {0};
    if (ReadFileAll(STATUS_JSON_PATH, json, sizeof(json))) {
        ParseStatusJson(json, &g_statusData);
        WriteDataBin(&g_statusData);
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
        Wh_RemoveFunctionHook((void *)DwmGetColorizationColor);
        return FALSE;
    }

    /* Start pulse timer for CRITICAL state */
    g_pulseTimer = SetTimer(NULL, 0, PULSE_INTERVAL_MS, PulseTimerProc);
    if (!g_pulseTimer) {
        KillTimer(NULL, g_pollTimer);
        Wh_RemoveFunctionHook((void *)DwmGetColorizationColor);
        return FALSE;
    }

    return TRUE;
}

void WhModUninit(PWH_MOD_MODULE_CONTEXT moduleContext) {
    UNREFERENCED_PARAMETER(moduleContext);

    if (g_pollTimer) {
        KillTimer(NULL, g_pollTimer);
        g_pollTimer = 0;
    }
    if (g_pulseTimer) {
        KillTimer(NULL, g_pulseTimer);
        g_pulseTimer = 0;
    }

    Wh_RemoveFunctionHook((void *)DwmGetColorizationColor);
    Real_DwmGetColorizationColor = DwmGetColorizationColor;

    g_taskbarWnd = NULL;
    g_currentStatusHash = 0;
}
