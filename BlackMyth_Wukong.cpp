#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <commctrl.h>
#include <vector>
#include <string>
#include <cstring>
#include <algorithm>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#define ID_BTN_ATTACH      1001
#define ID_CHK_GOD         1002
#define ID_CHK_HP          1003
#define ID_CHK_MP          1004
#define ID_CHK_STAMINA     1005
#define ID_CHK_SKILLCD     1006
#define ID_CHK_FABAO       1007
#define ID_CHK_VIGOR       1008
#define ID_CHK_SOUL        1009
#define ID_CHK_SKILLPTS    1010
#define ID_CHK_EXP         1011
#define ID_CHK_DROP        1012
#define ID_CHK_RELICS      1013
#define ID_EDIT_SPEED      1014
#define ID_BTN_SPEED       1015
#define ID_EDIT_PSPEED     1016
#define ID_BTN_PSPEED      1017
#define ID_EDIT_JUMP       1018
#define ID_BTN_JUMP        1019
#define ID_STATUS          1020
#define ID_TIMER           2001

HWND g_hwnd = NULL;
HWND g_hStatus = NULL;
HANDLE g_hProcess = NULL;
DWORD g_dwPID = 0;
uintptr_t g_modBase = 0;
size_t g_modSize = 0;

bool g_god = false, g_hp = false, g_mp = false, g_stamina = false;
bool g_skillcd = false, g_fabao = false, g_vigor = false;
bool g_soul = false, g_skillpts = false, g_exp = false, g_drop = false, g_relics = false;

uintptr_t addr_god = 0, addr_hp = 0, addr_skillcd = 0, addr_soul = 0;
uintptr_t addr_skillpts = 0, addr_relics = 0, addr_drop = 0;
uintptr_t addr_playerspeed = 0, addr_speed = 0, addr_jump = 0;
uintptr_t addr_attr = 0, addr_playerpawn = 0;

BYTE pat_god[] = {0x48,0x8B,0xCB,0x33,0xD2,0xE8,0x00,0x00,0x00,0x00,0x85,0xC0,0x0F,0x85};
char  msk_god[] = "xxxxxx????xxxx";
BYTE pat_god2[] = {0x8B,0x00,0x10,0x49,0x8B,0xCC,0x33,0xD2,0xE8,0x00,0x00,0x00,0x00,0x85,0xC0,0x0F,0x85};
char  msk_god2[] = "x?xxxxxxx????xxxx";
BYTE pat_skillcd[] = {0x48,0x8B,0x86,0x00,0x00,0x00,0x00,0x00,0x8B,0x00,0x00};
char  msk_skillcd[] = "xxx????x??x";
BYTE pat_soul[] = {0x48,0x8B,0x40,0x20,0x4C,0x63,0xC0,0x00,0x8B,0x00,0xE8};
char  msk_soul[] = "xxxxxxx?x?x";
BYTE pat_skillpts[] = {0x48,0x63,0x46,0x48,0x89,0x47,0x48,0x48,0x63,0x46,0x4C};
char  msk_skillpts[] = "xxxxxxxxxxx";
BYTE pat_relics[] = {0x4C,0x63,0x41,0x24,0x48,0x8B,0xC8};
char  msk_relics[] = "xxxxxxx";
BYTE pat_drop[] = {0x55,0x48,0x8B,0xEC,0x48,0x83,0xEC};
char  msk_drop[] = "xxxxxxx";
BYTE pat_pspeed[] = {0xF3,0x0F,0x10,0x8B,0x00,0x00,0x00,0x00,0xEB};
char  msk_pspeed[] = "xxxx????x";
BYTE pat_speed[] = {0x0F,0x28,0x00,0xFF,0x90,0x00,0x00,0x00,0x00,0x0F,0x10};
char  msk_speed[] = "xx?xx????xx";
BYTE pat_jump[] = {0x0F,0x5A,0xC0,0x41,0x8D,0x50,0x03,0xF2,0x0F,0x5F,0x83};
char  msk_jump[] = "xxxxxxxxxxx";
BYTE pat_attr[] = {0xF3,0x0F,0x11,0x45,0xF4,0x48,0x8B,0x87};
char  msk_attr[] = "xxxxxxxx";
BYTE pat_pawn[] = {0x41,0x8B,0x87,0x00,0x00,0x00,0x00,0xC1,0xE8,0x04,0xA8,0x01,0x0F,0x84};
char  msk_pawn[] = "xxx????xxxxxxx";
BYTE pat_hpval[] = {0xFF,0x50,0x00,0xF3,0x0F,0x11,0x45};
char  msk_hpval[] = "xx?xxxx";

bool MatchPattern(const BYTE* data, const BYTE* pat, const char* mask, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (mask[i] == 'x' && data[i] != pat[i]) return false;
    }
    return true;
}

uintptr_t PatternScan(HANDLE hProc, uintptr_t start, size_t size, const BYTE* pat, const char* mask) {
    size_t plen = strlen(mask);
    const size_t CHUNK = 0x10000;
    std::vector<BYTE> buf(CHUNK + plen);
    for (size_t offset = 0; offset < size; offset += CHUNK) {
        size_t toRead = (std::min)(CHUNK + plen, size - offset);
        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(hProc, (LPCVOID)(start + offset), buf.data(), toRead, &bytesRead) || bytesRead < plen)
            continue;
        for (size_t i = 0; i + plen <= bytesRead; i++) {
            if (MatchPattern(buf.data() + i, pat, mask, plen))
                return start + offset + i;
        }
    }
    return 0;
}

DWORD FindProcess(const wchar_t* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe = {sizeof(pe)};
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

uintptr_t GetModuleBase(DWORD pid, const wchar_t* modName, size_t* outSize) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    MODULEENTRY32W me = {sizeof(me)};
    uintptr_t base = 0;
    if (Module32FirstW(snap, &me)) {
        do {
            if (_wcsicmp(me.szModule, modName) == 0) {
                base = (uintptr_t)me.modBaseAddr;
                if (outSize) *outSize = me.modBaseSize;
                break;
            }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return base;
}

bool WriteBytes(uintptr_t addr, const BYTE* data, size_t len) {
    if (!g_hProcess || !addr) return false;
    DWORD old;
    VirtualProtectEx(g_hProcess, (LPVOID)addr, len, PAGE_EXECUTE_READWRITE, &old);
    SIZE_T written = 0;
    BOOL ok = WriteProcessMemory(g_hProcess, (LPVOID)addr, data, len, &written);
    VirtualProtectEx(g_hProcess, (LPVOID)addr, len, old, &old);
    return ok && written == len;
}

bool NopBytes(uintptr_t addr, size_t len) {
    std::vector<BYTE> nops(len, 0x90);
    return WriteBytes(addr, nops.data(), len);
}

bool WriteMem(uintptr_t addr, const void* buf, size_t len) {
    return WriteBytes(addr, (const BYTE*)buf, len);
}

bool ReadMem(uintptr_t addr, void* buf, size_t len) {
    SIZE_T r = 0;
    return ReadProcessMemory(g_hProcess, (LPCVOID)addr, buf, len, &r) && r == len;
}

void SetStatus(const wchar_t* msg) {
    if (g_hStatus) SetWindowTextW(g_hStatus, msg);
}

void ApplyGod(bool on) {
    if (!addr_god) return;
    if (on) {
        BYTE patch[] = {0x90,0x90,0x90,0x90,0x90,0x90};
        WriteBytes(addr_god + 0x0C, patch, 6);
    } else {
        BYTE orig[] = {0x0F,0x85};
        WriteBytes(addr_god + 0x0C, orig, 2);
    }
}

void ApplyHP(bool on) {
    if (!addr_hp) return;
    if (on) {
        BYTE patch[] = {0x90,0x90,0x90,0x90,0x90,0x90};
        WriteBytes(addr_hp + 0x0A, patch, 6);
    }
}

void ApplySkillCD(bool on) {
    if (!addr_skillcd) return;
    if (on) {
        BYTE patch[] = {0x31,0xC0,0x90,0x90};
        WriteBytes(addr_skillcd + 0x07, patch, 4);
    }
}

void ApplySoul(bool on) {
    if (!addr_soul) return;
    if (on) {
        int val = 999999;
        WriteMem(addr_soul + 0x08, &val, 4);
    }
}

void ApplySkillPts(bool on) {
    if (!addr_skillpts) return;
    if (on) {
        int val = 999;
        WriteMem(addr_skillpts + 0x03, &val, 4);
    }
}

void ApplyRelics(bool on) {
    if (!addr_relics) return;
    if (on) {
        int val = 99;
        WriteMem(addr_relics + 0x04, &val, 4);
    }
}

void ApplyDrop(bool on) {
    if (!addr_drop) return;
    if (on) {
        BYTE patch[] = {0xB8,0x01,0x00,0x00,0x00,0xC3};
        WriteBytes(addr_drop, patch, 6);
    }
}

void ApplySpeed(float mult) {
    if (!addr_speed) return;
    WriteMem(addr_speed + 0x05, &mult, 4);
}

void ApplyPlayerSpeed(float mult) {
    if (!addr_playerspeed) return;
    WriteMem(addr_playerspeed + 0x04, &mult, 4);
}

void ApplyJump(float mult) {
    if (!addr_jump) return;
    WriteMem(addr_jump + 0x0B, &mult, 4);
}

bool Attach() {
    if (g_hProcess) {
        CloseHandle(g_hProcess);
        g_hProcess = NULL;
    }
    g_dwPID = FindProcess(L"b1-Win64-Shipping.exe");
    if (!g_dwPID) {
        SetStatus(L"Process not found");
        return false;
    }
    g_hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, g_dwPID);
    if (!g_hProcess) {
        SetStatus(L"OpenProcess failed");
        return false;
    }
    g_modBase = GetModuleBase(g_dwPID, L"b1-Win64-Shipping.exe", &g_modSize);
    if (!g_modBase || !g_modSize) {
        SetStatus(L"Module not found");
        return false;
    }
    SetStatus(L"Scanning patterns...");
    addr_god = PatternScan(g_hProcess, g_modBase, g_modSize, pat_god, msk_god);
    if (!addr_god)
        addr_god = PatternScan(g_hProcess, g_modBase, g_modSize, pat_god2, msk_god2);
    addr_hp = PatternScan(g_hProcess, g_modBase, g_modSize, pat_hpval, msk_hpval);
    addr_skillcd = PatternScan(g_hProcess, g_modBase, g_modSize, pat_skillcd, msk_skillcd);
    addr_soul = PatternScan(g_hProcess, g_modBase, g_modSize, pat_soul, msk_soul);
    addr_skillpts = PatternScan(g_hProcess, g_modBase, g_modSize, pat_skillpts, msk_skillpts);
    addr_relics = PatternScan(g_hProcess, g_modBase, g_modSize, pat_relics, msk_relics);
    addr_drop = PatternScan(g_hProcess, g_modBase, g_modSize, pat_drop, msk_drop);
    addr_playerspeed = PatternScan(g_hProcess, g_modBase, g_modSize, pat_pspeed, msk_pspeed);
    addr_speed = PatternScan(g_hProcess, g_modBase, g_modSize, pat_speed, msk_speed);
    addr_jump = PatternScan(g_hProcess, g_modBase, g_modSize, pat_jump, msk_jump);
    addr_attr = PatternScan(g_hProcess, g_modBase, g_modSize, pat_attr, msk_attr);
    addr_playerpawn = PatternScan(g_hProcess, g_modBase, g_modSize, pat_pawn, msk_pawn);

    int found = 0;
    if (addr_god) found++;
    if (addr_hp) found++;
    if (addr_skillcd) found++;
    if (addr_soul) found++;
    if (addr_skillpts) found++;
    if (addr_relics) found++;
    if (addr_drop) found++;
    if (addr_playerspeed) found++;
    if (addr_speed) found++;
    if (addr_jump) found++;
    if (addr_attr) found++;
    if (addr_playerpawn) found++;

    wchar_t msg[128];
    swprintf_s(msg, L"Attached PID %lu | Patterns: %d/12", g_dwPID, found);
    SetStatus(msg);
    return true;
}

void OnTimer() {
    if (!g_hProcess) return;
    DWORD code = 0;
    if (!GetExitCodeProcess(g_hProcess, &code) || code != STILL_ACTIVE) {
        CloseHandle(g_hProcess);
        g_hProcess = NULL;
        SetStatus(L"Process closed");
        return;
    }
    if (g_god) ApplyGod(true);
    if (g_hp) ApplyHP(true);
    if (g_skillcd) ApplySkillCD(true);
    if (g_soul) ApplySoul(true);
    if (g_skillpts) ApplySkillPts(true);
    if (g_relics) ApplyRelics(true);
    if (g_drop) ApplyDrop(true);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        HFONT hFont = CreateFontW(15, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
        int y = 10;
        CreateWindowW(L"BUTTON", L"Attach to b1-Win64-Shipping.exe", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            10, y, 300, 28, hwnd, (HMENU)ID_BTN_ATTACH, NULL, NULL);
        y += 34;
        CreateWindowW(L"BUTTON", L"God Mode", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            10, y, 145, 22, hwnd, (HMENU)ID_CHK_GOD, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Infinite HP", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            165, y, 145, 22, hwnd, (HMENU)ID_CHK_HP, NULL, NULL);
        y += 24;
        CreateWindowW(L"BUTTON", L"Infinite MP", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            10, y, 145, 22, hwnd, (HMENU)ID_CHK_MP, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Infinite Stamina", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            165, y, 145, 22, hwnd, (HMENU)ID_CHK_STAMINA, NULL, NULL);
        y += 24;
        CreateWindowW(L"BUTTON", L"No Skill CD", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            10, y, 145, 22, hwnd, (HMENU)ID_CHK_SKILLCD, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Infinite Fabao Energy", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            165, y, 145, 22, hwnd, (HMENU)ID_CHK_FABAO, NULL, NULL);
        y += 24;
        CreateWindowW(L"BUTTON", L"Infinite Vigor", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            10, y, 145, 22, hwnd, (HMENU)ID_CHK_VIGOR, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Max Souls", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            165, y, 145, 22, hwnd, (HMENU)ID_CHK_SOUL, NULL, NULL);
        y += 24;
        CreateWindowW(L"BUTTON", L"Max Skill Points", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            10, y, 145, 22, hwnd, (HMENU)ID_CHK_SKILLPTS, NULL, NULL);
        CreateWindowW(L"BUTTON", L"EXP Multiplier", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            165, y, 145, 22, hwnd, (HMENU)ID_CHK_EXP, NULL, NULL);
        y += 24;
        CreateWindowW(L"BUTTON", L"100% Drop Rate", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            10, y, 145, 22, hwnd, (HMENU)ID_CHK_DROP, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Max Relics", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            165, y, 145, 22, hwnd, (HMENU)ID_CHK_RELICS, NULL, NULL);
        y += 30;
        CreateWindowW(L"STATIC", L"Game Speed:", WS_CHILD | WS_VISIBLE, 10, y + 2, 80, 20, hwnd, NULL, NULL, NULL);
        CreateWindowW(L"EDIT", L"1.0", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
            95, y, 55, 22, hwnd, (HMENU)ID_EDIT_SPEED, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Set", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            155, y, 45, 22, hwnd, (HMENU)ID_BTN_SPEED, NULL, NULL);
        y += 28;
        CreateWindowW(L"STATIC", L"Player Speed:", WS_CHILD | WS_VISIBLE, 10, y + 2, 80, 20, hwnd, NULL, NULL, NULL);
        CreateWindowW(L"EDIT", L"1.0", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
            95, y, 55, 22, hwnd, (HMENU)ID_EDIT_PSPEED, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Set", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            155, y, 45, 22, hwnd, (HMENU)ID_BTN_PSPEED, NULL, NULL);
        y += 28;
        CreateWindowW(L"STATIC", L"Jump Height:", WS_CHILD | WS_VISIBLE, 10, y + 2, 80, 20, hwnd, NULL, NULL, NULL);
        CreateWindowW(L"EDIT", L"1.0", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
            95, y, 55, 22, hwnd, (HMENU)ID_EDIT_JUMP, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Set", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            155, y, 45, 22, hwnd, (HMENU)ID_BTN_JUMP, NULL, NULL);
        y += 32;
        g_hStatus = CreateWindowW(L"STATIC", L"Ready - Attach to game", WS_CHILD | WS_VISIBLE | SS_LEFT,
            10, y, 300, 22, hwnd, (HMENU)ID_STATUS, NULL, NULL);
        EnumChildWindows(hwnd, [](HWND h, LPARAM f) -> BOOL {
            SendMessageW(h, WM_SETFONT, (WPARAM)f, TRUE);
            return TRUE;
        }, (LPARAM)hFont);
        SetTimer(hwnd, ID_TIMER, 200, NULL);
        break;
    }
    case WM_COMMAND: {
        int id = LOWORD(wParam);
        if (id == ID_BTN_ATTACH) {
            Attach();
        } else if (id == ID_CHK_GOD) {
            g_god = (IsDlgButtonChecked(hwnd, ID_CHK_GOD) == BST_CHECKED);
            ApplyGod(g_god);
        } else if (id == ID_CHK_HP) {
            g_hp = (IsDlgButtonChecked(hwnd, ID_CHK_HP) == BST_CHECKED);
            ApplyHP(g_hp);
        } else if (id == ID_CHK_MP) {
            g_mp = (IsDlgButtonChecked(hwnd, ID_CHK_MP) == BST_CHECKED);
        } else if (id == ID_CHK_STAMINA) {
            g_stamina = (IsDlgButtonChecked(hwnd, ID_CHK_STAMINA) == BST_CHECKED);
        } else if (id == ID_CHK_SKILLCD) {
            g_skillcd = (IsDlgButtonChecked(hwnd, ID_CHK_SKILLCD) == BST_CHECKED);
            ApplySkillCD(g_skillcd);
        } else if (id == ID_CHK_FABAO) {
            g_fabao = (IsDlgButtonChecked(hwnd, ID_CHK_FABAO) == BST_CHECKED);
        } else if (id == ID_CHK_VIGOR) {
            g_vigor = (IsDlgButtonChecked(hwnd, ID_CHK_VIGOR) == BST_CHECKED);
        } else if (id == ID_CHK_SOUL) {
            g_soul = (IsDlgButtonChecked(hwnd, ID_CHK_SOUL) == BST_CHECKED);
            ApplySoul(g_soul);
        } else if (id == ID_CHK_SKILLPTS) {
            g_skillpts = (IsDlgButtonChecked(hwnd, ID_CHK_SKILLPTS) == BST_CHECKED);
            ApplySkillPts(g_skillpts);
        } else if (id == ID_CHK_EXP) {
            g_exp = (IsDlgButtonChecked(hwnd, ID_CHK_EXP) == BST_CHECKED);
        } else if (id == ID_CHK_DROP) {
            g_drop = (IsDlgButtonChecked(hwnd, ID_CHK_DROP) == BST_CHECKED);
            ApplyDrop(g_drop);
        } else if (id == ID_CHK_RELICS) {
            g_relics = (IsDlgButtonChecked(hwnd, ID_CHK_RELICS) == BST_CHECKED);
            ApplyRelics(g_relics);
        } else if (id == ID_BTN_SPEED) {
            wchar_t buf[32];
            GetDlgItemTextW(hwnd, ID_EDIT_SPEED, buf, 32);
            float v = (float)_wtof(buf);
            if (v < 0.1f) v = 0.1f;
            if (v > 20.0f) v = 20.0f;
            ApplySpeed(v);
            SetStatus(L"Game speed set");
        } else if (id == ID_BTN_PSPEED) {
            wchar_t buf[32];
            GetDlgItemTextW(hwnd, ID_EDIT_PSPEED, buf, 32);
            float v = (float)_wtof(buf);
            if (v < 0.1f) v = 0.1f;
            if (v > 20.0f) v = 20.0f;
            ApplyPlayerSpeed(v);
            SetStatus(L"Player speed set");
        } else if (id == ID_BTN_JUMP) {
            wchar_t buf[32];
            GetDlgItemTextW(hwnd, ID_EDIT_JUMP, buf, 32);
            float v = (float)_wtof(buf);
            if (v < 0.1f) v = 0.1f;
            if (v > 20.0f) v = 20.0f;
            ApplyJump(v);
            SetStatus(L"Jump height set");
        }
        break;
    }
    case WM_TIMER:
        if (wParam == ID_TIMER) OnTimer();
        break;
    case WM_DESTROY:
        KillTimer(hwnd, ID_TIMER);
        if (g_hProcess) CloseHandle(g_hProcess);
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE, LPSTR, int nShow) {
    INITCOMMONCONTROLSEX icc = {sizeof(icc), ICC_STANDARD_CLASSES};
    InitCommonControlsEx(&icc);
    WNDCLASSEXW wc = {sizeof(wc)};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"BlackMythWukongTrainer";
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    RegisterClassExW(&wc);
    g_hwnd = CreateWindowExW(0, L"BlackMythWukongTrainer", L"Black Myth Wukong Trainer v1.0-v1.0.20",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 340, 420, NULL, NULL, hInst, NULL);
    ShowWindow(g_hwnd, nShow);
    UpdateWindow(g_hwnd);
    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}
