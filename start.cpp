#include "Headers.hpp"

static void PrintUsage(const char* exe)
{
    printf("Usage:\n");
    printf("  %s <target.exe> [target.dll]                    - Dump EXE (and optional DLL)\n", exe);
    printf("  %s <target.exe> --scan \"48 8B 05 ? ? ? ?\"       - Pattern scan main module\n", exe);
    printf("  %s <target.exe> --scan-section .text \"pattern\"  - Pattern scan specific PE section\n", exe);
    printf("  %s <target.exe> --decrypt <hex_addr> \"ops\"      - Decrypt pointer at address\n", exe);
    printf("      ops format: xor:KEY;ror:BITS;sub:KEY;not;bswap\n");
    printf("  %s <target.exe> --chain <hex_base> off1 off2..  - Walk pointer chain\n", exe);
    printf("  %s <target.exe> --export <module.dll> <name>    - Find named export\n", exe);
    printf("  %s <target.exe> --bruteforce-key <hex_addr>     - Guess XOR key for pointer\n", exe);
}

static std::string GetArgStr(int argc, char** argv, int idx)
{
    if (idx < argc)
        return argv[idx];
    return "";
}

int Start(int argc, char** argv) {

    bool DLL = false;
    bool DLLInitialized = false;

    if (argc < 2)
    {
        PrintUsage(argv[0]);
        return -1;
    }

    printf("Target Executable: %s\n", argv[1]);

    // Check for command flags
    std::string mode;
    if (argc >= 3)
        mode = argv[2];

    // --- Pattern Scan Mode ---
    if (mode == "--scan")
    {
        if (argc < 4)
        {
            printf("[!] Usage: %s <target.exe> --scan \"48 8B 05 ? ? ? ?\"\n", argv[0]);
            return -1;
        }

        if (!Initialize(argv[1]))
        {
            printf("[!] Failed to initialize memory\n");
            return -1;
        }

        RunPatternScan(argv[3]);
        return 0;
    }

    // --- Section Scan Mode ---
    if (mode == "--scan-section")
    {
        if (argc < 5)
        {
            printf("[!] Usage: %s <target.exe> --scan-section .text \"pattern\"\n", argv[0]);
            return -1;
        }

        if (!Initialize(argv[1]))
        {
            printf("[!] Failed to initialize memory\n");
            return -1;
        }

        uint64_t result = PatternScanSection(argv[3], argv[4]);
        if (result)
            printf("[+] Match found at 0x%llX (offset: +0x%llX)\n", result, result - process_base_address);
        else
            printf("[!] No match found.\n");
        return 0;
    }

    // --- Decrypt Pointer Mode ---
    if (mode == "--decrypt")
    {
        if (argc < 5)
        {
            printf("[!] Usage: %s <target.exe> --decrypt <hex_addr> \"xor:KEY;ror:BITS\"\n", argv[0]);
            return -1;
        }

        if (!Initialize(argv[1]))
        {
            printf("[!] Failed to initialize memory\n");
            return -1;
        }

        uint64_t addr = strtoull(argv[3], nullptr, 16);
        RunPointerDecrypt(addr, argv[4]);
        return 0;
    }

    // --- Pointer Chain Walk Mode ---
    if (mode == "--chain")
    {
        if (argc < 5)
        {
            printf("[!] Usage: %s <target.exe> --chain <hex_base> off1 off2 ..\n", argv[0]);
            return -1;
        }

        if (!Initialize(argv[1]))
        {
            printf("[!] Failed to initialize memory\n");
            return -1;
        }

        uint64_t base = strtoull(argv[3], nullptr, 16);
        std::vector<int64_t> offsets;
        for (int i = 4; i < argc; i++)
            offsets.push_back(static_cast<int64_t>(strtoll(argv[i], nullptr, 16)));

        RunPointerChainWalk(base, offsets);
        return 0;
    }

    // --- Export Finder Mode ---
    if (mode == "--export")
    {
        if (argc < 5)
        {
            printf("[!] Usage: %s <target.exe> --export <module.dll> <export_name>\n", argv[0]);
            return -1;
        }

        if (!Initialize(argv[1]))
        {
            printf("[!] Failed to initialize memory\n");
            return -1;
        }

        if (!InitializeDLL(argv[1], argv[3]))
        {
            printf("[!] Failed to initialize DLL module\n");
            return -1;
        }

        uint64_t addr = FindExport(DLL_base_address, argv[4]);
        if (addr)
            printf("[+] Export %s found at 0x%llX\n", argv[4], addr);
        return 0;
    }

    // --- Bruteforce XOR Key Mode ---
    if (mode == "--bruteforce-key")
    {
        if (argc < 4)
        {
            printf("[!] Usage: %s <target.exe> --bruteforce-key <hex_addr>\n", argv[0]);
            return -1;
        }

        if (!Initialize(argv[1]))
        {
            printf("[!] Failed to initialize memory\n");
            return -1;
        }

        uint64_t addr = strtoull(argv[3], nullptr, 16);
        uint64_t key = BruteforceXORKey(addr, process_base_address, process_size);
        if (key)
            printf("[+] Discovered XOR key: 0x%llX\n", key);
        else
            printf("[!] Could not determine XOR key.\n");
        return 0;
    }

    // --- Default: Dump Mode ---
    if (argc >= 3 && mode[0] != '-')
    {
        printf("Target DLL: %s\n", argv[2]);
        DLL = true;
    }
    else if (argc < 3)
    {
        printf("No DLL provided.\n");
    }

    if (!Initialize(argv[1])) {
        printf("[!] Failed to initialize memory\n");
    }

    if (!DumpExe()) {
        printf("[!] Failed to dump exe\n");
    }

    if (DLL) {
        InitializeDLL(argv[1], argv[2]);
        DLLInitialized = true;
    }

    if (DLLInitialized) {
        printf("DLL initialized");
    }

    if (DLLInitialized && !DumpDLL()) {
        printf("[!] Failed to dump dll\n");
    }

    return 0;
}

