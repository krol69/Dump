#include "Headers.hpp"

static void print_usage(const char* exe_name) {
    printf("Usage: %s <process.exe> [dll.dll] [options]\n\n", exe_name);
    printf("Options:\n");
    printf("  -o <path>    Output directory for dumped files (default: exe directory)\n");
    printf("  -d <device>  DMA device type (default: fpga)\n");
    printf("\nExamples:\n");
    printf("  %s game.exe\n", exe_name);
    printf("  %s game.exe render.dll\n", exe_name);
    printf("  %s game.exe -o C:\\Dumps\\\n", exe_name);
    printf("  %s game.exe render.dll -o C:\\Dumps\\ -d fpga\n", exe_name);
}

int Start(int argc, char** argv) {

    bool DLL = false;

    if (argc < 2) {
        printf("[!] Incorrect usage.\n");
        print_usage(argv[0]);
        return -1;
    }

    process_name = argv[1];
    printf("Target Executable: %s\n", process_name.c_str());

    // Parse remaining arguments: positional DLL name and flags
    for (int i = 2; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-o" && i + 1 < argc) {
            output_path = argv[++i];
            if (!output_path.empty() && output_path.back() != '\\' && output_path.back() != '/') {
                output_path += '\\';
            }
        }
        else if (arg == "-d" && i + 1 < argc) {
            device_type = argv[++i];
        }
        else if (arg[0] != '-' && !DLL) {
            DLL_Name = arg;
            DLL = true;
        }
        else {
            printf("[!] Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return -1;
        }
    }

    if (DLL) {
        printf("Target DLL: %s\n", DLL_Name.c_str());
    }
    else {
        printf("No DLL provided.\n");
    }

    if (!output_path.empty()) {
        printf("Output path: %s\n", output_path.c_str());
        CreateDirectoryA(output_path.c_str(), NULL);
    }

    printf("Device type: %s\n", device_type.c_str());

    if (!Initialize(process_name)) {
        printf("[!] Failed to initialize memory\n");
        return -1;
    }

    if (!DumpExe()) {
        printf("[!] Failed to dump exe\n");
    }

    if (DLL) {
        if (!InitializeDLL(process_name, DLL_Name)) {
            printf("[!] Failed to initialize DLL\n");
        }
        else if (!DumpDLL()) {
            printf("[!] Failed to dump dll\n");
        }
    }

    return 0;
}
