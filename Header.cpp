#include "Headers.hpp"

VMM_HANDLE hVMM = nullptr;
std::string process_name;
std::string DLL_Name;
std::string output_path;
std::string device_type = "fpga";
uint32_t process_id = 0;
HANDLE process_handle = nullptr;
ULONG64 process_base_address = 0;
ULONG64 DLL_base_address = 0;
DWORD process_size = 0;
DWORD DLL_size = 0;

