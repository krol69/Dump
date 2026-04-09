#pragma once
#define NOMINMAX
#include <Windows.h>
#include <string>
#include <string_view>
#include <memory>
#include <TlHelp32.h>
#include <fstream>
#include <mutex>
#include "vmmdll.h"
#include <iostream>
#include <vector>
#include <algorithm>



struct Info
{
    uint32_t index;
    uint32_t process_id;
    uint64_t dtb;
    uint64_t kernelAddr;
    char name[256];
};

extern VMM_HANDLE hVMM;
extern std::string process_name;
extern std::string DLL_Name;
extern uint32_t process_id;
extern HANDLE process_handle;
extern ULONG64 process_base_address;
extern ULONG64 DLL_base_address;
extern DWORD process_size;
extern DWORD DLL_size;

int Start(int argc, char** argv);

bool Initialize(const std::string process_name);

bool InitializeDLL(const std::string process_name, const std::string DLL_Name);

VOID cbAddFile(_Inout_ HANDLE h, _In_ LPCSTR uszName, _In_ ULONG64 cb, _In_opt_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo);

bool vmmdll_read(uint64_t address, void* buffer, size_t size);

template<class T> T read(uintptr_t address);

bool read_buffer(uintptr_t address, void* buffer, size_t size);

uint32_t get_process_id(const std::string process_name);

bool get_process_base_address(const std::string process_name, const uint32_t& process_id);

bool GetDLLModuleBase(const uint32_t& process_id, const std::string DLL_Name);

std::string get_path();

bool DumpExe();

bool DumpDLL();

// --- Scanner ---
int64_t PatternScanBuffer(const uint8_t* data, size_t data_size, const std::string& pattern);
std::vector<int64_t> PatternScanBufferAll(const uint8_t* data, size_t data_size, const std::string& pattern);
uint64_t PatternScanRemote(uint64_t base_address, size_t region_size, const std::string& pattern);
std::vector<uint64_t> PatternScanRemoteAll(uint64_t base_address, size_t region_size, const std::string& pattern);
uint64_t ResolveRIPRelative(uint64_t match_address, int instruction_offset, int instruction_size);
uint64_t PatternScanSection(const std::string& section_name, const std::string& pattern);
uint64_t FindExport(uint64_t module_base, const std::string& export_name);
void RunPatternScan(const std::string& pattern);

// --- Decryptor ---
uint64_t DecryptXOR(uint64_t encrypted_ptr, uint64_t key);
uint64_t DecryptROL(uint64_t value, int bits);
uint64_t DecryptROR(uint64_t value, int bits);
uint64_t DecryptSUB(uint64_t encrypted_ptr, uint64_t key);
uint64_t DecryptADD(uint64_t encrypted_ptr, uint64_t key);
uint64_t DecryptNOT(uint64_t encrypted_ptr);
uint64_t DecryptBSWAP(uint64_t value);
uint64_t DecryptChain(uint64_t encrypted_ptr, const std::string& operations);

// --- Pointer Chain ---
uint64_t ReadPointerChain(uint64_t base, const std::vector<int64_t>& offsets);
uint64_t ReadEncryptedPointer(uint64_t address, uint64_t xor_key);
uint64_t ReadEncryptedPointerChain(uint64_t address, const std::string& operations);
uint64_t ReadEncryptedPointerChainMulti(uint64_t base, const std::vector<int64_t>& offsets, const std::vector<uint64_t>& keys);
uint64_t BruteforceXORKey(uint64_t encrypted_ptr_addr, uint64_t expected_base, size_t expected_size);
void RunPointerDecrypt(uint64_t address, const std::string& operations);
void RunPointerChainWalk(uint64_t base, const std::vector<int64_t>& offsets);

