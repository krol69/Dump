#include "Headers.hpp"

// Parse an IDA-style pattern string like "48 8B 05 ? ? ? ? 48 85 C0"
// '?' or '??' are wildcards that match any byte
static bool ParsePattern(const std::string& pattern, std::vector<uint8_t>& bytes, std::vector<bool>& mask)
{
    bytes.clear();
    mask.clear();

    std::string token;
    for (size_t i = 0; i < pattern.size(); i++)
    {
        char c = pattern[i];
        if (c == ' ')
        {
            if (!token.empty())
            {
                if (token == "?" || token == "??")
                {
                    bytes.push_back(0x00);
                    mask.push_back(false);
                }
                else
                {
                    bytes.push_back(static_cast<uint8_t>(strtoul(token.c_str(), nullptr, 16)));
                    mask.push_back(true);
                }
                token.clear();
            }
        }
        else
        {
            token += c;
        }
    }

    if (!token.empty())
    {
        if (token == "?" || token == "??")
        {
            bytes.push_back(0x00);
            mask.push_back(false);
        }
        else
        {
            bytes.push_back(static_cast<uint8_t>(strtoul(token.c_str(), nullptr, 16)));
            mask.push_back(true);
        }
    }

    return !bytes.empty();
}

// Scan a memory buffer for a pattern, return offset from buffer start or -1
int64_t PatternScanBuffer(const uint8_t* data, size_t data_size, const std::string& pattern)
{
    std::vector<uint8_t> pat_bytes;
    std::vector<bool> pat_mask;

    if (!ParsePattern(pattern, pat_bytes, pat_mask))
    {
        printf("[!] Failed to parse pattern: %s\n", pattern.c_str());
        return -1;
    }

    size_t pat_len = pat_bytes.size();
    if (pat_len == 0 || pat_len > data_size)
        return -1;

    for (size_t i = 0; i <= data_size - pat_len; i++)
    {
        bool found = true;
        for (size_t j = 0; j < pat_len; j++)
        {
            if (pat_mask[j] && data[i + j] != pat_bytes[j])
            {
                found = false;
                break;
            }
        }
        if (found)
            return static_cast<int64_t>(i);
    }

    return -1;
}

// Scan a memory buffer for ALL occurrences of a pattern
std::vector<int64_t> PatternScanBufferAll(const uint8_t* data, size_t data_size, const std::string& pattern)
{
    std::vector<int64_t> results;
    std::vector<uint8_t> pat_bytes;
    std::vector<bool> pat_mask;

    if (!ParsePattern(pattern, pat_bytes, pat_mask))
    {
        printf("[!] Failed to parse pattern: %s\n", pattern.c_str());
        return results;
    }

    size_t pat_len = pat_bytes.size();
    if (pat_len == 0 || pat_len > data_size)
        return results;

    for (size_t i = 0; i <= data_size - pat_len; i++)
    {
        bool found = true;
        for (size_t j = 0; j < pat_len; j++)
        {
            if (pat_mask[j] && data[i + j] != pat_bytes[j])
            {
                found = false;
                break;
            }
        }
        if (found)
            results.push_back(static_cast<int64_t>(i));
    }

    return results;
}

// Scan live process memory for a pattern using DMA reads
// Returns the virtual address of the match, or 0 on failure
uint64_t PatternScanRemote(uint64_t base_address, size_t region_size, const std::string& pattern)
{
    auto buffer = std::make_unique<uint8_t[]>(region_size);
    memset(buffer.get(), 0, region_size);

    for (size_t offset = 0; offset < region_size; offset += 0x1000)
    {
        size_t chunk = ((offset + 0x1000) > region_size) ? (region_size - offset) : 0x1000;
        vmmdll_read(base_address + offset, buffer.get() + offset, chunk);
    }

    int64_t result = PatternScanBuffer(buffer.get(), region_size, pattern);
    if (result >= 0)
        return base_address + static_cast<uint64_t>(result);

    return 0;
}

// Scan live process memory for ALL occurrences of a pattern
std::vector<uint64_t> PatternScanRemoteAll(uint64_t base_address, size_t region_size, const std::string& pattern)
{
    std::vector<uint64_t> results;
    auto buffer = std::make_unique<uint8_t[]>(region_size);
    memset(buffer.get(), 0, region_size);

    for (size_t offset = 0; offset < region_size; offset += 0x1000)
    {
        size_t chunk = ((offset + 0x1000) > region_size) ? (region_size - offset) : 0x1000;
        vmmdll_read(base_address + offset, buffer.get() + offset, chunk);
    }

    auto offsets = PatternScanBufferAll(buffer.get(), region_size, pattern);
    for (auto off : offsets)
        results.push_back(base_address + static_cast<uint64_t>(off));

    return results;
}

// Resolve a RIP-relative address from a pattern match
// instruction_offset: offset within the pattern to the RIP-relative operand (e.g., 3 for "48 8B 05 xx xx xx xx")
// instruction_size: total size of the instruction containing the operand (e.g., 7)
uint64_t ResolveRIPRelative(uint64_t match_address, int instruction_offset, int instruction_size)
{
    int32_t rip_offset = 0;
    if (!vmmdll_read(match_address + instruction_offset, &rip_offset, sizeof(rip_offset)))
    {
        printf("[!] Failed to read RIP-relative offset at 0x%llX\n", match_address + instruction_offset);
        return 0;
    }
    return match_address + instruction_size + rip_offset;
}

// Scan a PE section by name within the process's main module
uint64_t PatternScanSection(const std::string& section_name, const std::string& pattern)
{
    if (!process_base_address || !process_size)
    {
        printf("[!] Process not initialized for section scan\n");
        return 0;
    }

    uint8_t header_buf[0x1000] = {};
    if (!vmmdll_read(process_base_address, header_buf, sizeof(header_buf)))
    {
        printf("[!] Failed to read PE header\n");
        return 0;
    }

    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(header_buf);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return 0;

    auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(header_buf + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return 0;

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, section++)
    {
        char name[9] = {};
        memcpy(name, section->Name, 8);
        if (section_name == name)
        {
            uint64_t sec_va = process_base_address + section->VirtualAddress;
            size_t sec_size = section->Misc.VirtualSize;
            printf("[+] Scanning section %s at 0x%llX (size: 0x%zX)\n", name, sec_va, sec_size);
            return PatternScanRemote(sec_va, sec_size, pattern);
        }
    }

    printf("[!] Section %s not found\n", section_name.c_str());
    return 0;
}

// Scan the module's export table and return the address of a named export
uint64_t FindExport(uint64_t module_base, const std::string& export_name)
{
    if (!module_base)
    {
        printf("[!] Invalid module base for export scan\n");
        return 0;
    }

    uint8_t header_buf[0x1000] = {};
    if (!vmmdll_read(module_base, header_buf, sizeof(header_buf)))
        return 0;

    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(header_buf);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return 0;

    auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(header_buf + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return 0;

    auto& export_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!export_dir.VirtualAddress || !export_dir.Size)
    {
        printf("[!] No export directory found\n");
        return 0;
    }

    auto export_buf = std::make_unique<uint8_t[]>(export_dir.Size);
    if (!vmmdll_read(module_base + export_dir.VirtualAddress, export_buf.get(), export_dir.Size))
        return 0;

    auto exports = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(export_buf.get());
    uint64_t delta = export_dir.VirtualAddress;

    auto functions = reinterpret_cast<uint32_t*>(export_buf.get() + (exports->AddressOfFunctions - delta));
    auto names = reinterpret_cast<uint32_t*>(export_buf.get() + (exports->AddressOfNames - delta));
    auto ordinals = reinterpret_cast<uint16_t*>(export_buf.get() + (exports->AddressOfNameOrdinals - delta));

    for (DWORD i = 0; i < exports->NumberOfNames; i++)
    {
        uint32_t name_rva = names[i];
        if (name_rva < delta || name_rva - delta >= export_dir.Size)
            continue;

        const char* func_name = reinterpret_cast<const char*>(export_buf.get() + (name_rva - delta));
        if (export_name == func_name)
        {
            uint16_t ordinal = ordinals[i];
            uint32_t func_rva = functions[ordinal];
            return module_base + func_rva;
        }
    }

    printf("[!] Export %s not found\n", export_name.c_str());
    return 0;
}

// Interactive scan mode - scan the main module for a pattern
void RunPatternScan(const std::string& pattern)
{
    if (!process_base_address || !process_size)
    {
        printf("[!] Process not initialized. Call Initialize() first.\n");
        return;
    }

    printf("[>] Scanning %s (base: 0x%llX, size: 0x%X) for pattern: %s\n",
        process_name.c_str(), process_base_address, process_size, pattern.c_str());

    auto results = PatternScanRemoteAll(process_base_address, process_size, pattern);

    if (results.empty())
    {
        printf("[!] No matches found.\n");
        return;
    }

    printf("[+] Found %zu match(es):\n", results.size());
    for (size_t i = 0; i < results.size(); i++)
    {
        printf("    [%zu] 0x%llX (offset: +0x%llX)\n", i, results[i], results[i] - process_base_address);
    }
}
