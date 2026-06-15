#include "Headers.hpp"

// --- Bitwise Pointer Decryption Primitives ---

uint64_t DecryptXOR(uint64_t encrypted_ptr, uint64_t key)
{
    return encrypted_ptr ^ key;
}

uint64_t DecryptROL(uint64_t value, int bits)
{
    bits &= 63;
    return (value << bits) | (value >> (64 - bits));
}

uint64_t DecryptROR(uint64_t value, int bits)
{
    bits &= 63;
    return (value >> bits) | (value << (64 - bits));
}

uint64_t DecryptSUB(uint64_t encrypted_ptr, uint64_t key)
{
    return encrypted_ptr - key;
}

uint64_t DecryptADD(uint64_t encrypted_ptr, uint64_t key)
{
    return encrypted_ptr + key;
}

uint64_t DecryptNOT(uint64_t encrypted_ptr)
{
    return ~encrypted_ptr;
}

uint64_t DecryptBSWAP(uint64_t value)
{
    return ((value & 0x00000000000000FFULL) << 56) |
           ((value & 0x000000000000FF00ULL) << 40) |
           ((value & 0x0000000000FF0000ULL) << 24) |
           ((value & 0x00000000FF000000ULL) << 8)  |
           ((value & 0x000000FF00000000ULL) >> 8)  |
           ((value & 0x0000FF0000000000ULL) >> 24) |
           ((value & 0x00FF000000000000ULL) >> 40) |
           ((value & 0xFF00000000000000ULL) >> 56);
}

// --- Multi-step Pointer Decryption ---

// Apply a chain of decryption operations defined by a simple instruction set
// Format: "xor:KEY;ror:BITS;sub:KEY;not;bswap"
uint64_t DecryptChain(uint64_t encrypted_ptr, const std::string& operations)
{
    uint64_t result = encrypted_ptr;
    std::string ops = operations;
    size_t pos = 0;

    while ((pos = ops.find(';')) != std::string::npos || !ops.empty())
    {
        std::string op;
        if (pos != std::string::npos)
        {
            op = ops.substr(0, pos);
            ops = ops.substr(pos + 1);
        }
        else
        {
            op = ops;
            ops.clear();
        }

        size_t colon = op.find(':');
        std::string cmd = (colon != std::string::npos) ? op.substr(0, colon) : op;
        std::string arg = (colon != std::string::npos) ? op.substr(colon + 1) : "";

        if (cmd == "xor")
            result = DecryptXOR(result, strtoull(arg.c_str(), nullptr, 16));
        else if (cmd == "ror")
            result = DecryptROR(result, atoi(arg.c_str()));
        else if (cmd == "rol")
            result = DecryptROL(result, atoi(arg.c_str()));
        else if (cmd == "sub")
            result = DecryptSUB(result, strtoull(arg.c_str(), nullptr, 16));
        else if (cmd == "add")
            result = DecryptADD(result, strtoull(arg.c_str(), nullptr, 16));
        else if (cmd == "not")
            result = DecryptNOT(result);
        else if (cmd == "bswap")
            result = DecryptBSWAP(result);
        else
            printf("[!] Unknown decrypt operation: %s\n", cmd.c_str());

        if (ops.empty())
            break;

        pos = ops.find(';');
    }

    return result;
}

// --- Pointer Chain Walker ---

// Follow a multi-level pointer chain: base -> [+off1] -> [+off2] -> ... -> [+offN]
// Returns the final dereferenced address, or 0 on failure
uint64_t ReadPointerChain(uint64_t base, const std::vector<int64_t>& offsets)
{
    uint64_t current = base;

    for (size_t i = 0; i < offsets.size(); i++)
    {
        current += static_cast<uint64_t>(offsets[i]);

        if (i < offsets.size() - 1)
        {
            uint64_t next = 0;
            if (!vmmdll_read(current, &next, sizeof(next)))
            {
                printf("[!] Pointer chain broken at level %zu (addr: 0x%llX)\n", i, current);
                return 0;
            }

            if (next == 0)
            {
                printf("[!] Null pointer at level %zu (addr: 0x%llX)\n", i, current);
                return 0;
            }

            current = next;
        }
    }

    return current;
}

// Read and decrypt a pointer from remote memory
uint64_t ReadEncryptedPointer(uint64_t address, uint64_t xor_key)
{
    uint64_t encrypted = 0;
    if (!vmmdll_read(address, &encrypted, sizeof(encrypted)))
    {
        printf("[!] Failed to read encrypted pointer at 0x%llX\n", address);
        return 0;
    }
    return DecryptXOR(encrypted, xor_key);
}

// Read and decrypt a pointer using a full chain of operations
uint64_t ReadEncryptedPointerChain(uint64_t address, const std::string& operations)
{
    uint64_t encrypted = 0;
    if (!vmmdll_read(address, &encrypted, sizeof(encrypted)))
    {
        printf("[!] Failed to read encrypted pointer at 0x%llX\n", address);
        return 0;
    }
    return DecryptChain(encrypted, operations);
}

// --- Encrypted Pointer Chain Walker ---

// Walk a pointer chain where each level may be encrypted with a different XOR key
// keys[i] is applied to the pointer read at level i (0 = no encryption)
uint64_t ReadEncryptedPointerChainMulti(uint64_t base, const std::vector<int64_t>& offsets, const std::vector<uint64_t>& keys)
{
    uint64_t current = base;

    for (size_t i = 0; i < offsets.size(); i++)
    {
        current += static_cast<uint64_t>(offsets[i]);

        if (i < offsets.size() - 1)
        {
            uint64_t next = 0;
            if (!vmmdll_read(current, &next, sizeof(next)))
            {
                printf("[!] Encrypted pointer chain broken at level %zu (addr: 0x%llX)\n", i, current);
                return 0;
            }

            if (i < keys.size() && keys[i] != 0)
                next = DecryptXOR(next, keys[i]);

            if (next == 0)
            {
                printf("[!] Null pointer at level %zu after decryption (addr: 0x%llX)\n", i, current);
                return 0;
            }

            current = next;
        }
    }

    return current;
}

// --- Bruteforce XOR Key Discovery ---

// Try to discover a XOR key by reading an encrypted pointer and testing if
// decryption produces a valid-looking address (within expected module range)
uint64_t BruteforceXORKey(uint64_t encrypted_ptr_addr, uint64_t expected_base, size_t expected_size)
{
    uint64_t encrypted = 0;
    if (!vmmdll_read(encrypted_ptr_addr, &encrypted, sizeof(encrypted)))
    {
        printf("[!] Failed to read pointer for bruteforce at 0x%llX\n", encrypted_ptr_addr);
        return 0;
    }

    // If the pointer looks like it could be XOR'd with a value where the upper bits
    // match the expected module base, extract the key
    uint64_t candidate_key = encrypted ^ expected_base;

    // Verify: does key ^ encrypted fall within the expected range?
    uint64_t decrypted = encrypted ^ candidate_key;
    if (decrypted >= expected_base && decrypted < expected_base + expected_size)
    {
        printf("[+] Potential XOR key: 0x%llX (decrypted: 0x%llX)\n", candidate_key, decrypted);
        return candidate_key;
    }

    // Try byte-level key rotation
    for (int rot = 0; rot < 64; rot += 8)
    {
        uint64_t rotated_key = (candidate_key >> rot) | (candidate_key << (64 - rot));
        decrypted = encrypted ^ rotated_key;
        if (decrypted >= expected_base && decrypted < expected_base + expected_size)
        {
            printf("[+] Potential XOR key (rot %d): 0x%llX (decrypted: 0x%llX)\n", rot, rotated_key, decrypted);
            return rotated_key;
        }
    }

    printf("[!] Could not determine XOR key for pointer at 0x%llX\n", encrypted_ptr_addr);
    return 0;
}

// --- Interactive Decrypt Mode ---

void RunPointerDecrypt(uint64_t address, const std::string& operations)
{
    uint64_t encrypted = 0;
    if (!vmmdll_read(address, &encrypted, sizeof(encrypted)))
    {
        printf("[!] Failed to read pointer at 0x%llX\n", address);
        return;
    }

    printf("[>] Encrypted value at 0x%llX: 0x%llX\n", address, encrypted);

    uint64_t decrypted = DecryptChain(encrypted, operations);
    printf("[+] Decrypted result: 0x%llX\n", decrypted);
}

void RunPointerChainWalk(uint64_t base, const std::vector<int64_t>& offsets)
{
    printf("[>] Walking pointer chain from 0x%llX with %zu offset(s)\n", base, offsets.size());

    uint64_t current = base;
    for (size_t i = 0; i < offsets.size(); i++)
    {
        current += static_cast<uint64_t>(offsets[i]);
        printf("    [%zu] + 0x%llX => 0x%llX", i, static_cast<uint64_t>(offsets[i]), current);

        if (i < offsets.size() - 1)
        {
            uint64_t next = 0;
            if (!vmmdll_read(current, &next, sizeof(next)))
            {
                printf(" => [READ FAILED]\n");
                return;
            }
            printf(" => [0x%llX]\n", next);
            current = next;
        }
        else
        {
            printf(" (final)\n");
        }
    }

    printf("[+] Final address: 0x%llX\n", current);

    // Read and display the value at the final address
    uint64_t value = 0;
    if (vmmdll_read(current, &value, sizeof(value)))
        printf("[+] Value at final address: 0x%llX (%llu)\n", value, value);
}
