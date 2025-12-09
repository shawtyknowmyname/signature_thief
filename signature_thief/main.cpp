#include "signature_thief.hpp"
#include <iostream>
#include <fstream>
#include <stdexcept>

int main(int argc, char** argv)
{
    try {
        std::string signed_pe_path;
        std::string payload_path;
        std::string output_path;

        if (argc >= 4) {
            signed_pe_path = argv[1];
            payload_path = argv[2];
            output_path = argv[3];
        }
        else {
            std::cout << "Enter path to SIGNED PE file: ";
            std::getline(std::cin, signed_pe_path);

            std::cout << "Enter path to PAYLOAD file: ";
            std::getline(std::cin, payload_path);

            std::cout << "Enter OUTPUT file path: ";
            std::getline(std::cin, output_path);
        }

        signature_thief thief(payload_path);

        if (auto err = thief.load_payload()) {
            std::cerr << "Error: " << *err << "\n";
            return EXIT_FAILURE;
        }

        thief.extract_certificate(signed_pe_path);

        thief.append_certificate(thief.certificate());

        std::ofstream out(output_path, std::ios::binary);
        if (!out.is_open())
            throw std::runtime_error("Failed to open output file: " + output_path);

        const auto& data = thief.payload();
        out.write(reinterpret_cast<const char*>(data.data()), data.size());

        std::cout << "Certificate appended successfully\n";

        return EXIT_SUCCESS;
    }
    catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << "\n";
        return EXIT_FAILURE;
    }
}