#include "signature_thief.hpp"

#include <iostream>
#include <print>
#include <string>

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
            std::print("Enter path to SIGNED PE file: ");
            std::getline(std::cin, signed_pe_path);

            std::print("Enter path to PAYLOAD file: ");
            std::getline(std::cin, payload_path);

            std::print("Enter OUTPUT file path: ");
            std::getline(std::cin, output_path);
        }

        signature_thief thief(payload_path);
        thief.process(signed_pe_path, output_path);

        std::println("Certificate appended successfully");

        return EXIT_SUCCESS;
    }
    catch (const std::exception& e) {
        std::println(stderr, "Fatal error: {}", e.what());
        return EXIT_FAILURE;
    }
}