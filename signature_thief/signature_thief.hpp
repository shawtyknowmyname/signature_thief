#ifndef SIGNATURE_THIEF_HPP
#define SIGNATURE_THIEF_HPP

#include <vector>
#include <iostream>
#include <fstream>
#include <stdexcept>
#include <Windows.h>

struct MappedFile {
    std::vector<BYTE> data;
    LONGLONG size;
};

MappedFile MapFileToMemory(const std::string& filename);
MappedFile RippedCert(const std::string& fromWhere);
void AppendSignatureToPayload(const std::string& signedPePath, const std::string& payloadPath, const std::string& outputPath);

#endif 
