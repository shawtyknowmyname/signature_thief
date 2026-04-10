#include "pe_utils.hpp"

#include <fstream>
#include <stdexcept>

namespace pe_utils {

std::expected<std::vector<uint8_t>, std::string>
read_binary_file(const std::filesystem::path& path) noexcept {
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if (!stream.is_open())
        return std::unexpected("Unable to open file: " + path.string());

    auto file_size = static_cast<std::size_t>(stream.tellg());
    if (file_size == 0)
        return std::unexpected("Invalid file size: " + path.string());

    std::vector<uint8_t> buffer(file_size);
    stream.seekg(0);

    if (!stream.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(file_size)))
        return std::unexpected("Failed to read file: " + path.string());

    return buffer;
}

IMAGE_DATA_DIRECTORY* security_directory(std::span<uint8_t> buffer) {
    if (buffer.size() < sizeof(IMAGE_DOS_HEADER))
        throw std::runtime_error("Buffer too small for DOS header");

    auto* dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(buffer.data());

    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
        throw std::runtime_error("Invalid DOS header");

    if (dos_header->e_lfanew < 0 || dos_header->e_lfanew > max_pe_header_offset)
        throw std::runtime_error("Invalid PE header offset");

    auto nt_offset = static_cast<std::size_t>(dos_header->e_lfanew);
    if (nt_offset + sizeof(IMAGE_NT_HEADERS) > buffer.size())
        throw std::runtime_error("Buffer too small for NT headers");

    auto* nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(buffer.data() + nt_offset);

    if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
        throw std::runtime_error("Invalid NT signature");

    WORD magic = nt_headers->OptionalHeader.Magic;

    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        return &reinterpret_cast<PIMAGE_NT_HEADERS32>(nt_headers)
            ->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];

    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return &reinterpret_cast<PIMAGE_NT_HEADERS64>(nt_headers)
            ->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];

    throw std::runtime_error("Unknown PE optional header format");
}

} // namespace pe_utils
