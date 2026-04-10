#pragma once

#include <cstdint>
#include <expected>
#include <filesystem>
#include <span>
#include <string>
#include <vector>
#include <windows.h>

namespace pe_utils {

inline constexpr std::size_t certificate_alignment = 8;
inline constexpr LONG max_pe_header_offset = 0x100000;

[[nodiscard]] constexpr std::size_t align_up(std::size_t value, std::size_t alignment) noexcept {
    return (value + alignment - 1) & ~(alignment - 1);
}

[[nodiscard]] std::expected<std::vector<uint8_t>, std::string>
read_binary_file(const std::filesystem::path& path) noexcept;

[[nodiscard]] IMAGE_DATA_DIRECTORY* security_directory(std::span<uint8_t> buffer);

} // namespace pe_utils
