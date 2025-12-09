#ifndef SIGNATURE_THIEF_HPP
#define SIGNATURE_THIEF_HPP

#include <vector>
#include <filesystem>
#include <optional>
#include <span>
#include <windows.h>

class signature_thief {
public:
    explicit signature_thief(std::filesystem::path path);

    [[nodiscard]] std::optional<std::string> load_payload() noexcept;

    void extract_certificate(const std::filesystem::path& signed_pe_path);

    void append_certificate(std::span<const uint8_t> signature);

    [[nodiscard]] const std::vector<uint8_t>& payload() const noexcept { return m_payload; }
    [[nodiscard]] const std::vector<uint8_t>& certificate() const noexcept { return m_cert; }

private:
    IMAGE_DATA_DIRECTORY* security_directory(uint8_t* base);

    std::filesystem::path m_payload_path;
    std::vector<uint8_t> m_payload;
    std::vector<uint8_t> m_cert;
};

#endif // SIGNATURE_THIEF_HPP
