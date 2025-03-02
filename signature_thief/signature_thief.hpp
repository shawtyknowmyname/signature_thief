#ifndef SIGNATURE_THIEF_HPP
#define SIGNATURE_THIEF_HPP

#include <vector>
#include <filesystem>
#include <optional>
#include <Windows.h>
#include <span>

class signature_thief {
public:
    explicit signature_thief(std::filesystem::path path_to_file);

    [[nodiscard]] std::optional<std::string> load_file() noexcept;
    void extract_certificate(std::filesystem::path from_where);
    void append_certificate_to_payload(std::span<const uint8_t> signature_data);

    [[nodiscard]] const std::vector<uint8_t>& get_binary() const { return m_file; }
    [[nodiscard]] const std::vector<uint8_t>& get_certificate() const { return m_cert; }

private:
    void update_pe_header();

    std::vector<uint8_t> m_file;
    std::vector<uint8_t> m_cert;
    std::filesystem::path m_source_path;
};

#endif