#pragma once

#include <cstdint>
#include <filesystem>
#include <vector>

class signature_thief {
public:
    explicit signature_thief(std::filesystem::path payload_path);

    void process(const std::filesystem::path& signed_pe_path,
                 const std::filesystem::path& output_path);

private:
    void load_payload();
    void extract_certificate(const std::filesystem::path& signed_pe_path);
    void apply_certificate();
    void save(const std::filesystem::path& output_path) const;

    std::filesystem::path m_payload_path;
    std::vector<uint8_t> m_payload;
    std::vector<uint8_t> m_certificate;
};
