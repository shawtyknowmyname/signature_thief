#ifndef SIGNATURE_THIEF_HPP
#define SIGNATURE_THIEF_HPP

#include <vector>
#include <string_view>
#include <filesystem>
#include <span>
#include <optional>

class signature_thief {
public:
	explicit signature_thief(std::filesystem::path path_to_file);

	std::optional<std::string> load_file() noexcept;
	void extract_certificate(std::filesystem::path from_where);
	void append_certificate_to_payload(std::span<uint8_t> signature_data);

	auto get_binary() const { return m_file; }
	auto get_certificate() const { return m_cert; }

private:
	std::vector<uint8_t> m_file;
	std::vector<uint8_t> m_cert;
	std::filesystem::path m_source_path;
};

#endif
