#ifndef SIGNATURE_THIEF_HPP
#define SIGNATURE_THIEF_HPP

#include <vector>
#include <string_view>

struct mapped_file_t {
    using byte_array_t = std::vector<uint8_t>;
    byte_array_t binary;
    uint64_t size;
};

class Signature_Thief {
public:
    mapped_file_t map_binary_to_memory(std::string_view filename);
    mapped_file_t rip_cert(std::string_view file_location);
    void append_signature_to_payload(std::string_view signature_file, mapped_file_t& payload);
};

#endif 
