#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace StringUtils
{
    std::string base64_encode(const std::vector<uint8_t> &bytes_to_encode);
    std::vector<uint8_t> base64_decode(const std::string &encoded_string);
}