#pragma once

#include <vector>
#include <string>
#include <unordered_map>
#include <cstdint>
#include "AES.h" 

class SE {
private:
    AES aes;
    std::unordered_map<std::string, std::vector<std::string>> encryptedIndex;

    std::string encryptKeyword(const std::string& keyword);
    std::string encryptDocID(const std::string& docID);

    static std::vector<uint8_t> convert_from_hex(const std::string& hex_str);
    static std::string convert_bytes_to_string(const std::vector<uint8_t>& data);

public:
    SE(const std::vector<uint8_t>& key);

    void add(const std::string& keyword, const std::vector<std::string>& docIDs);
    std::vector<std::string> search(const std::string& keyword);

    std::string decryptDocIDFromHex(const std::string& hex_encrypted_docID);
};