#pragma once

#include <vector>
#include <string>
#include <unordered_map>
#include <cstdint>
#include "AES.h" // Uses the new AES.h

class SE {
private:
    AES aes; 
    std::unordered_map<std::string, std::vector<std::string>> encryptedIndex;

    // These will now use aes.encrypt_deterministic() and return Base64 of (IV || CT || Tag)
    std::string encryptKeyword(const std::string& keyword);
    std::string encryptDocID(const std::string& docID);

    const std::vector<uint8_t> fixed_sse_iv_;

    static std::string convert_bytes_to_string(const std::vector<uint8_t>& data);

public:
    SE(const std::vector<uint8_t>& key);

    void add(const std::string& keyword, const std::vector<std::string>& docIDs);
    std::vector<std::string> search(const std::string& keyword);

    std::string decryptDocIDFromBase64(const std::string& base64_encrypted_docID);
};