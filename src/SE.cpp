// src/SE.cpp
#include "SE.h"
#include "utils/String_utils.h" 
#include <stdexcept>
#include <vector>
#include <string>


std::string SE::convert_bytes_to_string(const std::vector<uint8_t>& data) {
    return std::string(data.begin(), data.end());
}

SE::SE(const std::vector<uint8_t>& key_param) 
    : aes(key_param), fixed_sse_iv_(GCM_IV_SIZE, 0x00) {
    if (fixed_sse_iv_.size() != GCM_IV_SIZE) {
        throw std::logic_error("SE fixed IV size mismatch with GCM_IV_SIZE.");
    }
}

void SE::add(const std::string& keyword, const std::vector<std::string>& docIDs) {
    std::string encryptedKeywordBase64 = encryptKeyword(keyword);
    auto& id_list = encryptedIndex[encryptedKeywordBase64]; 

    for (const auto& docID : docIDs) {
        std::string encryptedDocIDBase64 = encryptDocID(docID);
        id_list.push_back(encryptedDocIDBase64);
    }
}

std::vector<std::string> SE::search(const std::string& keyword) {
    std::string encryptedKeywordBase64 = encryptKeyword(keyword);
    auto it = encryptedIndex.find(encryptedKeywordBase64);
    if (it != encryptedIndex.end()) {
        return it->second;
    }
    return {};
}

std::string SE::decryptDocIDFromBase64(const std::string& base64_encrypted_docID) {
    std::vector<uint8_t> iv_ciphertext_tag_blob = StringUtils::base64_decode(base64_encrypted_docID);
    
    std::vector<uint8_t> decrypted_docID_bytes = aes.decrypt(iv_ciphertext_tag_blob);
    
    return convert_bytes_to_string(decrypted_docID_bytes);
}

std::string SE::encryptKeyword(const std::string& keyword) {
    std::vector<uint8_t> input(keyword.begin(), keyword.end());
    std::vector<uint8_t> encrypted_blob = aes.encrypt_deterministic(input, fixed_sse_iv_);
    
    return StringUtils::base64_encode(encrypted_blob);
}

std::string SE::encryptDocID(const std::string& docID) {
    std::vector<uint8_t> input(docID.begin(), docID.end());
    std::vector<uint8_t> encrypted_blob = aes.encrypt_deterministic(input, fixed_sse_iv_);

    return StringUtils::base64_encode(encrypted_blob);
}