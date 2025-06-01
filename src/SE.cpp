#include "SE.h"
#include <sstream>
#include <iomanip>
#include <stdexcept>

std::string convert_to_hex(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    oss << std::hex;
    for (const auto& byte : data) {
        oss << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return oss.str();
}

std::vector<uint8_t> SE::convert_from_hex(const std::string& hex_str) {
    if (hex_str.length() % 2 != 0) {
        throw std::invalid_argument("Hex string must have an even number of characters.");
    }
    std::vector<uint8_t> bytes;
    bytes.reserve(hex_str.length() / 2);
    for (unsigned int i = 0; i < hex_str.length(); i += 2) {
        std::string byteString = hex_str.substr(i, 2);
        try {
            uint8_t byte = static_cast<uint8_t>(std::stoul(byteString, nullptr, 16));
            bytes.push_back(byte);
        } catch (const std::invalid_argument& e) {
            throw std::invalid_argument("Invalid hex character in string: " + byteString + " (" + e.what() + ")");
        } catch (const std::out_of_range& e) {
            throw std::out_of_range("Hex value out of range: " + byteString + " (" + e.what() + ")");
        }
    }
    return bytes;
}

std::string SE::convert_bytes_to_string(const std::vector<uint8_t>& data) {
    return std::string(data.begin(), data.end());
}

SE::SE(const std::vector<uint8_t>& key_param) : aes(key_param) {} 

void SE::add(const std::string& keyword, const std::vector<std::string>& docIDs) {
    std::string encryptedKeywordHex = encryptKeyword(keyword);
    if (encryptedIndex.find(encryptedKeywordHex) == encryptedIndex.end()) {
        encryptedIndex[encryptedKeywordHex] = {};
    }
    for (const auto& docID : docIDs) {
        std::string encryptedDocIDHex = encryptDocID(docID);
        encryptedIndex[encryptedKeywordHex].push_back(encryptedDocIDHex);
    }
}

std::vector<std::string> SE::search(const std::string& keyword) {
    std::string encryptedKeywordHex = encryptKeyword(keyword);
    if (encryptedIndex.count(encryptedKeywordHex)) {
        return encryptedIndex[encryptedKeywordHex];
    }
    return {};
}

std::string SE::decryptDocIDFromHex(const std::string& hex_encrypted_docID) {
    std::vector<uint8_t> encrypted_docID_bytes = convert_from_hex(hex_encrypted_docID);
    std::vector<uint8_t> decrypted_docID_bytes = aes.decrypt(encrypted_docID_bytes);
    return convert_bytes_to_string(decrypted_docID_bytes);
}

std::string SE::encryptKeyword(const std::string& keyword) {
    std::vector<uint8_t> input(keyword.begin(), keyword.end());
    auto encrypted_bytes = aes.encrypt(input);
    return convert_to_hex(encrypted_bytes);
}

std::string SE::encryptDocID(const std::string& docID) {
    std::vector<uint8_t> input(docID.begin(), docID.end());
    auto encrypted_bytes = aes.encrypt(input);
    return convert_to_hex(encrypted_bytes);
}