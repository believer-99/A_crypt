#include "SE.h"
#include<sstream>
#include<iomanip>

SE::SE(const std::vector<uint8_t>& key) : aes(key) {}

std::string convert_to_hex(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
oss << std::hex;
for (const auto& byte : data) {
    oss << std::setw(2) << std::setfill('0') << int(byte);
}

    return oss.str();
}

void SE::add(const std::string& keyword, const std::vector<std::string>& docIDs) {
    std::string encryptedKeyword = encryptKeyword(keyword);
    for (const auto& docID : docIDs) {
        std::string encryptedDocID = encryptDocID(docID);
        encryptedIndex[encryptedKeyword].push_back(encryptedDocID);
    }
}

std::vector<std::string> SE::search(const std::string& keyword) {
    std::string encryptedKeyword = encryptKeyword(keyword);
    if (encryptedIndex.find(encryptedKeyword) != encryptedIndex.end()) {
        return encryptedIndex[encryptedKeyword];
    }
    return {};
}
std::string SE::encryptKeyword(const std::string& keyword) {
    std::vector<uint8_t> input(keyword.begin(), keyword.end());
    auto encrypted = aes.encrypt(input); 
    return convert_to_hex(encrypted);
}

std::string SE::encryptDocID(const std::string& docID) {
    std::vector<uint8_t> input(docID.begin(), docID.end());
    auto encrypted = aes.encrypt(input);
    return convert_to_hex(encrypted);
}

