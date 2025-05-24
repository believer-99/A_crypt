#include "AES.h"
#include<stdexcept>

AES::AES(const std::vector<uint8_t>& key) {
    if (key.size() != 4) {
        throw std::invalid_argument("Only 4-byte keys supported for demo.");
    }
    this->key = key;
}

std::vector<uint8_t> AES::encrypt(const std::vector<uint8_t>& plaintext) {
    std::vector<uint8_t> ciphertext = plaintext;
    for (auto& byte : ciphertext) {
        byte ^= key[0];
    }
    return ciphertext;
}


std::vector<uint8_t> AES::decrypt(const std::vector<uint8_t>& ciphertext) {
    return encrypt(ciphertext); 
}

