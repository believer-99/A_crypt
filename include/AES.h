#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <stdexcept>

constexpr size_t AES_256_KEY_SIZE = 32;
constexpr size_t GCM_IV_SIZE = 12;
constexpr size_t GCM_TAG_SIZE = 16;

class AES
{
public:
    AES(const std::vector<uint8_t> &key);

    std::vector<uint8_t> encrypt(const std::vector<uint8_t> &plaintext);
    std::vector<uint8_t> decrypt(const std::vector<uint8_t> &iv_ciphertext_tag);
    std::vector<uint8_t> encrypt_deterministic(const std::vector<uint8_t> &plaintext, const std::vector<uint8_t> &provided_iv);

private:
    std::vector<uint8_t> key_;
    std::vector<uint8_t> gcm_encrypt(const std::vector<uint8_t> &plaintext, const std::vector<uint8_t> &iv, const std::vector<uint8_t> &aad = {});
    std::vector<uint8_t> gcm_decrypt(const std::vector<uint8_t> &ciphertext_with_tag, const std::vector<uint8_t> &iv, const std::vector<uint8_t> &aad = {});
};