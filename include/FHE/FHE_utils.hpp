#pragma once

#include "seal/seal.h"
#include <memory>
#include <vector>
#include <string>

struct FHEConfig
{
    size_t poly_modulus_degree = 8192;
    uint64_t plain_modulus_bits = 20;
};

class FHEUtils
{
public:
    FHEUtils(const FHEConfig &config = FHEConfig(), const std::vector<uint8_t> &mac_key = {});
    ~FHEUtils() = default;

    seal::Ciphertext encrypt(int64_t value, std::string *mac = nullptr);
    seal::Ciphertext encrypt_vector(const std::vector<uint64_t> &values, std::string *mac = nullptr);
    int64_t decrypt(const seal::Ciphertext &encrypted, const std::string &mac = "");
    std::vector<uint64_t> decrypt_vector(const seal::Ciphertext &encrypted, const std::string &mac = "");
    seal::Ciphertext add(const seal::Ciphertext &a, const seal::Ciphertext &b);
    seal::Ciphertext multiply(const seal::Ciphertext &a, const seal::Ciphertext &b);
    seal::Ciphertext compare_greater(const seal::Ciphertext &a, const seal::Ciphertext &b);
    void save_ciphertext(const seal::Ciphertext &ct, const std::string &file_path);
    seal::Ciphertext load_ciphertext(const std::string &file_path);

private:
    std::shared_ptr<seal::SEALContext> context;
    std::unique_ptr<seal::KeyGenerator> keygen;
    seal::SecretKey secret_key;
    seal::PublicKey public_key;
    seal::RelinKeys relin_keys;
    std::unique_ptr<seal::Encryptor> encryptor;
    std::unique_ptr<seal::Decryptor> decryptor;
    std::unique_ptr<seal::Evaluator> evaluator;
    std::unique_ptr<seal::BatchEncoder> batch_encoder;
    std::vector<uint8_t> mac_key;
    std::string compute_hmac(const seal::Ciphertext &ct);
};