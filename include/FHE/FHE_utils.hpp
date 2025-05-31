#pragma once

#include "seal/seal.h"
#include <memory>
#include <vector>

class FHEUtils {
public:
    FHEUtils();
    ~FHEUtils() = default; // Default destructor is sufficient due to unique_ptr

    seal::Ciphertext encrypt(int64_t value);
    seal::Ciphertext encrypt_vector(const std::vector<uint64_t>& values);
    int64_t decrypt(const seal::Ciphertext& encrypted);
    std::vector<uint64_t> decrypt_vector(const seal::Ciphertext& encrypted);
    seal::Ciphertext add(const seal::Ciphertext& a, const seal::Ciphertext& b);
    seal::Ciphertext multiply(const seal::Ciphertext& a, const seal::Ciphertext& b);

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
};