#include "FHE/FHE_utils.hpp"
#include <iostream>

using namespace seal;

FHEUtils::FHEUtils() {
    std::cout << "[+] Initializing FHE Utilities..." << std::endl;

    // Set encryption parameters for BFV scheme
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

    // Create SEALContext
    context = std::make_shared<SEALContext>(parms);

    // Check if the context is valid
    if (!context->parameters_set()) {
        std::cerr << "[!] Error: Invalid SEAL parameters" << std::endl;
        throw std::runtime_error("Invalid SEAL parameters");
    }

    // Create KeyGenerator
    keygen = std::make_unique<KeyGenerator>(*context);

    // Get secret key
    secret_key = keygen->secret_key();

    // Generate public key
    keygen->create_public_key(public_key);

    // Generate relinearization keys for multiplication
    keygen->create_relin_keys(relin_keys);

    // Initialize Encryptor, Decryptor, Evaluator, BatchEncoder
    encryptor = std::make_unique<Encryptor>(*context, public_key);
    decryptor = std::make_unique<Decryptor>(*context, secret_key);
    evaluator = std::make_unique<Evaluator>(*context);
    batch_encoder = std::make_unique<BatchEncoder>(*context);

    std::cout << "[+] FHE Utilities initialized successfully." << std::endl;
}

seal::Ciphertext FHEUtils::encrypt_vector(const std::vector<uint64_t>& values) {
    seal::Plaintext plain;
    batch_encoder->encode(values, plain);
    seal::Ciphertext encrypted;
    encryptor->encrypt(plain, encrypted);
    return encrypted;
}

std::vector<uint64_t> FHEUtils::decrypt_vector(const seal::Ciphertext& encrypted) {
    seal::Plaintext plain;
    decryptor->decrypt(encrypted, plain);
    std::vector<uint64_t> result;
    batch_encoder->decode(plain, result);
    return result;
}

int64_t FHEUtils::decrypt(const seal::Ciphertext& encrypted) {
    seal::Plaintext plain;
    decryptor->decrypt(encrypted, plain);
    std::vector<uint64_t> decoded;
    batch_encoder->decode(plain, decoded);
    return static_cast<int64_t>(decoded[0]);
}

seal::Ciphertext FHEUtils::encrypt(int64_t value) {
    seal::Plaintext plain;
    std::vector<uint64_t> input(batch_encoder->slot_count(), 0ULL);
    input[0] = static_cast<uint64_t>(value); // Put the value in the first slot
    batch_encoder->encode(input, plain);
    seal::Ciphertext encrypted;
    encryptor->encrypt(plain, encrypted);
    return encrypted;
}

seal::Ciphertext FHEUtils::add(const seal::Ciphertext& a, const seal::Ciphertext& b) {
    seal::Ciphertext result;
    evaluator->add(a, b, result);
    return result;
}

seal::Ciphertext FHEUtils::multiply(const seal::Ciphertext& a, const seal::Ciphertext& b) {
    seal::Ciphertext result;
    evaluator->multiply(a, b, result);
    evaluator->relinearize_inplace(result, relin_keys);
    return result;
}