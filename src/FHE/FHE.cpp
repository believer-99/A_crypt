#include "FHE/FHE.h"
#include "seal/batchencoder.h"
#include <iostream>

namespace hybridcrypto::fhe {

FHE::FHE()
    : parms_(seal::scheme_type::bfv),
      encryptor_(nullptr),
      evaluator_(nullptr),
      decryptor_(nullptr),
      encoder_(nullptr)
{
    initialize();
}

void FHE::initialize() {
    parms_.set_poly_modulus_degree(2048);
    parms_.set_coeff_modulus(seal::CoeffModulus::BFVDefault(2048));
    parms_.set_plain_modulus(seal::PlainModulus::Batching(2048, 20));

    context_ = std::make_shared<seal::SEALContext>(parms_);

    seal::KeyGenerator keygen(*context_);

    auto serial_pub_key = keygen.create_public_key();
    secret_key_ = keygen.secret_key();

    std::stringstream stream;
    serial_pub_key.save(stream);

    seal::PublicKey pub_key;
    pub_key.load(*context_, stream);

    public_key_ = pub_key;

    encryptor_ = std::make_unique<seal::Encryptor>(*context_, public_key_);
    decryptor_ = std::make_unique<seal::Decryptor>(*context_, secret_key_);
    evaluator_ = std::make_unique<seal::Evaluator>(*context_);
    encoder_   = std::make_unique<seal::BatchEncoder>(*context_);

}


void FHE::encryptInteger(int value) {
    std::vector<uint64_t> data(encoder_->slot_count(), 0);
    data[0] = static_cast<uint64_t>(value);

    seal::Plaintext plaintext;
    encoder_->encode(data, plaintext);
    encryptor_->encrypt(plaintext, encrypted_);
}

void FHE::decryptInteger() {
    seal::Plaintext decrypted;
    decryptor_->decrypt(encrypted_, decrypted);

    std::vector<uint64_t> result;
    encoder_->decode(decrypted, result);

    last_plaintext_result_ = static_cast<int>(result[0]);
}

void FHE::addEncrypted(int value) {
    std::vector<uint64_t> data(encoder_->slot_count(), 0);
    data[0] = static_cast<uint64_t>(value);

    seal::Plaintext plain;
    encoder_->encode(data, plain);
    evaluator_->add_plain_inplace(encrypted_, plain);
}

void FHE::multiplyEncrypted(int value) {
    std::vector<uint64_t> data(encoder_->slot_count(), 0);
    data[0] = static_cast<uint64_t>(value);

    seal::Plaintext plain;
    encoder_->encode(data, plain);
    evaluator_->multiply_plain_inplace(encrypted_, plain);
}

int FHE::getDecryptedValue() const {
    return last_plaintext_result_;
}

}
