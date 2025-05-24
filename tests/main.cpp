#include <iostream>
#include "AES.h"

int main() {
    std::vector<uint8_t> key = {0x10, 0x20, 0x30, 0x40};

    AES aes(key);

    std::vector<uint8_t> plaintext = {'H', 'e', 'l', 'l', 'o'};
    auto ciphertext = aes.encrypt(plaintext);
    auto decrypted = aes.decrypt(ciphertext);

    std::cout << "Original: ";
    for (auto ch : plaintext) std::cout << char(ch);
    std::cout << "\nDecrypted: ";
    for (auto ch : decrypted) std::cout << char(ch);
    std::cout << std::endl;

    return 0;
}
