#pragma once

#include <vector>
#include <string>
#include <unordered_map>
#include <cstdint>
#include <cstdint>
#include <AES.h>

class SE
{
    private:
        AES aes;
        std::vector<uint8_t> key;
        std::unordered_map<std::string,std::vector<std::string>>encryptedIndex;

        std::string encryptKeyword(const std::string& keyword);
        std::string encryptDocID(const std::string& docID);

        public:
        SE(const std::vector<uint8_t>& key);

        void add(const std::string& keyword, const std::vector<std::string>& docId);
        std::vector<std::string> search(const std::string& keyword);
};