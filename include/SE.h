#pragma once

#include<bits/stdc++.h>
#include <cstdint>

class SE
{
    private:
        std::vector<uint8_t> key;
        std::unordered_map<std::string,std::vector<std::string>>encryptedIndex;

        std::string encryptKeyword(const std::string& keyword);
        std::string encryptDocID(const std::string& docID);

        public:
        SE(const std::vector<uint8_t>& key);

        void addDocument(const std::string& docID, const std::vector<std::string>& keywords);
        std::vector<std::string> search(const std::string& keyword);
};