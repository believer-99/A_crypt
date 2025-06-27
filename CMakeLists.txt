cmake_minimum_required(VERSION 3.20)
project(HybridCryptoLib)

set(CMAKE_CXX_STANDARD 17)

find_package(OpenSSL REQUIRED)

set(SEAL_DIR "/usr/local/lib/cmake/SEAL")
find_package(SEAL 4.1 REQUIRED)

include_directories(
    ${PROJECT_SOURCE_DIR}/include 
    ${OpenSSL_INCLUDE_DIR}         
)

set(SOURCES
    src/AES.cpp
    src/FHE/FHE_utils.cpp
    src/SE.cpp
    src/utils/String_utils.cpp 
)

add_library(hybridcrypto STATIC ${SOURCES})
target_include_directories(hybridcrypto PUBLIC ${PROJECT_SOURCE_DIR}/include)

target_link_libraries(hybridcrypto PUBLIC SEAL::seal OpenSSL::SSL OpenSSL::Crypto)

add_executable(main tests/main.cpp)
target_link_libraries(main PRIVATE hybridcrypto)

add_executable(se_test tests/se_test.cpp)
target_link_libraries(se_test PRIVATE hybridcrypto)

add_executable(fhe_test tests/fhe_test.cpp)
target_link_libraries(fhe_test PRIVATE hybridcrypto)

add_executable(hybrid_test tests/hybrid_test.cpp)
target_link_libraries(hybrid_test PRIVATE hybridcrypto)