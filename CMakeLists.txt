cmake_minimum_required(VERSION 3.20)
project(HybridCryptoLib)

set(CMAKE_CXX_STANDARD 17)

set(SEAL_DIR "/usr/local/lib/cmake/SEAL")
find_package(SEAL 4.1 REQUIRED)

include_directories(${PROJECT_SOURCE_DIR}/include)

file(GLOB_RECURSE SOURCES "src/*.cpp")

add_library(hybridcrypto STATIC ${SOURCES})
target_include_directories(hybridcrypto PUBLIC ${PROJECT_SOURCE_DIR}/include)

target_link_libraries(hybridcrypto PUBLIC SEAL::seal)

add_executable(main tests/main.cpp)
target_link_libraries(main PRIVATE hybridcrypto)

add_executable(se_test tests/se_test.cpp)
target_link_libraries(se_test PRIVATE hybridcrypto)

add_executable(fhe_test tests/fhe_test.cpp)
target_link_libraries(fhe_test PRIVATE hybridcrypto)

add_executable(hybrid_test tests/hybrid_test.cpp)
target_link_libraries(hybrid_test PRIVATE hybridcrypto)
