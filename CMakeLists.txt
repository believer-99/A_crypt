cmake_minimum_required(VERSION 3.20)
project(HybridCryptoLib)

set(CMAKE_CXX_STANDARD 17)

file(GLOB_RECURSE SOURCES "src/*.cpp")

include_directories(${PROJECT_SOURCE_DIR}/include)

add_executable(main ${SOURCES} tests/main.cpp)

add_executable(se_test ${SOURCES} tests/se_test.cpp)

target_include_directories(main PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_include_directories(se_test PRIVATE ${PROJECT_SOURCE_DIR}/include)
