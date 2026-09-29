cmake_minimum_required(VERSION 3.20)
project(SENTINEL_CYBER_DEFENSE VERSION 1.4.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_compile_options(-Wall -Wextra -Wpedantic -O2)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/core
    ${CMAKE_CURRENT_SOURCE_DIR}/collector
)

find_package(OpenSSL REQUIRED)
find_package(nlohmann_json REQUIRED)

# 1. Native Collector Binary
add_executable(sentinel_collector
    collector/main_collector.cpp
)
target_link_libraries(sentinel_collector PRIVATE OpenSSL::SSL OpenSSL::Crypto nlohmann_json::nlohmann_json)

# 2. C++ Unit Tests Binary
add_executable(sentinel_tests
    tests/test_sentinel_core.cpp
)
target_link_libraries(sentinel_tests PRIVATE OpenSSL::SSL OpenSSL::Crypto nlohmann_json::nlohmann_json)
