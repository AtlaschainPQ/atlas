cmake_minimum_required(VERSION 3.18)
project(atlas_triad_miner VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Optimierungen
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_FLAGS_RELEASE "-O3 -march=native -DNDEBUG")
set(CMAKE_CXX_FLAGS_DEBUG   "-O0 -g -fsanitize=address")

# SIMD Support prüfen
include(CheckCXXCompilerFlag)
check_cxx_compiler_flag("-mavx2"  HAS_AVX2)
check_cxx_compiler_flag("-maes"   HAS_AES)
check_cxx_compiler_flag("-msse4.1" HAS_SSE4)

if(HAS_AVX2)
    add_compile_options(-mavx2)
    add_definitions(-DHAS_AVX2)
endif()

if(HAS_AES)
    add_compile_options(-maes)
    add_definitions(-DHAS_AES)
endif()

# Threads
find_package(Threads REQUIRED)

# Quellen
add_library(atlas_triad_miner SHARED
    src/triad_miner.cpp
    src/dataset.cpp
    src/cache.cpp
    src/sha256.cpp
)

target_include_directories(atlas_triad_miner PUBLIC include)
target_link_libraries(atlas_triad_miner PRIVATE Threads::Threads)

# Benchmark Binary
add_executable(triad_bench src/bench.cpp)
target_link_libraries(triad_bench PRIVATE atlas_triad_miner Threads::Threads)
target_include_directories(triad_bench PRIVATE include)

# Tests
enable_testing()
add_executable(triad_test src/test.cpp)
target_link_libraries(triad_test PRIVATE atlas_triad_miner Threads::Threads)
target_include_directories(triad_test PRIVATE include)
add_test(NAME TriadTest COMMAND triad_test)
