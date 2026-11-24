cmake_minimum_required(VERSION 3.22.1)
project(shieldlab LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_library(shieldlab SHARED
    apk_signature.cpp
    anti_debug.cpp
    extra_checks.cpp
    emulator_deep.cpp
    sha256.c
    vigil_checks.cpp
)
target_compile_options(shieldlab PRIVATE -O2 -fvisibility=hidden)
target_link_libraries(shieldlab log)
