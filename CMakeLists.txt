cmake_minimum_required(VERSION 3.14)
project(pwner VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Release by default
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_FLAGS_RELEASE "-O2 -DNDEBUG")
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -fsanitize=address,undefined")

add_executable(pwner
    src/main.cpp
    src/utils.cpp
    src/config.cpp
    src/elf_parser.cpp
    src/scripts.cpp
    src/patcher.cpp
    src/decomp.cpp
)

target_include_directories(pwner PRIVATE src)
target_compile_options(pwner PRIVATE -Wall -Wextra -Wpedantic)

install(TARGETS pwner DESTINATION bin)
