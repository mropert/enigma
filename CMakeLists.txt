cmake_minimum_required(VERSION 3.18)
project(enigma CXX)

find_package(Catch2 CONFIG REQUIRED)

add_compile_options(/Zi /std:c++latest)
add_link_options(/DEBUG)

add_library(enigma_lib src/enigma.cpp)
target_include_directories(enigma_lib PUBLIC include)

add_executable(enigma main.cpp)
target_link_libraries(enigma PRIVATE enigma_lib)

enable_testing()

add_executable(enigma_test test/catch_main.cpp test/enigma_test.cpp)
target_link_libraries(enigma_test PRIVATE enigma_lib)
target_link_libraries(enigma_test PRIVATE Catch2::Catch2)