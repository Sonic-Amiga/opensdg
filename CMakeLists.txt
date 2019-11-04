cmake_minimum_required(VERSION 3.13)

project(OpenSDG)

include_directories(include)
add_compile_definitions(_CRT_SECURE_NO_WARNINGS)

add_subdirectory(library)
add_subdirectory(testapp)
