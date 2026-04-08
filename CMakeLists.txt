cmake_minimum_required(VERSION 3.10)
project(vL2 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release")
endif()

file(GLOB SOURCES "src/cpp/*.cpp")

include_directories(
    "${CMAKE_SOURCE_DIR}/src/h"
    "${CMAKE_SOURCE_DIR}/src"
)
add_executable(vl2 ${SOURCES})

target_compile_options(vl2 PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/W4>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall;-Wextra;-Wpedantic>
)

if(WIN32)
    target_link_libraries(vl2 PRIVATE shell32 user32)
endif()
