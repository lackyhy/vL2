cmake_minimum_required(VERSION 3.10)
project(vL2 LANGUAGES CXX ASM)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release")
endif()

# ── Sources (C++ only; .S file added conditionally below) ──────────────────
file(GLOB SOURCES "src/cpp/*.cpp")
# Remove the stub by default — it is added only when embedding is disabled
list(FILTER SOURCES EXCLUDE REGEX "xray_embedded_stub\\.cpp$")

include_directories(
    "${CMAKE_SOURCE_DIR}/src/h"
    "${CMAKE_SOURCE_DIR}/src"
    "${CMAKE_BINARY_DIR}"          # for generated files
)

add_executable(vl2 ${SOURCES})

target_compile_options(vl2 PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/W4>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall;-Wextra;-Wpedantic>
)

if(WIN32)
    target_link_libraries(vl2 PRIVATE shell32 user32)
endif()

# ── Xray binary embedding via .incbin ──────────────────────────────────────
# Supported compilers: GCC, Clang, AppleClang (i.e. NOT MSVC).
# Place the platform-appropriate xray binary in one of these locations
# before running cmake:
#   xray/xray        (macOS / Linux)
#   xray/xray.exe    (Windows)

if(WIN32)
    set(_xray_candidates
        "${CMAKE_SOURCE_DIR}/xray/xray.exe"
        "${CMAKE_SOURCE_DIR}/xray/xray-core.exe"
    )
else()
    set(_xray_candidates
        "${CMAKE_SOURCE_DIR}/xray/xray"
        "${CMAKE_SOURCE_DIR}/xray/xray-core"
    )
endif()

set(XRAY_BINARY_PATH "")
foreach(_c ${_xray_candidates})
    if(EXISTS "${_c}")
        set(XRAY_BINARY_PATH "${_c}")
        break()
    endif()
endforeach()

if(XRAY_BINARY_PATH AND NOT CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    # ── Get file size for the companion xray_size.cpp ──────────────────────
    file(SIZE "${XRAY_BINARY_PATH}" XRAY_SIZE)

    message(STATUS "Embedding xray binary: ${XRAY_BINARY_PATH} (${XRAY_SIZE} bytes)")

    # ── Generate assembly file (.S goes through C preprocessor) ───────────
    configure_file(
        "${CMAKE_SOURCE_DIR}/src/asm/xray_embed.S.in"
        "${CMAKE_BINARY_DIR}/xray_embed.S"
        @ONLY
    )

    # ── Generate size constant source ──────────────────────────────────────
    configure_file(
        "${CMAKE_SOURCE_DIR}/src/cpp/xray_size.cpp.in"
        "${CMAKE_BINARY_DIR}/xray_size.cpp"
        @ONLY
    )

    target_sources(vl2 PRIVATE
        "${CMAKE_BINARY_DIR}/xray_embed.S"
        "${CMAKE_BINARY_DIR}/xray_size.cpp"
    )
    target_compile_definitions(vl2 PRIVATE VL2_EMBED_XRAY)

else()
    # ── No embedding: use stub so the linker is satisfied ──────────────────
    if(XRAY_BINARY_PATH AND CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
        message(STATUS "MSVC detected — xray .incbin embedding not supported; using stub")
    else()
        message(STATUS "No xray binary found in xray/ — embedding disabled; binary will be loaded from disk")
    endif()

    target_sources(vl2 PRIVATE
        "${CMAKE_SOURCE_DIR}/src/cpp/xray_embedded_stub.cpp"
    )
endif()
