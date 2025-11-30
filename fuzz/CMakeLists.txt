# GIMP image format fuzzers
# Standalone harnesses for fuzzing GIMP's file format parsers

cmake_minimum_required(VERSION 3.16)
project(gimp-fuzz C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Fuzzer sources
set(FUZZ_TARGETS
    fuzz_xwd
    fuzz_tga
    fuzz_farbfeld
    fuzz_wbmp
    fuzz_sunras
    fuzz_dicom
    fuzz_icns
    fuzz_bmp
    fuzz_psd
    fuzz_dds
    fuzz_fli
    fuzz_pcx
    fuzz_sgi
    fuzz_pnm
    fuzz_gif
    fuzz_xpm
    fuzz_cel
    fuzz_ani
    fuzz_qoi
    fuzz_psp
    fuzz_fits
    fuzz_pvr
    fuzz_paa
    fuzz_tim
    fuzz_iff
    fuzz_faxg3
)

# Find zlib for PSP fuzzer
find_package(ZLIB REQUIRED)

# Build each fuzzer
foreach(target ${FUZZ_TARGETS})
    add_executable(${target} ${target}.c)

    # Link math library if needed
    target_link_libraries(${target} PRIVATE m)

    # Enable position-independent code for better ASAN support
    set_target_properties(${target} PROPERTIES POSITION_INDEPENDENT_CODE ON)

    # Note: We keep the standalone main() for AFL++ compatibility
    # AFL++ will instrument the binary and use file-based input
    # For libFuzzer mode, define FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION externally

    # Install to bin directory
    install(TARGETS ${target} DESTINATION bin)
endforeach()

# Link zlib to PSP fuzzer
target_link_libraries(fuzz_psp PRIVATE ZLIB::ZLIB)

# Summary message
message(STATUS "GIMP fuzz targets: ${FUZZ_TARGETS}")
