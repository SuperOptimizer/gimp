# GIMP fuzzing targets
# This CMakeLists.txt builds standalone fuzzers for GIMP image format parsers
# without requiring the full GIMP build infrastructure.

cmake_minimum_required(VERSION 3.16)
project(gimp-fuzzers C)

# Only build the fuzz targets
add_subdirectory(fuzz)
