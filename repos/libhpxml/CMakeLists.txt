cmake_minimum_required(VERSION 3.10.0)
project(libhpxml C)

add_library(hpxml STATIC
  libhpxml/src/libhpxml.c
  libhpxml/src/bstring.c
)

target_include_directories(hpxml PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/libhpxml/src"
)

target_compile_options(hpxml PRIVATE
  -Wall
  -O2
  -Wno-error
)

target_compile_definitions(hpxml PRIVATE
  "-DWITH_MMAP"
)

set_target_properties(hpxml PROPERTIES
  OUTPUT_NAME "hpxml"
)