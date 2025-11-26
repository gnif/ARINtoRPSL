cmake_minimum_required(VERSION 3.10.0)
project(ARINtoRPSL VERSION 0.1.0 LANGUAGES C)

add_compile_options(
  "-Wall"
  "-Wextra"
  "-Wno-sign-compare"
  "-Wno-unused-parameter"
  "$<$<COMPILE_LANGUAGE:C>:-Wstrict-prototypes>"
  "$<$<C_COMPILER_ID:GNU>:-Wimplicit-fallthrough=2>"
  "-Werror"
  "-Wfatal-errors"
  "-ffast-math"
  "-fdata-sections"
  "-ffunction-sections"
  "$<$<CONFIG:DEBUG>:-O0;-g3;-ggdb>"  
)

add_subdirectory(repos/libhpxml)

add_executable(ARINtoRPSL
  main.c
  util.c
  process.c
  process/org.c
  process/net.c)

target_link_libraries(ARINtoRPSL
  PRIVATE hpxml)