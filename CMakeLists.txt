cmake_minimum_required(VERSION 3.12)
project(ouroboros VERSION 1.0.0)

find_package(Python COMPONENTS Interpreter)

# Use waf to resolve dependencies
if(NOT DEFINED STEINWURF_RESOLVE)
  message(STATUS "Resolving dependencies...")

  execute_process(
    COMMAND ${Python_EXECUTABLE} waf resolve ${STEINWURF_RESOLVE_OPTIONS} ${STEINWURF_RESOLVE_OPTIONS2}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    RESULT_VARIABLE STATUS)

  if(STATUS AND NOT STATUS EQUAL 0)
    message(FATAL_ERROR "Failed: ${STATUS}")
  endif()

  set(STEINWURF_RESOLVE "${CMAKE_CURRENT_SOURCE_DIR}/resolve_symlinks")
endif()

# Include common CMake settings
include("${STEINWURF_RESOLVE}/toolchains/common_settings.cmake")

# platform dependency
if(NOT TARGET steinwurf::platform)
  add_subdirectory("${STEINWURF_RESOLVE}/platform" platform EXCLUDE_FROM_ALL)
endif()

# verify
if(NOT TARGET steinwurf::verify)
  add_subdirectory("${STEINWURF_RESOLVE}/verify" verify EXCLUDE_FROM_ALL)
endif()

# expected dependency
if(NOT TARGET steinwurf::expected)
  add_subdirectory("${STEINWURF_RESOLVE}/expected" expected EXCLUDE_FROM_ALL)
endif()

get_property(steinwurf_object_libraries GLOBAL
  PROPERTY steinwurf::object_libraries)

# Define library
file(GLOB_RECURSE ouroboros_sources ./src/*.cpp)

# Is this the top-level steinwurf project?
if(${CMAKE_PROJECT_NAME} STREQUAL ${PROJECT_NAME})
  # Create static library
  add_library(ouroboros STATIC ${ouroboros_sources})

  # Install library
  install(
    FILES $<TARGET_FILE:ouroboros>
    DESTINATION lib
    COMPONENT library)
else()
  # Create object library
  add_library(ouroboros OBJECT ${ouroboros_sources})

  # Add this library to a global list of steinwurf object libraries
  set_property(GLOBAL APPEND PROPERTY steinwurf::object_libraries
    steinwurf::ouroboros)

  # Link object dependencies

endif()

# Link header only dependencies
target_link_libraries(ouroboros PRIVATE steinwurf::platform)
target_link_libraries(ouroboros PRIVATE steinwurf::verify)
target_link_libraries(ouroboros PRIVATE steinwurf::expected)

# Link POSIX shared memory library (rt) on Linux for shm_open/shm_unlink
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  target_link_libraries(ouroboros PUBLIC rt)
endif()

target_include_directories(ouroboros PUBLIC src)

# Make sure we compile with C++17 and do not use compiler-specific extensions
set_property(TARGET ouroboros PROPERTY CXX_STANDARD 17)
set_property(TARGET ouroboros PROPERTY CXX_EXTENSIONS OFF)

add_library(steinwurf::ouroboros ALIAS ouroboros)

# Is top level project?
if(${CMAKE_PROJECT_NAME} STREQUAL ${PROJECT_NAME})
  # CLI11 dependency is only for toplevel project when building apps
  enable_testing()

  # CLI11 dependency
  if(NOT TARGET CLI11::CLI11)
    add_subdirectory("${STEINWURF_RESOLVE}/cli11-source" cli11 EXCLUDE_FROM_ALL)
  endif()

  if(CMAKE_C_COMPILER_ID MATCHES "MSVC")
    # For Windows: Prevent overriding the parent project's compiler/linker
    # settings
    set(gtest_force_shared_crt
      ON
      CACHE BOOL "" FORCE)
  endif()

  # Google Test dependency
  add_subdirectory("${STEINWURF_RESOLVE}/gtest")

  # Define library
  file(GLOB_RECURSE ouroboros_test_sources test/**/*.cpp)
  list(APPEND ouroboros_test_sources test/ouroboros_tests.cpp)

  # Build test executable
  add_executable(ouroboros_tests ${ouroboros_test_sources})
  target_link_libraries(ouroboros_tests steinwurf::ouroboros)
  target_link_libraries(ouroboros_tests steinwurf::gtest)
  target_link_libraries(ouroboros_tests steinwurf::verify)
  target_link_libraries(ouroboros_tests steinwurf::expected)
  target_link_libraries(ouroboros_tests steinwurf::platform)

  # Make sure we compile with C++17 and do not use compiler-specific extensions
  set_property(TARGET ouroboros_tests PROPERTY CXX_STANDARD 17)
  set_property(TARGET ouroboros_tests PROPERTY CXX_EXTENSIONS OFF)

  add_test(ouroboros_tests ouroboros_tests)

  # Build shm_generator tool
  add_executable(ouroboros_shm_generator tools/shm_generator.cpp)
  target_link_libraries(ouroboros_shm_generator steinwurf::ouroboros)
  target_link_libraries(ouroboros_shm_generator steinwurf::platform)
  target_link_libraries(ouroboros_shm_generator CLI11::CLI11)
  target_link_libraries(ouroboros_shm_generator steinwurf::verify)
  target_link_libraries(ouroboros_shm_generator steinwurf::expected)
  target_include_directories(ouroboros_shm_generator PRIVATE
    "${STEINWURF_RESOLVE}/cli11-source")

  # Make sure we compile with C++17 and do not use compiler-specific extensions
  set_property(TARGET ouroboros_shm_generator PROPERTY CXX_STANDARD 17)
  set_property(TARGET ouroboros_shm_generator PROPERTY CXX_EXTENSIONS OFF)

  # Set output directory to bin/
  set_target_properties(ouroboros_shm_generator PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

  # Install executable
  install(TARGETS ouroboros_shm_generator
    RUNTIME DESTINATION bin
    COMPONENT tools)

  # Build shm_dumper tool
  add_executable(ouroboros_shm_dumper tools/shm_dumper.cpp)
  target_link_libraries(ouroboros_shm_dumper steinwurf::ouroboros)
  target_link_libraries(ouroboros_shm_dumper steinwurf::platform)
  target_link_libraries(ouroboros_shm_dumper CLI11::CLI11)
  target_link_libraries(ouroboros_shm_dumper steinwurf::verify)
  target_link_libraries(ouroboros_shm_dumper steinwurf::expected)
  target_include_directories(ouroboros_shm_dumper PRIVATE
    "${STEINWURF_RESOLVE}/cli11-source")

  # Make sure we compile with C++17 and do not use compiler-specific extensions
  set_property(TARGET ouroboros_shm_dumper PROPERTY CXX_STANDARD 17)
  set_property(TARGET ouroboros_shm_dumper PROPERTY CXX_EXTENSIONS OFF)

  # Set output directory to bin/
  set_target_properties(ouroboros_shm_dumper PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

  # Install executable
  install(TARGETS ouroboros_shm_dumper
    RUNTIME DESTINATION bin
    COMPONENT tools)

  # Include benchmark targets
  # Google Benchmark dependency
  set(BENCHMARK_ENABLE_TESTING
    OFF
    CACHE INTERNAL "Disable gbenchmark test" FORCE)

  if(NOT TARGET benchmark)
    add_subdirectory("${STEINWURF_RESOLVE}/gbenchmark-source")
  endif()

  add_subdirectory(benchmark)
endif()
