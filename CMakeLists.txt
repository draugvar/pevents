cmake_minimum_required(VERSION 3.15)

project(pevents VERSION 1.0 LANGUAGES CXX)

option(PEVENTS_WFMO "Enable WFMO events" ON)
option(PEVENTS_PULSE "Enable PulseEvent()" OFF)
option(PEVENTS_BUILD_EXAMPLES "Build example programs" ON)
option(PEVENTS_BUILD_TESTS "Build unit tests" ON)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(Threads REQUIRED)

set(pevents_sources src/pevents.cpp)

add_library(pevents STATIC ${pevents_sources})
target_include_directories(pevents
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

set_target_properties(pevents PROPERTIES
    CXX_STANDARD 11
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
)

target_link_libraries(pevents
    PUBLIC
        Threads::Threads
)

target_compile_definitions(pevents
    PUBLIC
        $<$<BOOL:${PEVENTS_WFMO}>:WFMO>
        $<$<BOOL:${PEVENTS_PULSE}>:PULSE>
)

# Generate single-header amalgamation similar to meson target
set(PEVENTS_SINGLE_HEADER "${CMAKE_CURRENT_BINARY_DIR}/pevents.hpp")
add_custom_command(
    OUTPUT ${PEVENTS_SINGLE_HEADER}
    COMMAND ${CMAKE_COMMAND}
        -DINPUTS="${CMAKE_CURRENT_SOURCE_DIR}/src/pevents.h;${CMAKE_CURRENT_SOURCE_DIR}/${pevents_sources}"
        -DOUTPUT="${PEVENTS_SINGLE_HEADER}"
        -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/pevents_single_header.cmake"
    DEPENDS ${pevents_sources} src/pevents.h cmake/pevents_single_header.cmake
    COMMENT "Generating pevents.hpp single-header"
    VERBATIM
)
add_custom_target(pevents_single_header ALL DEPENDS ${PEVENTS_SINGLE_HEADER})
add_dependencies(pevents pevents_single_header)

# Installation targets
install(TARGETS pevents EXPORT peventsTargets)
install(FILES src/pevents.h ${PEVENTS_SINGLE_HEADER} DESTINATION include)
install(EXPORT peventsTargets FILE peventsTargets.cmake NAMESPACE pevents:: DESTINATION lib/cmake/pevents)

include(CMakePackageConfigHelpers)
configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/peventsConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/peventsConfig.cmake
    INSTALL_DESTINATION lib/cmake/pevents
)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/peventsConfig.cmake DESTINATION lib/cmake/pevents)

if(PEVENTS_BUILD_EXAMPLES AND PEVENTS_WFMO)
    add_subdirectory(examples)
endif()

if(PEVENTS_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

