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
# Use BUILD/INSTALL interface include dirs to avoid exporting source-prefixed paths
target_include_directories(pevents
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
        $<INSTALL_INTERFACE:include>
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

# Installation targets
install(TARGETS pevents EXPORT peventsTargets)
install(FILES src/pevents.h ${PEVENTS_SINGLE_HEADER} DESTINATION include)
install(EXPORT peventsTargets FILE peventsTargets.cmake NAMESPACE pevents:: DESTINATION lib/cmake/pevents)

if(PEVENTS_BUILD_EXAMPLES AND PEVENTS_WFMO)
    add_subdirectory(examples)
endif()

if(PEVENTS_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

