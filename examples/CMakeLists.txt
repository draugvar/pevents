add_executable(sample sample.cpp)

set_target_properties(sample PROPERTIES
    CXX_STANDARD 11
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
)

target_link_libraries(sample PRIVATE pevents)
target_compile_definitions(sample PRIVATE $<$<BOOL:${PEVENTS_WFMO}>:WFMO> $<$<BOOL:${PEVENTS_PULSE}>:PULSE>)
target_include_directories(sample PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)

