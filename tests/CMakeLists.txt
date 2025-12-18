set(BASIC_TESTS
    AutoResetInitialState
    AutoResetBasicTests
    ManualResetInitialState
    ManualResetBasicTests
    EventContention
)

set(WFMO_TESTS
    WaitTimeoutAllSignalled
)

# Use numeric C++ standard levels for CMake
set(TEST_STD 11)
if (WIN32)
    set(TEST_STD 17)
endif()

set(TEST_COMPILE_DEFS)
if(PEVENTS_WFMO)
    list(APPEND TEST_COMPILE_DEFS WFMO)
endif()
if(PEVENTS_PULSE)
    list(APPEND TEST_COMPILE_DEFS PULSE)
endif()

foreach(test_name IN LISTS BASIC_TESTS)
    add_executable(${test_name} ${test_name}.cpp)
    target_link_libraries(${test_name} PRIVATE pevents)
    target_include_directories(${test_name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)
    target_compile_definitions(${test_name} PRIVATE ${TEST_COMPILE_DEFS})
    set_target_properties(${test_name} PROPERTIES
        CXX_STANDARD ${TEST_STD}
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS OFF
    )
    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()

if(PEVENTS_WFMO)
    foreach(test_name IN LISTS WFMO_TESTS)
        add_executable(${test_name} ${test_name}.cpp)
        target_link_libraries(${test_name} PRIVATE pevents)
        target_include_directories(${test_name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)
        target_compile_definitions(${test_name} PRIVATE ${TEST_COMPILE_DEFS})
        set_target_properties(${test_name} PROPERTIES
            CXX_STANDARD ${TEST_STD}
            CXX_STANDARD_REQUIRED ON
            CXX_EXTENSIONS OFF
        )
        add_test(NAME ${test_name} COMMAND ${test_name})
    endforeach()
endif()
