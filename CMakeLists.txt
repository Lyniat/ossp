cmake_minimum_required(VERSION 3.22)

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

project(ossp LANGUAGES C CXX)

file(GLOB_RECURSE SRC CONFIGURE_DEPENDS src/*.cpp)

include_directories(include)

if(MSVC)
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /Od")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2")
else()
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3")
endif()

# build type
if(${CMAKE_BUILD_TYPE} STREQUAL "Release")
    add_definitions(-DMETA_TYPE="Release")
elseif(${CMAKE_BUILD_TYPE} STREQUAL "Debug")
    add_definitions(-DMETA_TYPE="Debug")
    add_definitions(-DDEBUG)
else()
    add_definitions(-DMETA_TYPE="Other")
endif()

set(CMAKE_SKIP_RPATH ON)

# OSSP STANDALONE
add_library(ossp STATIC ${SRC})
set_target_properties(ossp PROPERTIES CXX_STANDARD 17 OUTPUT_NAME "ossp")

include(FetchContent)
FetchContent_Declare(
        byte-buffer
        GIT_REPOSITORY https://github.com/Lyniat/Byte-Buffer
        GIT_TAG        0470ff516a1929075dc1471be8aaad95262bf67e)
FetchContent_MakeAvailable(byte-buffer)

target_link_libraries(ossp PUBLIC byte-buffer)

if (WIN32)
    if(NOT MSVC)
        target_compile_options(ossp PUBLIC -fPIC -fno-rtti -fno-exceptions -Wno-deprecated-enum-enum-conversion)
    endif()
elseif (APPLE)
    target_compile_options(ossp PUBLIC -fPIC -fno-rtti -fno-exceptions)
elseif (UNIX)
    target_compile_options(ossp PUBLIC -fPIC -fno-rtti -fno-exceptions)
endif ()

# https://discourse.cmake.org/t/installing-headers-the-modern-way-regurgitated-and-revisited/3238/3
target_sources(ossp PUBLIC
        FILE_SET public_headers
        TYPE HEADERS
        BASE_DIRS include
        FILES
        include/ossp/api.h
        include/ossp/help.h
        include/ossp/serialize.h
)

install(TARGETS ossp FILE_SET public_headers)

# OSSP DRGTK
option(BUILD_DRGTK "Build DRGTK" OFF)
if(BUILD_DRGTK)
    add_library(ossp_drgtk STATIC ${SRC})
    set_target_properties(ossp_drgtk PROPERTIES CXX_STANDARD 17 OUTPUT_NAME "ossp_drgtk")
    target_link_libraries(ossp_drgtk PUBLIC byte-buffer)
    if (WIN32)
        if(NOT MSVC)
            target_compile_options(ossp_drgtk PUBLIC -fPIC -fno-rtti -fno-exceptions -Wno-deprecated-enum-enum-conversion)
        endif()
    elseif (APPLE)
        target_compile_options(ossp_drgtk PUBLIC -fPIC -fno-rtti -fno-exceptions)
    elseif (UNIX)
        target_compile_options(ossp_drgtk PUBLIC -fPIC -fno-rtti -fno-exceptions)
    endif ()

    target_sources(ossp_drgtk PUBLIC
            FILE_SET public_headers
            TYPE HEADERS
            BASE_DIRS include
            FILES
            include/ossp/api.h
            include/ossp/help.h
            include/ossp/serialize.h
    )
    install(TARGETS ossp_drgtk FILE_SET public_headers)
endif ()

option(BUILD_TESTING "Build Tests" ON)
if (BUILD_TESTING)
    enable_testing()

    add_executable(test_ossp_01 test/test_ossp_01.cpp)
    set_property(TARGET test_ossp_01 PROPERTY CXX_STANDARD 17)
    target_link_directories(test_ossp_01 PRIVATE test/lib)
    if(USE_DRGTK)
        target_link_libraries(test_ossp_01 ossp_drgtk)
    else()
        target_link_libraries(test_ossp_01 ossp mruby)
    endif ()
    add_test(NAME "Test OSSP 1"
            COMMAND test_ossp_01)

    add_executable(test_ossp_02 test/test_ossp_02.cpp)
    set_property(TARGET test_ossp_02 PROPERTY CXX_STANDARD 17)
    target_link_directories(test_ossp_02 PRIVATE test/lib)
    if(USE_DRGTK)
        target_link_libraries(test_ossp_02 ossp_drgtk)
    else()
        target_link_libraries(test_ossp_02 ossp mruby)
    endif ()
    add_test(NAME "Test OSSP 2"
            COMMAND test_ossp_02)

    add_executable(test_ossp_03 test/test_ossp_03.cpp)
    set_property(TARGET test_ossp_03 PROPERTY CXX_STANDARD 17)
    target_link_directories(test_ossp_03 PRIVATE test/lib)
    if(USE_DRGTK)
        target_link_libraries(test_ossp_03 ossp_drgtk)
    else()
        target_link_libraries(test_ossp_03 ossp mruby)
    endif ()
    add_test(NAME "Test OSSP 3"
            COMMAND test_ossp_03)

    add_executable(test_ossp_04 test/test_ossp_04.cpp)
    set_property(TARGET test_ossp_04 PROPERTY CXX_STANDARD 17)
    target_link_directories(test_ossp_04 PRIVATE test/lib)
    if(USE_DRGTK)
        target_link_libraries(test_ossp_04 ossp_drgtk)
    else()
        target_link_libraries(test_ossp_04 ossp mruby)
    endif ()
    add_test(NAME "Test OSSP 4"
            COMMAND test_ossp_04)
endif ()