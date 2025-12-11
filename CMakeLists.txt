cmake_minimum_required(VERSION 3.22)

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
set(THIS_PROJECT_NAME "ossp")

project(${THIS_PROJECT_NAME} LANGUAGES C CXX)

file(GLOB_RECURSE SRC CONFIGURE_DEPENDS src/*.cpp)

include_directories(include)

add_library(${THIS_PROJECT_NAME} STATIC ${SRC})

set_property(TARGET ${THIS_PROJECT_NAME} PROPERTY CXX_STANDARD 17)

set_target_properties(${THIS_PROJECT_NAME} PROPERTIES OUTPUT_NAME "ossp")

include(FetchContent)
FetchContent_Declare(
        byte-buffer
        GIT_REPOSITORY https://github.com/Lyniat/Byte-Buffer
        GIT_TAG        45e8918b6961f1b0b124325e910b215ea3da01f3)

FetchContent_MakeAvailable(byte-buffer)

target_link_libraries(${THIS_PROJECT_NAME} PUBLIC byte-buffer)

if (WIN32)
    if(MSVC)
        # ?
    else()
        target_compile_options(${THIS_PROJECT_NAME} PUBLIC -fPIC -fno-rtti -fno-exceptions -Wno-deprecated-enum-enum-conversion)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++20")
        #target_link_options(${THIS_PROJECT_NAME} PUBLIC -static-libgcc -static-libstdc++) #needed?
    endif()
elseif (APPLE)
    target_compile_options(${THIS_PROJECT_NAME} PUBLIC -fPIC -fno-rtti -fno-exceptions)
elseif (UNIX)
    target_compile_options(${THIS_PROJECT_NAME} PUBLIC -fPIC -fno-rtti -fno-exceptions)
endif ()

if(MSVC)
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /Od")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2 /MT")
else()
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3")
endif()
# set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE} -g -fno-eliminate-unused-debug-symbols")

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

# https://discourse.cmake.org/t/installing-headers-the-modern-way-regurgitated-and-revisited/3238/3
target_sources(${THIS_PROJECT_NAME} PUBLIC
        FILE_SET public_headers
        TYPE HEADERS
        BASE_DIRS include
        FILES
        include/ossp/api.h
        include/ossp/help.h
        include/ossp/serialize.h
)

install(TARGETS ${THIS_PROJECT_NAME} FILE_SET public_headers)

include(CTest)

add_executable(test_ossp_deep_diff test/test_ossp_deep_diff.cpp)
set_property(TARGET test_ossp_deep_diff PROPERTY CXX_STANDARD 17)
target_link_directories(test_ossp_deep_diff PRIVATE lib)
target_link_libraries(test_ossp_deep_diff ${THIS_PROJECT_NAME} mruby)
add_test(NAME "Test OSSP deep diff"
        COMMAND test_ossp_deep_diff)

