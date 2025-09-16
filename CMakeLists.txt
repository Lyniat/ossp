cmake_minimum_required(VERSION 3.22)

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
set(THIS_PROJECT_NAME "ossp")

project(${THIS_PROJECT_NAME} LANGUAGES C CXX)

file(GLOB_RECURSE SRC CONFIGURE_DEPENDS src/*.cpp)

include_directories(
        include
)

add_library(${THIS_PROJECT_NAME} STATIC ${SRC})

set_property(TARGET ${THIS_PROJECT_NAME} PROPERTY CXX_STANDARD 17)

set_target_properties(${THIS_PROJECT_NAME} PROPERTIES OUTPUT_NAME "ossp")

include(FetchContent)

FetchContent_Declare(
        fmt
        GIT_REPOSITORY https://github.com/fmtlib/fmt
        GIT_TAG        e69e5f977d458f2650bb346dadf2ad30c5320281) # 10.2.1

FetchContent_MakeAvailable(fmt)

target_compile_options(fmt PUBLIC -fPIC -fno-rtti)

target_link_libraries(${THIS_PROJECT_NAME}
        PRIVATE
        fmt
)

# -static-libgcc -static-libstdc++ SUPER IMPORTANT!
# ucrt -std=c++20 -Wno-deprecated-enum-enum-conversion
target_compile_definitions(${THIS_PROJECT_NAME} PUBLIC XXH_INLINE_ALL)

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
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_definitions(-DMETA_TYPE="Release")
elseif(CMAKE_BUILD_TYPE STREQUAL "Debug")
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
        include/ossp/buffer.h
        include/ossp/help.h
        include/ossp/serialize.h
)

install(TARGETS ${THIS_PROJECT_NAME} FILE_SET public_headers)
