cmake_minimum_required(VERSION 3.8)
project(KClient)

set(CMAKE_CXX_STANDARD 11)
include_directories(/usr/local/include/FHESI)
include_directories(/usr/local/include/NTL)
set(SOURCE_FILES main.cpp clientfhesiutils.cpp clientfhesiutils.h KClient.cpp KClient.h KClientV1.cpp KClientV1.h )
add_executable(KClient ${SOURCE_FILES})
target_link_libraries(KClient libfhesi.a libntl.a libgmp.a libm.a)