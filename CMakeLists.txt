cmake_minimum_required(VERSION 3.24)
project(PcapAnalyze)

set(CMAKE_CXX_STANDARD 17)
link_libraries(ws2_32 wsock32)
add_executable(PcapAnalyze main.cpp pcapanalyze.h )
