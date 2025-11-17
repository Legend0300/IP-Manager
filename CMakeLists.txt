cmake_minimum_required(VERSION 3.15)
project(AppGate)
set(CMAKE_CXX_STANDARD 17)

# Add compile definitions to prevent winsock conflicts
add_compile_definitions(_WINSOCK_DEPRECATED_NO_WARNINGS WIN32_LEAN_AND_MEAN)

add_executable(AppGate
    main.cpp
    FirewallManager.cpp
    Utils.cpp
)
# Link Windows libs
target_link_libraries(AppGate
    ws2_32 iphlpapi fwpuclnt psapi shlwapi shell32 ole32 version
)
