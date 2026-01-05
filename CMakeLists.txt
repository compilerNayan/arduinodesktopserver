cmake_minimum_required(VERSION 3.14)

project(server-posix 
    VERSION 1.0.0
    LANGUAGES CXX
)

# Set C++17 standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Fetch dependencies
include(FetchContent)

# Fetch the serverlib library from GitHub
FetchContent_Declare(
    serverlib
    GIT_REPOSITORY https://github.com/compilerNayan/arduionolibserver.git
    GIT_TAG main
)

# Make the library available
FetchContent_MakeAvailable(serverlib)

# Create header-only library (INTERFACE library)
# Note: CMake target names cannot have hyphens, so we use server_posix
add_library(server_posix INTERFACE)

# Set target properties
set_target_properties(server_posix PROPERTIES
    VERSION ${PROJECT_VERSION}
)

# Set include directories
target_include_directories(server_posix INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# Add serverlib include directory
# Use BUILD_INTERFACE generator expression to properly handle FetchContent paths
FetchContent_GetProperties(serverlib)
if(serverlib_SOURCE_DIR)
    target_include_directories(server_posix INTERFACE
        $<BUILD_INTERFACE:${serverlib_SOURCE_DIR}/include>
    )
endif()

# Link to serverlib if it provides a target
# Try to find and link the library target if it exists
if(TARGET serverlib)
    target_link_libraries(server_posix INTERFACE serverlib)
elseif(TARGET serverlib::serverlib)
    target_link_libraries(server_posix INTERFACE serverlib::serverlib)
else()
    # If no target exists, the include directories above should be sufficient
    # for header-only dependencies
endif()

# Note: For INTERFACE libraries, we don't need to add header files to target_sources
# The include directories are sufficient for consumers to find the headers

# Optional: Set up installation
include(GNUInstallDirs)

install(TARGETS server_posix
    EXPORT server_posixTargets
)

install(FILES include/HttpTcpServer.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(EXPORT server_posixTargets
    FILE server_posixTargets.cmake
    NAMESPACE server_posix::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/server-posix
)

