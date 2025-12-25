cmake_minimum_required(VERSION 3.14)

project(ArduinoDesktopServer 
    VERSION 1.0.0
    LANGUAGES CXX
)

# Set C++17 standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Fetch dependencies
include(FetchContent)

# Fetch the arduionolibserver library from GitHub
FetchContent_Declare(
    arduionolibserver
    GIT_REPOSITORY https://github.com/compilerNayan/arduionolibserver.git
    GIT_TAG main
)

# Make the library available
FetchContent_MakeAvailable(arduionolibserver)

# Create header-only library (INTERFACE library)
add_library(ArduinoDesktopServer INTERFACE)

# Set target properties
set_target_properties(ArduinoDesktopServer PROPERTIES
    VERSION ${PROJECT_VERSION}
)

# Set include directories
target_include_directories(ArduinoDesktopServer INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# Add arduionolibserver include directory
# Use BUILD_INTERFACE generator expression to properly handle FetchContent paths
FetchContent_GetProperties(arduionolibserver)
if(arduionolibserver_SOURCE_DIR)
    target_include_directories(ArduinoDesktopServer INTERFACE
        $<BUILD_INTERFACE:${arduionolibserver_SOURCE_DIR}/include>
    )
endif()

# Link to arduionolibserver if it provides a target
# Try to find and link the library target if it exists
if(TARGET arduionolibserver)
    target_link_libraries(ArduinoDesktopServer INTERFACE arduionolibserver)
else()
    # If no target exists, the include directories above should be sufficient
    # for header-only dependencies
endif()

# Note: For INTERFACE libraries, we don't need to add header files to target_sources
# The include directories are sufficient for consumers to find the headers

# Optional: Set up installation
include(GNUInstallDirs)

install(TARGETS ArduinoDesktopServer
    EXPORT ArduinoDesktopServerTargets
)

install(FILES include/HttpTcpServer.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(EXPORT ArduinoDesktopServerTargets
    FILE ArduinoDesktopServerTargets.cmake
    NAMESPACE ArduinoDesktopServer::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ArduinoDesktopServer
)

