cmake_minimum_required(VERSION 3.14)

project(ArduinoDesktopServer 
    VERSION 1.0.0
    LANGUAGES CXX
)

# Set C++17 standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Include FetchContent for downloading external dependencies
include(FetchContent)

# Fetch the arduionolibserver library from GitHub
FetchContent_Declare(
    arduionolibserver
    GIT_REPOSITORY https://github.com/compilerNayan/arduionolibserver.git
    GIT_TAG main
)

# Make the library available
FetchContent_MakeAvailable(arduionolibserver)

# Optional: If you want to create your own library or executable
# Uncomment and modify the following lines as needed:

# add_library(${PROJECT_NAME} 
#     # Add your source files here
#     # src/your_source.cpp
# )

# # Link against the included library
# target_link_libraries(${PROJECT_NAME} 
#     PRIVATE 
#     # Link to the arduionolibserver library targets here
#     # The exact target name depends on the library's CMakeLists.txt
# )

# # Include directories
# target_include_directories(${PROJECT_NAME}
#     PUBLIC
#     # Add your include directories here
#     # include
# )

