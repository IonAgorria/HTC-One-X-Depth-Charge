cmake_minimum_required(VERSION 3.11)
set(CMAKE_C_STANDARD 11)

include(FetchContent)

message("-- Fetching tinyusb")
FetchContent_Declare(tinyusb
        GIT_REPOSITORY    https://github.com/hathach/tinyusb
        GIT_TAG           0bfb9d62de3a13b685437b503e2170550662bb96
        #GIT_SHALLOW       ON
)
FetchContent_MakeAvailable(tinyusb)
include_directories("${tinyusb_SOURCE_DIR}/")
message("-- Tinyusb fetched")

include(${tinyusb_SOURCE_DIR}/hw/bsp/family_support.cmake)

# gets PROJECT name for the example (e.g. <BOARD>-<DIR_NAME>)
family_get_project_name(PROJECT depthcharge)

project(${PROJECT})

# Checks this example is valid for the family and initializes the project
family_initialize_project(${PROJECT} ${CMAKE_CURRENT_LIST_DIR})

add_executable(${PROJECT})

target_sources(${PROJECT} PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src/main.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/msc_disk.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/usb_descriptors.c
)

target_include_directories(${PROJECT} PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Configure compilation flags and libraries for the example... see the corresponding function
# in hw/bsp/FAMILY/family.cmake for details.
family_configure_device_example(${PROJECT})