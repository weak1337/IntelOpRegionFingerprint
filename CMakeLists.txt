cmake_minimum_required(VERSION 3.20)

project(IntelOpRegionFingerprint LANGUAGES C CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}")
set(WDK_WINVER "0x0A00" CACHE STRING "" FORCE)
find_package(WDK REQUIRED)

wdk_add_driver(IntelOpRegionFingerprint
    src/Driver.cpp
)

target_include_directories(IntelOpRegionFingerprint PRIVATE src)
target_link_libraries(IntelOpRegionFingerprint WDK::CNG)

find_program(SIGNTOOL_EXE
    NAMES signtool
    PATHS
        "${WDK_ROOT}/bin/${WDK_VERSION}/x64"
        "${WDK_ROOT}/bin/x64"
    NO_DEFAULT_PATH
)

if(NOT SIGNTOOL_EXE)
    message(WARNING "signtool not found under ${WDK_ROOT}/bin — driver will not be test-signed")
else()
    message(STATUS "signtool: ${SIGNTOOL_EXE}")
    add_custom_command(TARGET IntelOpRegionFingerprint POST_BUILD
        COMMAND powershell.exe -NoProfile -ExecutionPolicy Bypass
            -File "${CMAKE_CURRENT_SOURCE_DIR}/scripts/sign.ps1"
            -Signtool "${SIGNTOOL_EXE}"
            -File     "$<TARGET_FILE:IntelOpRegionFingerprint>"
            -PfxPath  "${CMAKE_CURRENT_SOURCE_DIR}/IntelOpRegionFingerprint.pfx"
        COMMENT "Test-signing IntelOpRegionFingerprint.sys"
        VERBATIM
    )
endif()
