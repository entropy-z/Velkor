cmake_minimum_required(VERSION 3.27)

# Project name
project( Template )

# Set architecture and compiler based on ARCH variable
if( ARCH STREQUAL "64")
    set( CMAKE_CXX_COMPILER "x86_64-w64-mingw32-g++" )
    set( NASM_FLAGS "-f win64" )
elseif( ARCH STREQUAL "86" )
    set( CMAKE_CXX_COMPILER "i686-w64-mingw32-g++" )
    set( NASM_FLAGS "-f win32" )
endif()

# Set output directory
set( OUTPUT_DIR "${CMAKE_SOURCE_DIR}/Bin" )
set( CMAKE_RUNTIME_OUTPUT_DIRECTORY ${OUTPUT_DIR} )

# Set NASM source and output
set( NASM_SRC "${CMAKE_SOURCE_DIR}/Source/Asm/Entry.x${ARCH}.asm" )
set( NASM_OUTPUT "${OUTPUT_DIR}/asm_${PROJECT_NAME}.x${ARCH}.o" )

# Include directory
include_directories( ${CMAKE_SOURCE_DIR}/Include )

# Linker script
set( LINKER_SCRIPT "${CMAKE_SOURCE_DIR}/Linker.ld" )

# C++ Compiler Flags
set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -masm=intel -fpermissive -mrdrnd" )
set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-ident -fpack-struct=8 -falign-functions=1" )
set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -s -ffunction-sections -falign-jumps=1 -w" )
set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -falign-labels=1 -fPIC -nostdlib" )
set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Os -fno-asynchronous-unwind-tables" )

# Collect source files
file( GLOB POSTEX_SRC  "${CMAKE_SOURCE_DIR}/Source/*.cc" )

# Generate object file from assembly
add_custom_command(
    OUTPUT ${NASM_OUTPUT}
    COMMAND nasm ${NASM_FLAGS} ${NASM_SRC} -o ${NASM_OUTPUT}
    DEPENDS ${NASM_SRC}
    COMMENT "Compiling assembly: ${NASM_SRC}"
)

# Create executable
add_executable( ${PROJECT_NAME}.x${ARCH}.exe
    ${POSTEX_SRC}
    ${NASM_OUTPUT}
)

# Apply specific compilation flags to the target
target_compile_options( ${PROJECT_NAME}.x${ARCH}.exe PRIVATE
    -masm=intel
    -fpermissive
    -mrdrnd
    -fno-ident
    -fpack-struct=8
    -falign-functions=1
    -s
    -ffunction-sections
    -falign-jumps=1
    -w
    -falign-labels=1
    -fPIC
    -nostdlib
    -Os
    -fno-asynchronous-unwind-tables
)

# Linker options
target_link_options( ${PROJECT_NAME}.x${ARCH}.exe PRIVATE
    -Wl,-s,--no-seh,--enable-stdcall-fixup
)

# Set linker script
set_target_properties( ${PROJECT_NAME}.x${ARCH}.exe PROPERTIES
    LINK_FLAGS "-T ${LINKER_SCRIPT}"
)