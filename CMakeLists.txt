project(PTrace)
cmake_minimum_required(VERSION 2.8)

set(CMAKE_BUILD_TYPE "Release")

find_path(PIN_ROOT_DIR
  NAMES source/include/pin/pin.H
  PATHS $ENV{PIN_ROOT_DIR}
  DOC "Pin's base directory"
)

if(NOT PIN_ROOT_DIR)
  message(FATAL_ERROR
    "\nPin not found!\n"
    "Please set the environment variable PIN_ROOT_DIR to the base directory"
    " of the pin library.\n"
  )
endif(NOT PIN_ROOT_DIR)
message(STATUS "PIN_ROOT_DIR: ${PIN_ROOT_DIR}")

if(DEFINED ARCH)
  if (ARCH STREQUAL "intel64")
    set(PIN_CPU_ARCH "intel64")
    set(PIN_CPU_ARCH_LONG "intel64")
  else()
    set(PIN_CPU_ARCH "ia32")
    set(PIN_CPU_ARCH_LONG "ia32")
  endif()
else()
  set(PIN_CPU_ARCH "ia32")
  set(PIN_CPU_ARCH_LONG "ia32")
endif()

if (PIN_CPU_ARCH STREQUAL "intel64")
  message(STATUS "64 bit build")
else()
  message(STATUS "32 bit build")
endif()


set(PIN_INCLUDE_DIRS
  ${PIN_ROOT_DIR}/extras/xed-${PIN_CPU_ARCH_LONG}/include
  ${PIN_ROOT_DIR}/source/include/pin
  ${PIN_ROOT_DIR}/source/include/pin/gen
  ${PIN_ROOT_DIR}/extras/components/include
  ${LOCAL_INCLUDE_DIR})

set(PIN_LIBRARY_DIRS
  ${PIN_ROOT_DIR}/extras/xed-${PIN_CPU_ARCH_LONG}/lib
  ${PIN_ROOT_DIR}/${PIN_CPU_ARCH_LONG}/lib
  ${PIN_ROOT_DIR}/${PIN_CPU_ARCH_LONG}/lib-ext
  ${PIN_ROOT_DIR}/${PIN_CPU_ARCH_LONG}/runtime/pincrt)

#set(SOURCES
#  src/main.cpp
#  src/lib/cap/tracer.cpp
#  src/lib/cap/parser.cpp
#  src/lib/type/instruction.cpp
#  src/lib/type/trace.pb.cc)

# Pintool sources
set(PINTOOL_SRCS
  src/main.cpp
  src/lib/cap/tracer.cpp
  src/lib/cap/parser.cpp
  src/lib/type/instruction.cpp
  src/lib/type/trace_with_chunk.pb.cc)

if((DEFINED FAST) AND (FAST STREQUAL "Yes"))
  set(FAST_DEFS "/D FAST_TRACING")
  message(STATUS "Fast tracing is enabled")
else()
  set(FAST_DEFS "")
  message(STATUS "Fast tracing is disabled")
endif()

# ========================================= start host configuration

if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")

  if(NOT PROTOBUF_ROOT_DIR)
    message(FATAL_ERROR
      "\nProtobuf library not found!\n"
      "Please set the environment variable PROTOBUF_ROOT_DIR\n"
    )
  endif(NOT PROTOBUF_ROOT_DIR)
  message(STATUS "PROTOBUF_ROOT_DIR: ${PROTOBUF_ROOT_DIR}")

  set(PROTOBUF_LIB_DIRS ${PROTOBUF_ROOT_DIR}/lib)
  set(PROTOBUF_INCLUDE_DIRS ${PROTOBUF_ROOT_DIR}/include)

  set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMake/")

  set(PIN_DEFS "/D TARGET_IA32 /D HOST_IA32 /D TARGET_WINDOWS /D USING_XED /D_SECURE_SCL=0 /D_ITERATOR_DEBUG_LEVEL=0 /Zc:auto")
  set(LINKER_DEFS "/D _WINDLL /D _MBCS /GS- /MT /EHsc /Ox /O2 /Ob2 /nologo")
  set(PROTOBUF_DEFS "/D PROTOBUF_USE_DLLS")

  set(PIN_LIBRARY_DIRS
    ${PIN_ROOT_DIR}/extras/xed-${PIN_CPU_ARCH_LONG}/lib
    ${PIN_ROOT_DIR}/${PIN_CPU_ARCH_LONG}/lib
    ${PIN_ROOT_DIR}/${PIN_CPU_ARCH_LONG}/lib-ext)

  set(PIN_LIBS pin pinvm libxed ntdll-32 dbghelp)

  set(PROTOBUF_LIBS libprotobuf)

  set(OTHER_LIBS libcpmt libcmt)

  if(NOT DEFINED BOOST_ROOT_DIR)
    message(FATAL_ERROR "\nBoost not found!\n"
      "Please set the environment variable BOOST_ROOT_DIR to the base directory"
      " of the Boost library.\n")
  endif(NOT DEFINED BOOST_ROOT_DIR)
  message(STATUS "BOOST_ROOT_DIR: ${BOOST_ROOT_DIR}")

  set(INCLUDE_DIRS
    ${PIN_INCLUDE_DIRS}
    ${BOOST_ROOT_DIR})

  include_directories(${INCLUDE_DIRS} ${PROTOBUF_INCLUDE_DIRS})
  link_directories(${PIN_LIBRARY_DIRS} ${PROTOBUF_LIB_DIRS})

  add_definitions(${PIN_DEFS})
  add_definitions(${LINKER_DEFS})
  add_definitions(${PROTOBUF_DEFS})
  add_definitions(${FAST_DEFS})
#  add_definitions(${FUNC_DEFS})

  set(CMAKE_CXX_FLAGS "${FUNC_DEFS} ${OTHER_DEFS} ${PIN_DEFS}")
  set(CMAKE_SHARED_LINKER_FLAGS "/DLL /EXPORT:main /NODEFAULTLIB /MACHINE:x86 /ENTRY:Ptrace_DllMainCRTStartup@12 /BASE:0x55000000")

  add_library(vtrace SHARED ${PINTOOL_SRCS})
#  add_library(vtrace ${SOURCES})
  target_link_libraries(vtrace ${PIN_LIBS} ${OTHER_LIBS} ${PROTOBUF_LIBS})

else()

  set(PIN_DEFINITIONS "")
  if (PIN_CPU_ARCH STREQUAL "intel64")
    message(STATUS "Set 64 bit definitions")
    list(APPEND PIN_DEFINITIONS
      TARGET_LINUX
      BIGARRAY_MULTIPLIER=1
      USING_XED
      TARGET_IA32E HOST_IA32E)
  else()
    message(STATUS "Set 32 bit definitions")
    list(APPEND PIN_DEFINITIONS
      TARGET_LINUX
      BIGARRAY_MULTIPLIER=1
      USING_XED
      TARGET_IA32 HOST_IA32)
  endif()

#  add_custom_command(
#    OUTPUT  trace.pb.cc
#    COMMAND protoc --cpp_out ../src/lib/type/ -I ../proto/ ../proto/trace.proto
#    COMMENT "Launch protoc")

#  add_custom_target(run ALL
#    DEPENDS trace.pb.cc)

  set(PIN_VERSION_SCRIPT ${PIN_ROOT_DIR}/source/include/pin/pintool.ver)

  if (PIN_CPU_ARCH STREQUAL "intel64")
    set(PIN_COMPILE_FLAGS "-Wall -Wno-unknown-pragmas -std=c++11 -MMD -O3 -fomit-frame-pointer -fno-strict-aliasing -fno-stack-protector")
  else()
    set(PIN_COMPILE_FLAGS "-Wall -Wno-unknown-pragmas -std=c++11 -m32 -MMD -O3 -fomit-frame-pointer -fno-strict-aliasing -fno-stack-protector")
  endif()

  set(PIN_LINKER_FLAGS "-Wl,--hash-style=sysv -Wl,-Bsymbolic -Wl,--version-script=${PIN_VERSION_SCRIPT}")

  set(PIN_LINK_LIBS pin pinvm pinapp sapin xed pindwarf dwarf elf dl protobuf boost_system boost_filesystem)
  # set(PIN_LINK_LIBS pin sapin pin3dwarf c-dynamic dl-dynamic m-dynamic protobuf)

  link_directories(${PIN_LIBRARY_DIRS})
  include_directories(${PIN_INCLUDE_DIRS})

  # add Pintool
  add_library(vtrace SHARED ${PINTOOL_SRCS})

  # set compile and link flags
  set_source_files_properties(${PINTOOL_SRCS} PROPERTIES
    COMPILE_FLAGS "${PIN_COMPILE_FLAGS}"
    COMPILE_DEFINITIONS "${PIN_DEFINITIONS}")

  if (PIN_CPU_ARCH STREQUAL "intel64")
    set_target_properties(vtrace PROPERTIES
      PREFIX ""
      SUFFIX ".pin_m64"
      COMPILE_DEFINITIONS "${PIN_DEFINITIONS}"
      COMPILE_FLAGS "${PIN_COMPILE_FLAGS}"
      LINK_FLAGS "${PIN_LINKER_FLAGS} -v")
  else()
    set_target_properties(vtrace PROPERTIES
      PREFIX ""
      SUFFIX ".pin_m32"
      COMPILE_DEFINITIONS "${PIN_DEFINITIONS}"
      COMPILE_FLAGS "${PIN_COMPILE_FLAGS}"
      LINK_FLAGS "${PIN_LINKER_FLAGS} -v -m32")
  endif()

  target_link_libraries(vtrace ${PIN_LINK_LIBS})
endif()

