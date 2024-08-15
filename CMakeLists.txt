cmake_minimum_required(VERSION 3.21)
include(FetchContent)
# get capstone
FetchContent_Declare(
  capstone
  GIT_REPOSITORY https://github.com/AngelDev06/capstone
  GIT_TAG da74b9a3
  GIT_SUBMODULES "")

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
  message(
    FATAL_ERROR
      "In-tree builds are not supported. Run CMake from a separate directory: cmake -B build"
  )
endif()

set(ALTERHOOK_TOP_LEVEL OFF)
if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
  set(ALTERHOOK_TOP_LEVEL ON)
endif()

project(AlterHook VERSION 0.0)

# Enable Hot Reload for MSVC compilers if supported.
if(POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT
      "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>"
  )
endif()

string(
  CONCAT
    ALWAYS_RELAY_NOTE
    "On x64 builds it instructs the library to always use the relay function strategy "
    "regardless of the size of the target function "
    "(meaning it won't place a big jump on the target even if it fits)."
    "Gets ignored for other archs.")

string(
  CONCAT
    NO_NEARBY_ALLOCATIONS_NOTE
    "Disables all attempts of allocating the trampoline function close to the target one "
    "(it is ignored on x64 & x86, both default to false regardless).")

option(ALTERHOOK_SHARED "Use shared version of AlterHook")
option(ALTERHOOK_TARGET_ARCH "Specifies the target architecture to use")
option(ALTERHOOK_BUILD_TESTS
       "Determines whether to build the tests on folder 'tests/'"
       ${ALTERHOOK_TOP_LEVEL})
option(ALTERHOOK_ALWAYS_USE_RELAY "${ALWAYS_RELAY_NOTE}")
option(ALTERHOOK_NO_NEARBY_ALLOCATIONS "${NO_NEARBY_ALLOCATIONS_NOTE}")
set_property(CACHE ALTERHOOK_TARGET_ARCH PROPERTY STRINGS "X86" "ARM" "AArch64")

# Loops that register the api headers, utilities and implementation source files
# (excluding architecture specific stuff)
foreach(
  HEADER
  "calling_conventions"
  "concepts"
  "function_traits"
  "other"
  "static_vector"
  "type_sequence"
  "utils"
  "macros"
  "properties"
  "data_processing"
  "boilerplate"
  "type_name"
  "index_sequence")
  list(APPEND ALTERHOOK_UTILITIES "include/alterhook/utilities/${HEADER}.hpp")
endforeach()

set(ALTERHOOK_API "include/alterhook.hpp")
foreach(
  ITEM
  "addresser"
  "exceptions"
  "tools"
  "trampoline"
  "hook"
  "hook_chain"
  "hook_map"
  "modifier")
  list(APPEND ALTERHOOK_API "include/alterhook/${ITEM}.hpp")
  if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/${ITEM}.cpp")
    list(APPEND ALTERHOOK_IMPL "src/${ITEM}.cpp")
  endif()
endforeach()

foreach(HEADER "macros" "constants")
  list(APPEND ALTERHOOK_DETAILS "include/alterhook/detail/${HEADER}.hpp")
endforeach()

foreach(ITEM "buffer" "disassembler" "injection")
  list(APPEND ALTERHOOK_IMPL "src/${ITEM}.hpp")
  if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/${ITEM}.cpp")
    list(APPEND ALTERHOOK_IMPL "src/${ITEM}.cpp")
  endif()
endforeach()

foreach(SRC "misc")
  list(APPEND ALTERHOOK_IMPL "src/${SRC}.cpp")
endforeach()

# get target arch from the option or try to detect it otherwise
get_property(
  ALTERHOOK_TARGET_ARCHS
  CACHE ALTERHOOK_TARGET_ARCH
  PROPERTY STRINGS)
if(NOT ALTERHOOK_TARGET_ARCH IN_LIST ALTERHOOK_TARGET_ARCHS)
  string(CONCAT ALTERHOOK_INVALID_ARCH_OUTPUT
                "ALTERHOOK_TARGET_ARCH is invalid, "
                "determining the target architecture from the preprocessor")
  message(STATUS "${ALTERHOOK_INVALID_ARCH_OUTPUT}")
  list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/scripts")
  include(TargetArch)
  target_architecture(arch)

  if(arch MATCHES "x86|x64")
    set(ALTERHOOK_TARGET_ARCH "X86")
    message(STATUS "Auto-detected x86 target architecture")
  elseif(arch STREQUAL "armv7")
    set(ALTERHOOK_TARGET_ARCH "ARM")
    message(STATUS "Auto-detected armv7 target architecture")
  elseif(arch STREQUAL "aarch64")
    set(ALTERHOOK_TARGET_ARCH "AArch64")
    message(STATUS "Auto-detected aarch64 target architecture")
  else()
    string(
      CONCAT
        ERROR_OUTPUT
        "Failed to auto-detect 'ALTERHOOK_TARGET_ARCH=${ALTERHOOK_TARGET_ARCH}', "
        "consider specifying one of: X86, ARM, AArch64")
    message(FATAL_ERROR "${ERROR_OUTPUT}")
  endif()
endif()

set(CAPSTONE_ARCHITECTURE_DEFAULT
    OFF
    CACHE BOOL "Whether architectures are enabled by default" FORCE)
if(ALTERHOOK_TARGET_ARCH STREQUAL "X86")
  set(CAPSTONE_X86_SUPPORT
      ON
      CACHE BOOL "x86 support" FORCE)
  message(STATUS "Enabling alterhook x86 support")
elseif(ALTERHOOK_TARGET_ARCH STREQUAL "AArch64")
  set(CAPSTONE_AARCH64_SUPPORT
      ON
      CACHE BOOL "AARCH64 support" FORCE)
  message(STATUS "Enabling alterhook aarch64 support")
else()
  set(CAPSTONE_ARM_SUPPORT
      ON
      CACHE BOOL "ARM support" FORCE)
  message(STATUS "Enabling alterhook armv7 support")
  list(APPEND ALTERHOOK_ARCH_IMPL "src/ARM/exceptions.cpp")
endif()

# register loops for architecture specific source files
foreach(HEADER "instructions")
  list(APPEND ALTERHOOK_ARCH_IMPL "src/${ALTERHOOK_TARGET_ARCH}/${HEADER}.hpp")
endforeach()

foreach(SRC "trampoline" "injection" "thread_processing")
  file(
    GLOB shared_cpp
    LIST_DIRECTORIES false
    "src/*${ALTERHOOK_TARGET_ARCH}*/${SRC}.cpp")
  list(LENGTH shared_cpp file_count)
  if(NOT file_count EQUAL 1)
    message(
      FATAL_ERROR "architecture-specific source file `${SRC}.cpp` was not found"
    )
  endif()
  list(APPEND ALTERHOOK_ARCH_IMPL "${shared_cpp}")
endforeach()

if(ALTERHOOK_ALWAYS_USE_RELAY AND NOT ALTERHOOK_TARGET_ARCH STREQUAL "X86")
  message(
    WARNING "ALTERHOOK_ALWAYS_USE_RELAY is ignored for non x86/x64 builds")
  set(ALTERHOOK_ALWAYS_USE_RELAY OFF)
endif()

if(WIN32)
  set(OS_STR "windows")
else()
  set(OS_STR "linux")
endif()

# register loops for os specific source files
foreach(HEADER "thread_handler")
  list(APPEND ALTERHOOK_OS_IMPL "src/${OS_STR}/${HEADER}.hpp")
endforeach()

foreach(SRC "other" "allocation" "freezer" "exceptions")
  list(APPEND ALTERHOOK_OS_IMPL "src/${OS_STR}/${SRC}.cpp")
endforeach()

# pch file
set(ALTERHOOK_PCH "pch/${OS_STR}/pch.hpp")

# setup capstone
string(CONCAT GNU_WARNINGS_ONLY $<OR: $<CXX_COMPILER_ID:Clang>,
              $<NOT:$<BOOL:${MSVC}>> >)

FetchContent_MakeAvailable(capstone)
target_compile_options(
  capstone PRIVATE $<$<BOOL:${MSVC}>:/wd4715>
                   $<${GNU_WARNINGS_ONLY}:-Wno-return-type>)

set(ALTERHOOK_PROJECT_FILES
    ${ALTERHOOK_UTILITIES} ${ALTERHOOK_API} ${ALTERHOOK_DETAILS}
    ${ALTERHOOK_IMPL} ${ALTERHOOK_ARCH_IMPL} ${ALTERHOOK_OS_IMPL})

if(ALTERHOOK_SHARED)
  add_library(AlterHook SHARED ${ALTERHOOK_PROJECT_FILES})
  set_target_properties(capstone PROPERTIES POSITION_INDEPENDENT_CODE ON)
else()
  add_library(AlterHook STATIC ${ALTERHOOK_PROJECT_FILES})
endif()

target_compile_definitions(
  AlterHook
  PUBLIC $<$<CONFIG:Debug>:_GLIBCXX_DEBUG>
         $<$<BOOL:${ALTERHOOK_SHARED}>:ALTERHOOK_SHARED>
  PRIVATE
    $<$<BOOL:${ALTERHOOK_SHARED}>:ALTERHOOK_EXPORT>
    $<$<BOOL:${ALTERHOOK_ALWAYS_USE_RELAY}>:ALTERHOOK_ALWAYS_USE_RELAY>
    $<$<BOOL:${ALTERHOOK_NO_NEARBY_ALLOCATIONS}>:ALTERHOOK_NO_NEARBY_ALLOCATIONS>
)

target_include_directories(
  AlterHook
  PUBLIC "${PROJECT_SOURCE_DIR}/include"
  PRIVATE "${PROJECT_SOURCE_DIR}/include/alterhook"
          "${PROJECT_SOURCE_DIR}/src/${ALTERHOOK_TARGET_ARCH}"
          "${PROJECT_SOURCE_DIR}/src/${OS_STR}"
          "${PROJECT_SOURCE_DIR}/pch/${OS_STR}"
          "${capstone_SOURCE_DIR}/include")

target_link_libraries(AlterHook PRIVATE capstone)

target_precompile_headers(AlterHook PRIVATE ${ALTERHOOK_PCH})

# setup file tabs for VS
source_group("Include\\General" FILES ${ALTERHOOK_API})
source_group("Include\\Utilities" FILES ${ALTERHOOK_UTILITIES})
source_group("Include\\Details" FILES ${ALTERHOOK_DETAILS})
source_group("Source Files\\General" ${ALTERHOOK_IMPL})
source_group("Source Files\\Arch" ${ALTERHOOK_ARCH_IMPL})
source_group("Source Files\\OS" ${ALTERHOOK_OS_IMPL})
source_group("PCH" FILES ${ALTERHOOK_PCH})

# warnings config
if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
  target_compile_options(AlterHook PRIVATE /W3 /wd5030 /wd4068)
else()
  set(ALTERHOOK_GNU_WARNINGS
      -Wall
      -Wextra
      -Wcast-align
      -Wcast-qual
      -Wctor-dtor-privacy
      -Wdisabled-optimization
      -Wformat=2
      -Winit-self
      -Wmissing-include-dirs
      -Wold-style-cast
      -Woverloaded-virtual
      -Wredundant-decls
      -Wsign-promo
      -Wstrict-overflow=5
      -Wundef
      -Wno-unused
      -Wno-variadic-macros
      -Wno-parentheses
      -Wno-unknown-pragmas)
  set(ALTERHOOK_GCC_WARNINGS $<$<CXX_COMPILER_ID:GNU>: -pedantic
                             -fdiagnostics-show-option >)
  set(ALTERHOOK_CLANG_WARNINGS
      $<$<CXX_COMPILER_ID:Clang>:
      -Wno-c++98-compat
      -Wno-reserved-macro-identifier
      -Wno-c++20-compat
      -Wno-c++98-compat-pedantic
      -Wno-unsafe-buffer-usage
      -Wno-shadow-field-in-constructor
      -Wno-disabled-macro-expansion
      -Wno-sign-conversion
      -Wno-ctad-maybe-unsupported
      -Wno-exit-time-destructors
      -Wno-global-constructors
      -Wno-reserved-identifier
      -Wno-missing-variable-declarations
      -Wno-unknown-attributes
      -Wno-missing-prototypes
      >)

  target_compile_options(
    AlterHook PRIVATE "${ALTERHOOK_GNU_WARNINGS}" "${ALTERHOOK_GCC_WARNINGS}"
                      "${ALTERHOOK_CLANG_WARNINGS}")
endif()

# generate test binary
if(ALTERHOOK_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)

  if(MSVC AND ALTERHOOK_SHARED)
    add_custom_command(
      TARGET AlterHook
      POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy -t $<TARGET_FILE_DIR:AlterHookTests>
              $<TARGET_RUNTIME_DLLS:AlterHookTests>
      COMMAND_EXPAND_LISTS)
  endif()
endif()
