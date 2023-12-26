cmake_minimum_required(VERSION 3.21)
include(FetchContent)
# get capstone
FetchContent_Declare(
	capstone
	GIT_REPOSITORY https://github.com/AngelDev06/capstone
	GIT_TAG dcc85dbd
)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
    message(FATAL_ERROR "In-tree builds are not supported. Run CMake from a separate directory: cmake -B build")
endif()

set(ALTERHOOK_TOP_LEVEL OFF)
if (CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
	set(ALTERHOOK_TOP_LEVEL ON)
endif()

project(
	AlterHook
	VERSION 0.0
)

# Enable Hot Reload for MSVC compilers if supported.
if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(
	  CMAKE_MSVC_DEBUG_INFORMATION_FORMAT 
	  "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>"
  )
endif()

option(ALTERHOOK_SHARED "Use shared version of AlterHook")
option(ALTERHOOK_TARGET_ARCH "Specifies the target architecture to use")
option(ALTERHOOK_BUILD_TESTS "Determines whether to build the tests on folder 'tests/'" ${ALTERHOOK_TOP_LEVEL})
set_property(CACHE ALTERHOOK_TARGET_ARCH PROPERTY STRINGS "X86" "ARM" "ARM64")

set(
	ALTERHOOK_PRIVATE_HEADERS
	"headers/buffer.h"
	"headers/disassembler.h"
	"headers/injection.h"
)

set(
	ALTERHOOK_UTILITIES_HEADERS
	"include/alterhook/utilities/calling_conventions.h"
	"include/alterhook/utilities/concepts.h"
	"include/alterhook/utilities/function_traits.h"
	"include/alterhook/utilities/other.h"
	"include/alterhook/utilities/static_vector.h"
	"include/alterhook/utilities/type_sequence.h"
	"include/alterhook/utilities/utils.h"
	"include/alterhook/utilities/utils_macros.h"
	"include/alterhook/utilities/properties.h"
)

set(
	ALTERHOOK_PUBLIC_HEADERS
	"include/alterhook.h"
	"include/alterhook/addresser.h"
	"include/alterhook/exceptions.h"
	"include/alterhook/tools.h"
	"include/alterhook/trampoline.h"
	"include/alterhook/hook.h"
	"include/alterhook/hook_chain.h"
	"include/alterhook/hook_map.h"
	"include/alterhook/modifier.h"
)

set(
	ALTERHOOK_DETAIL_HEADERS
	"include/alterhook/detail/macros.h"
	"include/alterhook/detail/constants.h"
)

set(
	ALTERHOOK_CPP_FILES
	"src/addresser.cpp"
	"src/buffer.cpp"
	"src/misc.cpp"
	"src/hook.cpp"
	"src/hook_chain.cpp"
)

get_property(ALTERHOOK_TARGET_ARCHS CACHE ALTERHOOK_TARGET_ARCH PROPERTY STRINGS)
if (NOT ALTERHOOK_TARGET_ARCH IN_LIST ALTERHOOK_TARGET_ARCHS)
	string(
		CONCAT ALTERHOOK_INVALID_ARCH_OUTPUT
		"ALTERHOOK_TARGET_ARCH is invalid, "
		"determining the target architecture from the preprocessor"
	)
	message(STATUS "${ALTERHOOK_INVALID_ARCH_OUTPUT}")
	list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/scripts")
	include(TargetArch)
	target_architecture(arch)

	if (arch MATCHES "x86|x64")
		set(ALTERHOOK_TARGET_ARCH "X86")
		message(STATUS "Auto-detected x86 target architecture")
	elseif (arch STREQUAL "armv7")
		set(ALTERHOOK_TARGET_ARCH "ARM")
		message(STATUS "Auto-detected armv7 target architecture")
	elseif (arch STREQUAL "aarch64")
		set(ALTERHOOK_TARGET_ARCH "ARM64")
		message(STATUS "Auto-detected aarch64 target architecture")
	else()
		string(
			CONCAT ERROR_OUTPUT
			"Failed to auto-detect 'ALTERHOOK_TARGET_ARCH=${ALTERHOOK_TARGET_ARCH}', "
			"consider specifying one of: X86, ARM, ARM64"
		)
		message(FATAL_ERROR "${ERROR_OUTPUT}")
	endif()
endif()

set(CAPSTONE_ARCHITECTURE_DEFAULT OFF CACHE BOOL "Whether architectures are enabled by default" FORCE)
if (ALTERHOOK_TARGET_ARCH STREQUAL "X86")
	set(CAPSTONE_X86_SUPPORT ON CACHE BOOL "x86 support" FORCE)
	message(STATUS "Enabling alterhook x86 support")
elseif (ALTERHOOK_TARGET_ARCH STREQUAL "ARM64")
	set(CAPSTONE_AARCH64_SUPPORT ON CACHE BOOL "AARCH64 support" FORCE)
	message(STATUS "Enabling alterhook aarch64 support")
else()
	set(CAPSTONE_ARM_SUPPORT ON CACHE BOOL "ARM support" FORCE)
	message(STATUS "Enabling alterhook armv7 support")
endif()

string(TOLOWER "${ALTERHOOK_TARGET_ARCH}" ALTERHOOK_TARGET_ARCH_LOWER)
list(APPEND ALTERHOOK_PRIVATE_HEADERS "headers/${ALTERHOOK_TARGET_ARCH_LOWER}_instructions.h")
foreach (SRC "trampoline" "injection" "thread_processing")
	list(APPEND ALTERHOOK_CPP_FILES "src/${ALTERHOOK_TARGET_ARCH}/${SRC}.cpp")
endforeach()

if (WIN32)
	set(OS_STR "windows")
else()
	set(OS_STR "linux")
endif()

set(ALTERHOOK_PCH "pre-compiled headers/${OS_STR}/pch.h")
list(APPEND ALTERHOOK_PRIVATE_HEADERS "headers/${OS_STR}_thread_handler.h")
foreach (SRC "other" "allocation" "freezer" "exceptions")
	list(APPEND ALTERHOOK_CPP_FILES "src/${OS_STR}/${SRC}.cpp")
endforeach()

FetchContent_MakeAvailable(capstone)

set(
	ALTERHOOK_ALL_HEADERS
	${ALTERHOOK_PRIVATE_HEADERS}
	${ALTERHOOK_UTILITIES_HEADERS}
	${ALTERHOOK_PUBLIC_HEADERS}
	${ALTERHOOK_DETAIL_HEADERS}
	${ALTERHOOK_PCH}
)

source_group("Source Files" ${CPP_FILES})
source_group("Header Files" ${ALTERHOOK_PRIVATE_HEADERS})
source_group("Include\\utilities" ${ALTERHOOK_UTILITIES_HEADERS})
source_group("Include\\detail" ${ALTERHOOK_DETAIL_HEADERS})
source_group("Include" ${ALTERHOOK_PUBLIC_HEADERS})
source_group("PCH" ${ALTERHOOK_PCH})

if (ALTERHOOK_SHARED)
	add_library(AlterHook SHARED ${ALTERHOOK_ALL_HEADERS} ${ALTERHOOK_CPP_FILES})
	set_target_properties(capstone PROPERTIES POSITION_INDEPENDENT_CODE ON)
else()
	add_library(AlterHook STATIC ${ALTERHOOK_ALL_HEADERS} ${ALTERHOOK_CPP_FILES})
endif()

target_compile_definitions(
	AlterHook 
PUBLIC
	$<$<CONFIG:Debug>:_GLIBCXX_DEBUG>
	$<$<BOOL:${ALTERHOOK_SHARED}>:ALTERHOOK_SHARED>
PRIVATE
	$<$<BOOL:${ALTERHOOK_SHARED}>:ALTERHOOK_EXPORT>
)

target_include_directories(
	AlterHook 
PUBLIC
	$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
PRIVATE
	$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include/alterhook>
	$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/headers>
	"$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/pre-compiled headers/${OS_STR}>"
	$<BUILD_INTERFACE:${capstone_SOURCE_DIR}/include>
)

target_link_libraries(AlterHook PRIVATE capstone)

target_precompile_headers(AlterHook PRIVATE ${ALTERHOOK_PCH})

if (MSVC)
	target_compile_options(AlterHook PRIVATE /W3)
else()
	set(
		ALTERHOOK_GNU_WARNINGS
		-Wall
		-Wextra
		-pedantic
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
		-fdiagnostics-show-option
	)

	target_compile_options(AlterHook PRIVATE ${ALTERHOOK_GNU_WARNINGS})
endif()

if (ALTERHOOK_BUILD_TESTS)
	enable_testing()
	add_subdirectory(tests)

	if (MSVC AND ALTERHOOK_SHARED)
		add_custom_command(
			TARGET AlterHook POST_BUILD
			COMMAND ${CMAKE_COMMAND} -E copy -t $<TARGET_FILE_DIR:AlterHookTests> $<TARGET_RUNTIME_DLLS:AlterHookTests>
			COMMAND_EXPAND_LISTS
		)
	endif()
endif()