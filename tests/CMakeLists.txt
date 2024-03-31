cmake_minimum_required(VERSION 3.21)
include(FetchContent)
FetchContent_Declare(
	googletest
	GIT_REPOSITORY https://github.com/google/googletest
	GIT_TAG f8d7d77
)

project(
	AlterHookTests
	VERSION 0.0
)

if (CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
	message(FATAL_ERROR "Can't build alterhook tests as top-level")
endif()

set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()

if (ALTERHOOK_TARGET_ARCH STREQUAL "ARM")
	set(
		ALTERHOOK_ARM_TESTS
		"ARM/trampolines.cpp"
		"ARM/trampolines.h"
		"ARM/trampoline_target_tests.h"
		"ARM/trampolines_general.h"
	)
elseif (ALTERHOOK_TARGET_ARCH STREQUAL "AArch64")
	set(
		ALTERHOOK_AARCH64_TESTS
		"AArch64/trampolines.cpp"
		"AArch64/trampolines.h"
	)
endif()

add_executable(
	AlterHookTests
	"hooks.cpp"
    "hook_chains.cpp"
	"modifiers.cpp"
	"testcls.h"
	"modifiers.h"
	${ALTERHOOK_ARM_TESTS}
	${ALTERHOOK_AARCH64_TESTS}
)

target_link_libraries(
	AlterHookTests
PRIVATE
	AlterHook
	GTest::gtest_main
)

include(GoogleTest)

if (CMAKE_CROSSCOMPILING)
	gtest_add_tests(TARGET AlterHookTests)
else()
	gtest_discover_tests(AlterHookTests)
endif()