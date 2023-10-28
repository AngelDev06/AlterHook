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

add_executable(
	AlterHookTests
	"hooks.cpp"
	"hook_chains.cpp"
	"modifiers.cpp"
	"testcls.h"
	"modifiers.h"
)

target_link_libraries(
	AlterHookTests
PRIVATE
	AlterHook
	GTest::gtest_main
)

if (MSVC AND ALTERHOOK_SHARED)
	add_custom_command(
		TARGET AlterHookTests POST_BUILD 
		COMMAND ${CMAKE_COMMAND} -E copy -t $<TARGET_FILE_DIR:AlterHookTests> $<TARGET_RUNTIME_DLLS:AlterHookTests>
		COMMAND_EXPAND_LISTS
	)
endif()

include(GoogleTest)
gtest_discover_tests(AlterHookTests)