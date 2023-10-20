cmake_minimum_required(VERSION 3.21)

project(
	AlterHookTests
	VERSION 0.0
)

if (CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
	message(FATAL_ERROR "Can't build alterhook tests as top-level'")
endif()

set(
	ALTERHOOK_TEST_PROJECTS
	"hooks.cpp testcls.h"
	"modifiers.cpp modifiers.h testcls.h"
	"hook_chains.cpp testcls.h"
)

set(ALTERHOOK_TEST_PROJECTS ${ALTERHOOK_TEST_PROJECTS} PARENT_SCOPE)

foreach (TEST_PROJECT ${ALTERHOOK_TEST_PROJECTS})
	separate_arguments(TEST_PROJECT)
	list(GET TEST_PROJECT 0 TEST_CPP_FILE)
	string(REGEX REPLACE ".cpp$" "" TEST_BIN ${TEST_CPP_FILE})
	add_executable(${TEST_BIN} ${TEST_PROJECT})
	target_link_libraries(${TEST_BIN} PRIVATE AlterHook)
	if (MSVC AND ALTERHOOK_SHARED)
		add_custom_command(
			TARGET ${TEST_BIN} POST_BUILD 
			COMMAND ${CMAKE_COMMAND} -E copy -t $<TARGET_FILE_DIR:${TEST_BIN}> $<TARGET_RUNTIME_DLLS:${TEST_BIN}>
			COMMAND_EXPAND_LISTS
		)
	endif()
endforeach()