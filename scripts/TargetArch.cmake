cmake_minimum_required(VERSION 3.25)

function(target_architecture output_var)
	set(
		code "
		#if defined(__x86_64__) || defined(_M_X64)
			#error cmake_ARCH x64
		#elif defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86)
			#error cmake_ARCH x86
		#elif defined(__aarch64__) || defined(_M_ARM64)
			#error cmake_ARCH aarch64
		#elif defined(__ARM_ARCH_7__) || defined(__ARM_ARCH_7A__) ||               \\
			  defined(__ARM_ARCH_7R__) || defined(__ARM_ARCH_7M__) ||              \\
              (defined(__TARGET_ARCH_ARM) && __TARGET_ARCH_ARM - 0 >= 7)
			#error cmake_ARCH armv7
		#else
			#error cmake_ARCH unknown
		#endif
		"
	)

	if (ANDROID)
		if (ANDROID_ABI STREQUAL "armeabi-v7a")
			set(arch "armv7")
		elseif (ANDROID_ABI STREQUAL "arm64-v8a")
			set(arch "aarch64")
		elseif (ANDROID_ABI STREQUAL "x86")
			set(arch "x86")
		elseif (ANDROID_ABI STREQUAL "x86_64")
			set(arch "x64")
		else()
			set(arch "unknown")
		endif()
	else()
		try_compile(
			status
			SOURCE_FROM_VAR arch.c code 
			OUTPUT_VARIABLE result
		)

		string(REGEX MATCH "cmake_ARCH ([A-Za-z0-9]+)" arch "${result}")

		string(REPLACE "cmake_ARCH " "" arch "${arch}")
	endif()

	set(${output_var} "${arch}" PARENT_SCOPE)
endfunction()