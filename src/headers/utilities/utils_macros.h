#pragma once

#if defined(__WIN32__) || defined(_WIN32) || defined(_MSC_VER)
	#define utils_windows true
	#if defined(_M_X64) || defined(__x86_x64__)
		#define utils_windows64 true
	#endif
#else
	#define utils_windows false
	#define utils_windows64 false
#endif

#ifdef __ANDROID__
	#define utils_android true
#else
	#define utils_android false
#endif

// determines which compiler is used
// the order matters since some compilers may
// define the flags of other compilers
// for example clang may define _MSC_VER
// and icc may define __GNUC__
#ifdef __clang__
	#define utils_clang true
	#define utils_icc false
	#define utils_gcc false
	#define utils_msvc false
	#define utils_other false
#else
	#define utils_clang false
	#ifdef __INTEL_COMPILER
		#define utils_icc true
		#define utils_gcc false
		#define utils_msvc false
		#define utils_other false
	#else
		#define utils_icc false
		#ifdef __GNUC__
			#define utils_gcc true
			#define utils_msvc false
			#define utils_other false
		#else
			#define has_gcc false
			#if defined(_MSC_VER) || defined(_MSVC_LANG)
				#define utils_msvc true
				#define utils_other false
			#else
				#define utils_msvc false
				#define utils_other true
			#endif
		#endif
	#endif
#endif

#if utils_msvc
	#define utils_pack_begin() __pragma(pack(push, 1))
	#define utils_pack_end() __pragma(pack(pop))
#else
	#define utils_pack_begin()
	#define utils_pack_end()
#endif

#if utils_gcc || utils_clang
	#define utils_packed __attribute__((packed))
#else
	#define utils_packed
#endif

#if utils_msvc
	#ifdef _MSVC_LANG
		#define utils_cpp_version _MSVC_LANG
	#else
		#define utils_cpp_version __cplusplus
	#endif
#else
	#define utils_cpp_version __cplusplus
#endif

// determines whether we have access to c++17 or even c++20 features
#if utils_cpp_version >= 202002L
	#define utils_cpp20 true
	#define utils_cpp17 true
#else
	#define utils_cpp20 false
	#if utils_cpp_version >= 201703L
		#define utils_cpp17 true
	#else
		#define utils_cpp17 false
	#endif
#endif

#if utils_cpp20
	#define utils_concept concept
	#define utils_consteval consteval
#else
	#define utils_concept inline constexpr bool
	#define utils_consteval constexpr
#endif

// clang & msvc x86 windows support our trick to determine calling convention
#if (utils_msvc || utils_clang) && utils_windows && !utils_windows64
	#define utils_cc_assertions true
#else
	#define utils_cc_assertions false
#endif

#if (utils_msvc || utils_clang) && utils_windows

#endif
