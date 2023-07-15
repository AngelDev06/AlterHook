/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#if defined(_USRDLL) || (defined(ALTERHOOK_SHARED) && utils_windows)
	#ifdef ALTERHOOK_EXPORT
		#define ALTERHOOK_API __declspec(dllexport)
	#else
		#define ALTERHOOK_API __declspec(dllimport)
	#endif
#elif defined(__GNUC__) && defined(ALTERHOOK_SHARED)
#define ALTERHOOK_API __attribute__((visibility("default")))
#else
#define ALTERHOOK_API
#endif
