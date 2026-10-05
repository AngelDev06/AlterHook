/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include "../utilities/macros.hpp"

#if (defined(ALTERHOOK_SHARED) &&                                              \
     (defined(__WIN32__) || defined(_WIN32) || defined(_MSC_VER)))
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

#if !utils_arm && !utils_aarch64 && !utils_x86 && !utils_x64
  #error unsupported architecture
#endif
