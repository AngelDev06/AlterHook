/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#define __alterhook_expose_impl
#include "detail/macros.h"
#include "detail/constants.h"
#include <utilities/utils.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <array>
#include <vector>
#include <mutex>
#include <shared_mutex>
#include <sstream>
#include <iomanip>
#include <limits>
#include <unordered_map>
#include <capstone/capstone.h>

#if defined(ALTERHOOK_ALWAYS_USE_RELAY) && utils_x64
  #define always_use_relay true
#else
  #define always_use_relay false
#endif

#if (defined(ALTERHOOK_NO_NEARBY_ALLOCATIONS) && !utils_x64) || utils_x86
  #define allocate_nearby false
#else
  #define allocate_nearby true
#endif