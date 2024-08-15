/* Part of the AlterHook Project */
/* Designed & implemented by AngelDev06 */
#pragma once
#ifdef __INTELLISENSE__
  #define _Nullable
  #define _Nonnull
#endif
#define __alterhook_expose_impl
#include <capstone/capstone.h>
#include <string.h>
#include <array>
#include <vector>
#include <unordered_map>
#include <list>
#include <unistd.h>
#include <mutex>
#include <shared_mutex>
#include <atomic>
#include <sys/mman.h>
#ifndef __GNUC__
  #include <sys/cachectl.h>
#endif
#include <signal.h>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <fstream>
#include <limits>
#include <thread>
#include <bitset>
#include <variant>
#include <optional>
#include <numeric>
#include "detail/macros.h"
#include "detail/constants.h"
#include "utilities/utils.h"

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