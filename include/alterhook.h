/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once

// macro definitions
#include "alterhook/macros.h"

// standard headers
#include <cstddef>
#include <utility>
#include <cassert>
#include <functional>
#include <algorithm>
#include <iterator>
#include <sstream>
#include <string_view>
#include <memory>
#include <array>
#include <list>
#include <unordered_map>
#include <cstring>
#include <mutex>
#include <shared_mutex>
#if utils_cpp20
  #include <bit>
#else
  #include <limits>
#endif

// utilities
#include "alterhook/utilities/utils.h"

// api
#include "alterhook/addresser.h"
#include "alterhook/exceptions.h"
#include "alterhook/tools.h"
#include "alterhook/trampoline.h"
#include "alterhook/hook.h"
#include "alterhook/hook_chain.h"
#include "alterhook/hook_map.h"
#include "alterhook/modifier.h"