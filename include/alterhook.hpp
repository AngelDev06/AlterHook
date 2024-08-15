/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
/**
 * @namespace alterhook
 * @brief The main namespace for the entire api of the library. Everything this
 * library offers is scoped under this namespace (except macros of course).
 */

// detail
#include "alterhook/detail/macros.hpp"
#include "alterhook/detail/constants.hpp"

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
#include "alterhook/utilities/utils.hpp"

// api
#include "alterhook/addresser.hpp"
#include "alterhook/exceptions.hpp"
#include "alterhook/tools.hpp"
#include "alterhook/trampoline.hpp"
#include "alterhook/hook.hpp"
#include "alterhook/hook_chain.hpp"
#include "alterhook/hook_map.hpp"
#include "alterhook/modifier.hpp"
