/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include <cstddef>
#include <utility>
#include <cassert>
#include <functional>
#include <algorithm>
#include <iterator>
#include <sstream>
#include <string_view>
#include "utils_macros.h"
#if utils_cpp20
#include <bit>
#else
#include <limits>
#endif
#if !utils_cpp17
#error unsupported c++ version (at least c++17 is needed)
#endif
#include "other.h"
#include "type_sequence.h"
#include "calling_conventions.h"
#include "function_traits.h"
#include "static_vector.h"
#include "template_string.h"
