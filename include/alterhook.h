/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once

// macro definitions
#include "../src/headers/utilities/utils_macros.h"
#include "../src/headers/macros.h"

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
#include <bitset>
#include <array>
#include <list>
#if utils_cpp20
  #include <bit>
#else
  #include <limits>
#endif

// utilities
#include "../src/headers/utilities/other.h"
#include "../src/headers/utilities/type_sequence.h"
#include "../src/headers/utilities/calling_conventions.h"
#include "../src/headers/utilities/function_traits.h"
#include "../src/headers/utilities/static_vector.h"
#include "../src/headers/utilities/template_string.h"

// api
#include "addresser.h"
#include "exceptions.h"
#include "tools.h"
#include "api.h"
