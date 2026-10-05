/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
/**
 * @namespace alterhook::utils
 * @brief Consists of utilities that the main library is need of
 */
#include "macros.hpp"
#if !utils_cpp17
  #error unsupported c++ version (at least c++17 is needed)
#endif
#include "other.hpp"
#include "traits/index_sequence.hpp"
#include "traits/type_sequence.hpp"
#include "traits/calling_conventions.hpp"
#include "traits/function_traits.hpp"
#include "traits/concepts.hpp"
#include "traits/iterator_traits.hpp"
#include "traits/type_name.hpp"
#include "traits/map_traits.hpp"
#include "static_vector.hpp"
#include "storage.hpp"
#include "iterators.hpp"
#include "traits/properties.hpp"
#include "data_processing.hpp"
#include "tuple_tools.hpp"
