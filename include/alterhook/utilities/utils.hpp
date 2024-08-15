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
#include "index_sequence.hpp"
#include "type_sequence.hpp"
#include "calling_conventions.hpp"
#include "function_traits.hpp"
#include "static_vector.hpp"
#include "concepts.hpp"
#include "properties.hpp"
#include "data_processing.hpp"
#include "type_name.hpp"
