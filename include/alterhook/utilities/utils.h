/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
/**
 * @namespace alterhook::utils
 * @brief Consists of utilities that the main library is need of
 */
#include "utils_macros.h"
#if !utils_cpp17
  #error unsupported c++ version (at least c++17 is needed)
#endif
#include "other.h"
#include "index_sequence.h"
#include "type_sequence.h"
#include "calling_conventions.h"
#include "function_traits.h"
#include "static_vector.h"
#include "concepts.h"
#include "properties.h"
#include "data_processing.h"
#include "type_name.h"
