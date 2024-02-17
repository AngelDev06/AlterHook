#pragma once
#include "utils_macros.h"
#include "other.h"
#include <string_view>

namespace alterhook::utils
{
  /**
   * @brief A tool that stringifies any type passed and returns it (at compile
   * time)
   * @tparam T the type that should be stringified
   * @returns the stringified version of `T` as `std::string_view`
   */
  template <typename T>
  utils_consteval std::string_view name_of();

  namespace helpers
  {
    template <typename T>
    utils_consteval std::string_view get_raw_signature()
    {
#if utils_msvc
      return __FUNCSIG__;
#else
      return __PRETTY_FUNCTION__;
#endif
    }

    struct type_name_format_t
    {
      size_t junk_leading = 0;
      size_t junk_total   = 0;
    };

    constexpr type_name_format_t type_name_format = {
      get_raw_signature<int>().find("int"), get_raw_signature<int>().size() - 3
    };
  } // namespace helpers

  template <typename T>
  utils_consteval std::string_view name_of()
  {
    static_assert(helpers::type_name_format.junk_leading !=
                          std::string_view::npos ||
                      always_false<T>,
                  "can't determine type name format");
    std::string_view raw = helpers::get_raw_signature<T>();
    return raw.substr(helpers::type_name_format.junk_leading,
                      raw.size() - helpers::type_name_format.junk_total);
  }
} // namespace alterhook::utils