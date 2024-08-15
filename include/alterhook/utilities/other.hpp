/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include "utils_macros.h"
#include <utility>
#if utils_cpp20
  #include <bit>
#else
  #include <limits>
#endif

namespace alterhook::utils
{
  namespace helpers
  {
    template <typename bools, typename indexes>
    inline constexpr size_t index_of_true_impl = 0;
  }

  template <size_t i>
  struct rank : rank<i - 1>
  {
    static constexpr size_t index = i;
  };

  template <>
  struct rank<0>
  {
    static constexpr size_t index = 0;
  };

  template <typename T>
  struct type_identity
  {
    typedef T type;
  };

  template <typename T>
  using type_identity_t = typename type_identity<T>::type;

  template <typename T, typename... types>
  constexpr bool any_of(T&& value, types&&... args) noexcept
  {
    return ((value == args) || ...);
  }

  template <typename T>
  using nop_t = T;

  template <typename T>
  inline constexpr bool is_cv_v = false;
  template <typename T>
  inline constexpr bool is_cv_v<const volatile T> = true;

  template <typename T>
  struct is_cv
  {
    static constexpr bool value = is_cv_v<T>;
  };

  template <typename T>
  utils_concept cv_qualified =
      std::is_const_v<T> || std::is_volatile_v<T> || is_cv_v<T>;

  template <typename T1, typename T2>
  inline constexpr bool same_cv_qualification_v =
      !cv_qualified<T1> && !cv_qualified<T2>;
  template <typename T1, typename T2>
  inline constexpr bool same_cv_qualification_v<const T1, const T2> = true;
  template <typename T1, typename T2>
  inline constexpr bool same_cv_qualification_v<volatile T1, volatile T2> =
      true;
  template <typename T1, typename T2>
  inline constexpr bool
      same_cv_qualification_v<const volatile T1, const volatile T2> = true;

  template <template <typename...> typename left,
            template <typename...> typename right>
  inline constexpr bool is_same_template_v = false;
  template <template <typename...> typename cls>
  inline constexpr bool is_same_template_v<cls, cls> = true;

  template <typename T1, typename T2>
  struct same_cv_qualification
  {
    static constexpr bool value = same_cv_qualification_v<T1, T2>;
  };

#if !utils_cpp20
  template <typename T>
  using remove_cvref_t = std::remove_cv_t<std::remove_reference_t<T>>;
#else
  template <typename T>
  using remove_cvref_t = std::remove_cvref_t<T>;
#endif

  template <bool... values>
  inline constexpr size_t index_of_true =
      helpers::index_of_true_impl<std::integer_sequence<bool, values...>,
                                  std::make_index_sequence<sizeof...(values)>>;

  template <typename fn, typename ret, typename... args>
  utils_concept invocable_r = std::is_invocable_r_v<ret, fn, args...>;

  template <typename... types>
  utils_concept always_false = false;

  template <typename... types>
  struct undefined_struct;

  template <typename... types>
  struct overloaded : types...
  {
    using types::operator()...;
  };

  template <typename... types>
  overloaded(types...) -> overloaded<types...>;

  template <typename T>
  struct first_template_param_of;

  template <template <typename, typename...> typename templ, typename T,
            typename... rest>
  struct first_template_param_of<templ<T, rest...>>
  {
    typedef T type;
  };

  template <typename T>
  using first_template_param_of_t = typename first_template_param_of<T>::type;

  template <typename func_type, typename cls>
  using add_cls_t = func_type cls::*;

  template <typename derived, typename... bases>
  utils_concept derived_from_any_of =
      (std::is_base_of_v<bases, derived> || ...);

#if utils_cpp20
  template <auto left, auto right>
  concept compare_or_false = requires { left == right; } && left == right;
#else
  namespace helpers
  {
    template <auto left, auto right, typename = void>
    inline constexpr bool compare_or_false_impl = false;
    template <auto left, auto right>
    inline constexpr bool compare_or_false_impl<
        left, right, std::void_t<decltype(left == right)>> = left == right;
  } // namespace helpers

  template <auto left, auto right>
  inline constexpr bool compare_or_false =
      helpers::compare_or_false_impl<left, right>;
#endif

  namespace helpers
  {
    template <bool... values, size_t... indexes>
    inline constexpr size_t
        index_of_true_impl<std::integer_sequence<bool, values...>,
                           std::index_sequence<indexes...>> =
            ((values ? indexes : 0) + ...);
  }
} // namespace alterhook::utils
