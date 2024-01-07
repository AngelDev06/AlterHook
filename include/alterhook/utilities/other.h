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

  template <typename T1, typename T2>
  struct same_cv_qualification
  {
    static constexpr bool value = same_cv_qualification_v<T1, T2>;
  };

  namespace helpers
  {
    // I remade std::make_index_sequence because I wanted a specific range of
    // indexes
    template <size_t start, typename seq, size_t end>
    struct make_index_sequence_impl;

    template <size_t start, size_t... indexes, size_t end>
    struct make_index_sequence_impl<start, std::index_sequence<indexes...>, end>
        : make_index_sequence_impl<start + 1,
                                   std::index_sequence<indexes..., start>, end>
    {
    };

    template <size_t end, size_t... indexes>
    struct make_index_sequence_impl<end, std::index_sequence<indexes...>, end>
    {
      typedef std::index_sequence<indexes...> type;
    };
  } // namespace helpers

  template <size_t end, size_t start = 0>
  struct make_index_sequence
      : helpers::make_index_sequence_impl<start, std::index_sequence<>, end>
  {
    static_assert(start <= end,
                  "utils::make_index_sequence<end, start>: invalid parameters");
  };

  template <size_t end, size_t start = 0>
  using make_index_sequence_t = typename make_index_sequence<end, start>::type;

  namespace helpers
  {
    template <typename seq, size_t begin, size_t end, size_t step>
    struct index_seq_step_impl;

    template <size_t... indexes, size_t begin, size_t end, size_t step>
    struct index_seq_step_impl<std::index_sequence<indexes...>, begin, end,
                               step>
        : index_seq_step_impl<std::index_sequence<indexes..., begin>,
                              begin + step, end, step>
    {
    };

    template <size_t... indexes, size_t end, size_t step>
    struct index_seq_step_impl<std::index_sequence<indexes...>, end, end, step>
    {
      typedef std::index_sequence<indexes...> type;
    };
  } // namespace helpers

  template <size_t end, size_t begin = 0, size_t step = 2>
  using make_index_sequence_with_step =
      typename helpers::index_seq_step_impl<std::index_sequence<>, begin,
                                            end + (begin % step), step>::type;

#if !utils_cpp20
  template <typename T>
  using remove_cvref_t = std::remove_cv_t<std::remove_reference_t<T>>;
#else
  template <typename T>
  using remove_cvref_t = std::remove_cvref_t<T>;
#endif

  namespace helpers
  {
    template <typename pair>
    inline constexpr bool is_pair_impl = false;

    template <typename F, typename S>
    inline constexpr bool is_pair_impl<std::pair<F, S>> = true;

    template <typename tuple>
    inline constexpr bool is_tuple_impl = false;

    template <typename... types>
    inline constexpr bool is_tuple_impl<std::tuple<types...>> = true;
  } // namespace helpers

  template <typename pair>
  utils_concept stl_pair = helpers::is_pair_impl<remove_cvref_t<pair>>;

  template <typename tuple>
  utils_concept stl_tuple = helpers::is_tuple_impl<remove_cvref_t<tuple>>;

  template <typename... types>
  utils_concept stl_tuples_or_pairs = ((stl_tuple<remove_cvref_t<types>> ||
                                        stl_pair<remove_cvref_t<types>>)&&...);

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
} // namespace alterhook::utils
