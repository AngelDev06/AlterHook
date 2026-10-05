/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include <type_traits>
#include <utility>
#include "macros.hpp"
#include "traits/type_sequence.hpp"
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
    template <typename T, template <typename> typename pred, typename default_t,
              typename = void>
    struct try_apply_impl;
    template <template <typename...> typename Tmpl, typename TypeSeq,
              typename = void>
    constexpr bool can_substitute_impl = false;
    template <typename T, template <typename> typename pred, typename expected,
              typename = void>
    constexpr bool optionally_is_convertible_to_impl = true;
    template <typename T, template <typename> typename pred, typename expected,
              typename = void>
    constexpr bool optionally_is_same_impl = true;
    template <typename From, typename To>
    struct copy_cv_impl;
  } // namespace helpers

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

  struct nothing
  {
  };

  template <auto arg>
  struct val
  {
    static constexpr auto value = arg;
  };

  template <typename T>
  struct type_identity
  {
    typedef T type;
  };

  template <typename T>
  using type_identity_t = typename type_identity<T>::type;

  template <typename T, template <typename> typename pred, typename default_t>
  struct try_apply : helpers::try_apply_impl<T, pred, default_t>
  {
  };

  template <typename T, template <typename> typename pred, typename default_t>
  using try_apply_t = typename try_apply<T, pred, default_t>::type;

  template <template <typename...> typename Tmpl, typename... Types>
  constexpr bool can_substitute =
      helpers::can_substitute_impl<Tmpl, type_sequence<Types...>>;

  template <typename From, typename To>
  using copy_cv_t = typename helpers::copy_cv_impl<From, To>::type;

  template <typename From>
  struct apply_cv
  {
    template <typename To>
    using apply = copy_cv_t<From, To>;
  };

  template <typename T>
  using make_const_reference_t = typename std::conditional_t<
      std::is_lvalue_reference_v<T>,
      std::add_lvalue_reference<const std::remove_reference_t<T>>,
      std::add_rvalue_reference<const std::remove_reference_t<T>>>::type;

  template <typename T, template <typename> typename pred, typename expected>
  constexpr bool optionally_is_convertible_v =
      helpers::optionally_is_convertible_to_impl<T, pred, expected>;

  template <typename T, template <typename> typename pred, typename expected>
  constexpr bool optionally_is_same_v =
      helpers::optionally_is_same_impl<T, pred, expected>;

  template <typename T, typename... types>
  constexpr bool any_of(T&& value, types&&... args) noexcept
  {
    return ((value == args) || ...);
  }

  template <typename T>
  using nop_t = T;

  template <typename T1, typename T2>
  struct equal_val
  {
    static constexpr bool value = T1::value == T2::value;
  };

  template <typename T1, typename T2>
  constexpr bool equal_val_v = equal_val<T1, T2>::value;

  template <typename T>
  utils_concept cv_qualified =
      std::disjunction_v<std::is_const<T>, std::is_volatile<T>>;

  template <typename T1, typename T2>
  constexpr bool same_cv_v =
      std::conjunction_v<equal_val<std::is_const<T1>, std::is_const<T2>>,
                         equal_val<std::is_volatile<T1>, std::is_volatile<T2>>>;

  template <typename T1, typename T2>
  struct same_cv
  {
    static constexpr bool value = same_cv_v<T1, T2>;
  };

  template <template <typename...> typename left,
            template <typename...> typename right>
  inline constexpr bool is_same_template_v = false;
  template <template <typename...> typename cls>
  inline constexpr bool is_same_template_v<cls, cls> = true;

  template <typename T, template <typename...> typename Tmpl>
  constexpr bool is_instantiation_of = false;
  template <template <typename...> typename Tmpl, typename... Types>
  constexpr bool is_instantiation_of<Tmpl<Types...>, Tmpl> = true;

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
  constexpr bool all_same = true;
  template <typename T, typename... types>
  constexpr bool all_same<T, types...> = (std::is_same_v<T, types> && ...);

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

  template <template <typename...> typename Tmpl>
  struct template_wrapper
  {
    template <typename... Types>
    using apply = Tmpl<Types...>;
  };

  template <typename func_type, typename cls>
  using add_cls_t = func_type cls::*;

  template <typename derived, typename... bases>
  utils_concept derived_from_any_of =
      (std::is_base_of_v<bases, derived> || ...);

#define __utils_define_optional_type_member_accessor(name)                     \
  namespace helpers                                                            \
  {                                                                            \
    template <typename T>                                                      \
    using utils_concat(name, _type_member_of) = typename T::name;              \
  }                                                                            \
  template <typename T, typename fallback>                                     \
  using utils_concat(name, _optional_type_member_of) =                         \
      try_apply_t<T, helpers::utils_concat(name, _type_member_of), fallback>;

#define __utils_generate_optional_type_member_accessors(...)                   \
  utils_map(__utils_define_optional_type_member_accessor, __VA_ARGS__)

  __utils_generate_optional_type_member_accessors(value_type, size_type,
                                                  difference_type, reference,
                                                  const_reference, pointer,
                                                  const_pointer, allocator_type,
                                                  iterator_category);

  template <typename T>
  using size_type_member_or_size_t =
      size_type_optional_type_member_of<T, size_t>;

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

    template <typename T, template <typename> typename pred, typename default_t,
              typename>
    struct try_apply_impl
    {
      using type = default_t;
    };

    template <typename T, template <typename> typename pred, typename default_t>
    struct try_apply_impl<T, pred, default_t, std::void_t<pred<T>>>
    {
      using type = pred<T>;
    };

    template <template <typename...> typename Tmpl, typename... Types>
    constexpr bool can_substitute_impl<Tmpl, type_sequence<Types...>,
                                       std::void_t<Tmpl<Types...>>> = true;

    template <typename From, typename To>
    struct copy_cv_impl
    {
    private:
      using FromUnref = std::remove_reference_t<From>;
      using ConstTo   = std::conditional_t<std::is_const_v<FromUnref>,
                                           std::add_const_t<To>, To>;

    public:
      using type = std::conditional_t<std::is_volatile_v<FromUnref>,
                                      std::add_volatile_t<ConstTo>, ConstTo>;
    };

    template <typename T, template <typename> typename pred, typename expected>
    constexpr bool optionally_is_convertible_to_impl<T, pred, expected,
                                                     std::void_t<pred<T>>> =
        std::is_convertible_v<pred<T>, expected>;

    template <typename T, template <typename> typename pred, typename expected>
    constexpr bool
        optionally_is_same_impl<T, pred, expected, std::void_t<pred<T>>> =
            std::is_same_v<pred<T>, expected>;
  } // namespace helpers
} // namespace alterhook::utils
