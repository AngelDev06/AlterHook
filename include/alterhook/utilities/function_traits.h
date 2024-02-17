/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include <cstddef>
#include <utility>
#include <functional>
#include "other.h"
#include "type_sequence.h"
#include "calling_conventions.h"
#include "type_name.h"

namespace alterhook::utils
{
  namespace helpers
  {
    template <typename T>
    struct clean_function_type_helper;
    template <typename T>
    struct unwrap_stl_function_impl;
    template <typename T>
    struct remove_first_arg;
    template <typename T>
    struct captureless_lambda_clean_type_impl;
    template <typename T, typename = void>
    struct function_traits_impl;
    template <typename T, typename = void>
    struct clean_type_impl;
    template <typename T>
    struct add_thiscall_if_needed;
    template <typename T>
    inline constexpr bool is_stl_function_impl = false;
    template <typename T, typename = void>
    inline constexpr bool no_ambiguous_callable = false;
    template <typename T>
    using remove_first_arg_t = typename remove_first_arg<T>::type;
    template <typename T>
    using call_overload_t = decltype(&T::operator());
#if utils_cc_assertions
    template <typename T1, typename T2, typename = void>
    inline constexpr bool compatible_calling_convention_with_impl = false;
#endif
#if !utils_cpp20
    template <typename T, typename = void>
    inline constexpr bool captureless_lambda_impl = false;
#endif
    utils_consteval bool is_lambda(std::string_view type) noexcept;
    template <typename T1, typename T2>
    utils_consteval bool have_compatible_fn_args();
  } // namespace helpers

  /**
   * @brief Takes a function-like type and defines a function type of the form
   * of `ret(args...)` where `ret` is the return type of the function passed and
   * `args...` its argument types respectively.
   * @tparam T the function-like type to use. Can be a function type, a regular
   * function pointer, a member function pointer or an instance of
   * `std::function`.
   * @note This also handles stuff like calling conventions, constness and the
   * noexcept specifier. Therefore it can come in handy when in need to simplify
   * partial overloads. Also note that for member function pointers, it adds the
   * implicit `this` pointer as a first argument with its expected constness.
   */
  template <typename T>
  struct clean_function_type
      : helpers::clean_function_type_helper<std::remove_pointer_t<T>>
  {
  };

  /// Alias for @ref alterhook::utils::clean_function_type
  template <typename T>
  using clean_function_type_t = typename helpers::clean_function_type_helper<
      std::remove_pointer_t<T>>::type;

  /**
   * @brief Takes any type and defines a static member named `value` set to
   * `true` when `remove_cvref_t<T>` evaluates to an instance of
   * `std::function`, false otherwise.
   * @tparam T the type to check (can be anything).
   */
  template <typename T>
  struct is_stl_function
  {
    static constexpr bool value =
        helpers::is_stl_function_impl<remove_cvref_t<T>>;
  };

  /// Alias for @ref alterhook::utils::is_stl_function
  template <typename T>
  utils_concept stl_function_type =
      helpers::is_stl_function_impl<remove_cvref_t<T>>;

  /**
   * @brief Takes an instance of `std::function` and defines its template
   * parameter.
   * @tparam T the instance of `std::function` to be used (can contain const and
   * references)
   */
  template <typename T>
  struct unwrap_stl_function
      : std::add_pointer<
            typename helpers::unwrap_stl_function_impl<remove_cvref_t<T>>::type>
  {
  };

  /// Alias for @ref alterhook::utils::unwrap_stl_function
  template <typename T>
  using unwrap_stl_function_t = typename unwrap_stl_function<T>::type;

  template <typename T>
  utils_concept lambda_type = helpers::is_lambda(name_of<T>());

#if utils_cpp20
  /**
   * @brief Takes any type and evaluates to true if `T` meets the requirements
   * of a captureless lambda.
   * @tparam T the type to check
   *
   * The requirements for `T` to be considered as a captureless lambda are:
   * - It must have a non-ambiguous overload of `operator()` defined. (because
   * of this generic lambdas are not allowed)
   * - Must be implicitly convertible to its respective function pointer via an
   * overload of `operator F()`.
   */
  template <typename T>
  concept captureless_lambda = requires(T instance) {
    &T::operator();
    typename clean_function_type_t<decltype(&T::operator())>;
    static_cast<std::add_pointer_t<helpers::remove_first_arg_t<
        clean_function_type_t<decltype(&T::operator())>>>>(instance);
  };
#else
  template <typename T>
  inline constexpr bool captureless_lambda =
      helpers::captureless_lambda_impl<T>;
#endif

  /**
   * @brief Takes a captureless lambda type and defined the function type to
   * which it can be implicitly converted.
   * @tparam T the capturless lambda to use
   * @note On 32-bit windows this also minds calling convention tags (e.g.
   * `utils::fastcall`). As a result it will proceed to replace the tags with
   * their respective calling convention on the type defined. If you are
   * interested in the actual underlying function type to which the lambda can
   * be converted, a second typedef is provided named `actual_type` that keeps
   * the tags in the return type and still include their respective calling
   * convention! One exception to be note is lambdas tagged with
   * `utils::thiscall` in which case the old tag will be replaced by a different
   * implementation tag and no calling convention will be added. The reason
   * being the MSVC doesn't like `__thiscall` used on function types.
   */
  template <typename T>
  struct captureless_lambda_func_type
      : helpers::captureless_lambda_clean_type_impl<decltype(&T::operator())>
  {
  };

  /// Alias for @ref alterhook::utils::captureless_lambda_func_type
  template <typename T>
  using capturless_lambda_func_type_t =
      typename captureless_lambda_func_type<T>::type;

  /// Alias for @ref alterhook::utils::captureless_lambda_func_type but uses the
  /// other typedef instead
  template <typename T>
  using captureless_lambda_actual_func_type_t =
      typename captureless_lambda_func_type<T>::actual_type;

  /**
   * @brief Removes constness and references via `remove_cvref_t` on any type
   * passed. On function pointers it calls `std::remove_pointer_t` to get back a
   * function type and on capturless lambdas it uses
   * `captureless_lambda_func_type` to get the underlying function type of the
   * lambda.
   * @tparam T the type to use (can be anything).
   * @note On 32-bit windows when `T` is a function pointer with the
   * `__thiscall` calling convention the result type is a function type with
   * same args and specifiers but with the return type replaced by a custom
   * internal tag that denotes the said calling convention. The reason for doing
   * this is that MSVC does not accept function types with this calling
   * convention applied.
   */
  template <typename T>
  struct clean_type : helpers::clean_type_impl<remove_cvref_t<T>>
  {
  };

  /// Alias for @ref alterhook::utils::clean_type
  template <typename T>
  using clean_type_t = typename clean_type<T>::type;

  /**
   * @brief Takes any type and evaluates to true when `T` is a function
   * type/pointer, a member function pointer or an instance of `std::function`,
   * false otherwise.
   * @tparam T the type to use (can be anything).
   * @note constness and references are removed before checking.
   */
  template <typename T>
  utils_concept function_type =
      std::is_function_v<clean_type_t<T>> ||
      std::is_member_function_pointer_v<remove_cvref_t<T>> ||
      stl_function_type<T>;

  /**
   * @brief Takes any type and evaluates to true when `T` either meets the
   * requirements of @ref alterhook::utils::function_type or has the
   * `operator()` defined.
   * @tparam T the type to use (can be anything).
   */
  template <typename T>
  utils_concept callable_type =
      function_type<T> || helpers::no_ambiguous_callable<remove_cvref_t<T>>;

  /**
   * @brief Takes any type that meets the requirements of
   * @ref alterhook::utils::callable_type and defines a few members that contain
   * info about the callable type specified.
   * @tparam T the callable type to use
   */
  template <typename T>
  struct function_traits : helpers::function_traits_impl<remove_cvref_t<T>>
  {
#ifdef RUNNING_DOXYGEN
    /// Specifies the return type of the callable.
    typedef get_return_type_t<i, T> return_type;
    /// Specifies the number of arguments the callable has.
    static constexpr size_t         arity;
    /**
     * @brief Gets the argument at index `i`.
     * @tparam i the index of the argument to access.
     */
    template <size_t i>
    using argument = get_argument_t<i, T>;
    /**
     * @brief Specifies whether the type passed is a callable object or just a
     * function-like type.
     * @note `std::function` is treated as a function type rather than a
     * callable type.
     */
    static constexpr bool               object;
    /// Holds an enum value specifying the calling convention of the callable
    /// passed.
    static constexpr calling_convention calling_convention;
#endif
  };

  /// Gets the return type of the callable type `T`
  template <typename T>
  using fn_return_t = typename function_traits<T>::return_type;
  /// Gets the amount of arguments the callable type `T` accepts
  template <typename T>
  inline constexpr size_t fn_arity_v = function_traits<T>::arity;
  /**
   * @brief Gets the argument type of the callable type `T` at index `i`
   * @tparam T the callable type to use
   * @tparam i the index of the argument type
   */
  template <typename T, size_t i>
  using fn_argument_t = typename function_traits<T>::template argument<i>;
  /// Evaluates to true if the callable type `T` is an object, false otherwise.
  template <typename T>
  inline constexpr bool fn_object_v = function_traits<T>::object;
#if utils_cc_assertions
  /// Evaluates to an enum value that specifies the type of calling convention
  /// the callable type `T` uses.
  template <typename T>
  inline constexpr calling_convention fn_calling_convention_v =
      function_traits<T>::calling_convention;
#endif
  /// Gets the class type from the member function pointer `T`
  template <typename T>
  using fn_class_t =
      std::remove_const_t<std::remove_pointer_t<fn_argument_t<T, 0>>>;

#if utils_cc_assertions
  /**
   * @brief Checks if the calling conventions of the callable types `T1` and
   * `T2` are compatible which is true if they are equal or one of them is
   * `__fastcall` and the other `__thiscall`.
   * @tparam T1 the first callable type to use
   * @tparam T2 the second callable type to use
   * @note argument count and other factors are not checked, only the calling
   * conventions. See @ref alterhook::utils::compatible_function_arguments_with
   * for a more accurate result.
   */
  template <typename T1, typename T2>
  utils_concept compatible_calling_convention_with =
      helpers::compatible_calling_convention_with_impl<T1, T2>;
#endif

  /**
   * @brief Checks if the arguments of `fn_1` are compatible with those of
   * `fn_2`.
   * @tparam fn_1 the first callable type to use
   * @tparam fn_2 the second callable type to use
   *
   * On platforms other than 32-bit windows this basically just checks if the
   * arguments of both are identical. On 32-bit windows however, calling
   * conventions are taken into account. So for example when you want to
   * determine compatibility between a `__fastcall` and a `__thiscall` function,
   * this concept requires that the `__fastcall` function has an additional
   * argument placed after the first one that is of size equal to
   * `sizeof(void*)` and is unused. The rest of arguments of `__fastcall` should
   * be identical to those of `__thiscall` (and in the same order). Now if the
   * first template parameter is the one with `__thiscall` and not the second it
   * instead requires that both accept only one argument and that it's the same
   * one.
   */
  template <typename fn_1, typename fn_2>
  utils_concept compatible_function_arguments_with =
      helpers::have_compatible_fn_args<fn_1, fn_2>();

  /// Check if `T` is a member function pointer.
  template <typename T>
  utils_concept member_function_type = std::is_member_function_pointer_v<T>;

  /// Same as @ref alterhook::utils::capturless_lambda_func_type_t except it
  /// evaluates to a function pointer instead of a function type. And it also
  /// replaces the internal thiscall tag with the actual calling convention.
  template <typename T>
  using captureless_lambda_func_ptr_type_t =
      typename helpers::add_thiscall_if_needed<
          std::add_pointer_t<capturless_lambda_func_type_t<T>>>::type;

  /// Same as @ref alterhook::utils::captureless_lambda_func_ptr_type_t except
  /// it uses the other typedef.
  template <typename T>
  using captureless_lambda_actual_func_ptr_type_t =
      typename helpers::add_thiscall_if_needed<
          std::add_pointer_t<captureless_lambda_actual_func_type_t<T>>>::type;

  namespace helpers
  {
#define __utils_clean_function(calling_convention, cv, ref, exception)         \
  template <typename R, typename... args>                                      \
  struct clean_function_type_helper<R          calling_convention(args...)     \
                                        cv ref exception>                      \
  {                                                                            \
    typedef R type(args...);                                                   \
  };

#define __utils_clean_member_function(calling_convention, cv, ref, exception)  \
  template <typename R, typename cls, typename... args>                        \
  struct clean_function_type_helper<R (calling_convention cls::*)(args...)     \
                                        cv ref exception>                      \
  {                                                                            \
    typedef R type(cv cls*, args...);                                          \
  };

#define __utils_clean_stl_function(calling_convention, cv, ref, exception)     \
  template <typename R, typename... args>                                      \
  struct clean_function_type_helper<                                           \
      std::function<R calling_convention(args...) cv ref exception>>           \
  {                                                                            \
    typedef R type(args...);                                                   \
  };

    __utils_non_member_call_cv_ref_noexcept(__utils_clean_stl_function);
    __utils_non_member_call_cv_ref_noexcept(__utils_clean_function);
    __utils_member_call_cv_ref_noexcept(__utils_clean_member_function);

    template <typename T>
    struct unwrap_stl_function_impl<std::function<T>>
    {
      typedef T type;
    };

    template <typename R, typename first, typename... rest>
    struct remove_first_arg<R(first, rest...)>
    {
      typedef R type(rest...);
    };

#if !utils_cpp20
    template <typename T>
    inline constexpr bool captureless_lambda_impl<
        T, std::void_t<
               decltype(&T::operator()),
               clean_function_type_t<decltype(&T::operator())>,
               decltype(static_cast<std::add_pointer_t<remove_first_arg_t<
                            clean_function_type_t<decltype(&T::operator())>>>>(
                   std::declval<T>()))>> = true;
#endif

#define __utils_forward_cv(func, exception)                                    \
  func(const, exception) func(, exception)
#define __utils_gen_clct_impl_overloads(func)                                  \
  __utils_forward_cv(func, ) __utils_forward_cv(func, noexcept)

    template <typename T>
    struct captureless_lambda_clean_type_impl
    {
      typedef remove_first_arg_t<clean_function_type_t<T>> type, actual_type;
    };

#if utils_cc_assertions
  #define __utils_clct_impl(cc, cc_val, cv, exception)                         \
    template <typename R, typename cls, typename... args>                      \
    struct captureless_lambda_clean_type_impl<value_wrapper<                   \
        R, calling_convention::cc_val> (cls::*)(args...) cv exception>         \
    {                                                                          \
      typedef R cc type(args...) exception;                                    \
      typedef value_wrapper<R, calling_convention::cc_val>                     \
          cc actual_type(args...) exception;                                   \
    };

  #define __utils_clct_thiscall_impl(cc, cc_val, cv, exception)                \
    template <typename R, typename cls, typename... args>                      \
    struct captureless_lambda_clean_type_impl<value_wrapper<                   \
        R, calling_convention::cc_val> (cls::*)(args...) cv exception>         \
    {                                                                          \
      typedef thiscall_pfn_tag<R> type(args...) exception;                     \
      typedef thiscall_pfn_tag<value_wrapper<R, calling_convention::cc_val>>   \
          actual_type(args...) exception;                                      \
    };

  #define __utils_emit_cc(cv, exception)                                       \
    __utils_emit_cdecl(__utils_clct_impl, __CDECL, cv, exception)              \
        __utils_emit_clrcall(__utils_clct_impl, __CLRCALL, cv, exception)      \
            __utils_emit_fastcall(__utils_clct_impl, __FASTCALL, cv,           \
                                  exception)                                   \
                __utils_emit_stdcall(__utils_clct_impl, __STDCALL, cv,         \
                                     exception)                                \
                    __utils_emit_thiscall(__utils_clct_thiscall_impl,          \
                                          __THISCALL, cv, exception)           \
                        __utils_emit_vectorcall(__utils_clct_impl,             \
                                                __VECTORCALL, cv, exception)
    __utils_gen_clct_impl_overloads(__utils_emit_cc);
#endif

    template <typename T>
    inline constexpr bool simple_function_v = false;
    template <typename R, typename... args>
    inline constexpr bool simple_function_v<R(args...)> = true;

    template <typename T>
    struct function_traits_impl<T, std::enable_if_t<no_ambiguous_callable<T>>>
    {
      typedef function_traits_impl<clean_function_type_t<call_overload_t<T>>>
                                              call_type;
      typedef typename call_type::return_type return_type;
      static constexpr size_t                 arity = call_type::arity;
      template <size_t i>
      using argument               = typename call_type::template argument<i>;
      static constexpr bool object = true;
#if utils_cc_assertions
      static constexpr calling_convention calling_convention =
          get_calling_convention<call_overload_t<T>>();
#endif
    };

    template <typename T>
    struct function_traits_impl<
        T, std::enable_if_t<function_type<T> && !simple_function_v<T>>>
        : function_traits_impl<clean_function_type_t<T>>
    {
#if utils_cc_assertions
      static constexpr calling_convention calling_convention =
          get_calling_convention<T>();
#endif
    };

    template <typename R, typename... args>
    struct function_traits_impl<R(args...), void>
    {
      typedef R               return_type;
      static constexpr size_t arity = sizeof...(args);
      template <size_t i>
      using argument               = type_at_t<i, args...>;
      static constexpr bool object = false;
    };

#if utils_cc_assertions
    template <typename R, typename... args>
    struct function_traits_impl<thiscall_pfn_tag<R>(args...), void>
        : function_traits_impl<R(args...)>
    {
    };
#endif

    template <typename T, typename>
    struct clean_type_impl
    {
      typedef T type;
    };

    template <typename T>
    struct clean_type_impl<
        T, std::enable_if_t<std::is_function_v<std::remove_pointer_t<T>>>>
        : std::remove_pointer<T>
    {
    };

    template <typename T>
    struct clean_type_impl<T, std::enable_if_t<captureless_lambda<T>>>
        : captureless_lambda_func_type<T>
    {
    };

#if utils_cc_assertions
    template <typename R, typename... args>
    struct clean_type_impl<R(__thiscall*)(args...), void>
    {
      typedef thiscall_pfn_tag<R> type(args...);
    };

    template <typename R, typename... args>
    struct clean_type_impl<R(__thiscall*)(args...) noexcept, void>
    {
      typedef thiscall_pfn_tag<R> type(args...) noexcept;
    };
#endif

    template <typename T>
    inline constexpr bool
        no_ambiguous_callable<T, std::void_t<call_overload_t<T>>> =
            !stl_function_type<T>;

    template <typename T>
    inline constexpr bool is_stl_function_impl<std::function<T>> = true;

#if utils_cc_assertions
    template <typename T1, typename T2>
    inline constexpr bool compatible_calling_convention_with_impl<
        T1, T2, std::enable_if_t<callable_type<T1> && callable_type<T2>>> =
        fn_calling_convention_v<T1> == fn_calling_convention_v<T2> ||
        (any_of(calling_convention::__THISCALL, fn_calling_convention_v<T1>,
                fn_calling_convention_v<T2>) &&
         any_of(calling_convention::__FASTCALL, fn_calling_convention_v<T1>,
                fn_calling_convention_v<T2>));
#endif

    template <typename T1, typename T2>
    utils_concept are_member_function_pointers =
        std::is_member_function_pointer_v<T1> &&
        std::is_member_function_pointer_v<T2>;
    template <typename T1, typename T2>
    utils_concept has_any_mem_func_ptr =
        std::is_member_function_pointer_v<T1> ||
        std::is_member_function_pointer_v<T2>;

    template <typename T1, typename T2>
    utils_concept are_pointers = std::is_pointer_v<T1> && std::is_pointer_v<T2>;

    template <typename PT1, typename PT2,
              typename T1 = std::remove_pointer_t<PT1>,
              typename T2 = std::remove_pointer_t<PT2>>
    utils_concept have_this =
        are_pointers<PT1, PT2> &&
        (std::is_base_of_v<T1, T2> ||
         std::is_base_of_v<T2, T1>)&&same_cv_qualification_v<T1, T2>;

    template <typename seq, typename fn_1, typename fn_2>
    inline constexpr bool all_arguments_same_check =
        undefined_struct<seq, fn_1, fn_2>::value;
    template <size_t... indexes, typename fn_1, typename fn_2>
    inline constexpr bool
        all_arguments_same_check<std::index_sequence<indexes...>, fn_1, fn_2> =
            (std::is_same_v<fn_argument_t<fn_1, indexes>,
                            fn_argument_t<fn_2, indexes - 1>> &&
             ...);

    template <typename seq, typename fn_1, typename fn_2, bool member_fn>
    inline constexpr bool all_arguments_same_check_2_impl =
        undefined_struct<seq, fn_1, fn_2>::value;
    // handles case where either detour or original is member function (we need
    // to check if the first arg with is the this pointer is of type that has
    // any relationship with the other one and have equal size)
    template <size_t index, size_t... indexes, typename fn_1, typename fn_2>
    inline constexpr bool all_arguments_same_check_2_impl<
        std::index_sequence<index, indexes...>, fn_1, fn_2, true> =
        have_this<remove_cvref_t<fn_argument_t<fn_1, index>>,
                  remove_cvref_t<fn_argument_t<fn_2, index>>> &&
        (std::is_same_v<fn_argument_t<fn_1, indexes>,
                        fn_argument_t<fn_2, indexes>> &&
         ...);
    template <size_t... indexes, typename fn_1, typename fn_2>
    inline constexpr bool all_arguments_same_check_2_impl<
        std::index_sequence<indexes...>, fn_1, fn_2, false> =
        (std::is_same_v<fn_argument_t<fn_1, indexes>,
                        fn_argument_t<fn_2, indexes>> &&
         ...);

    template <typename seq, typename fn_1, typename fn_2>
    inline constexpr bool all_arguments_same_check_2 =
        all_arguments_same_check_2_impl<seq, fn_1, fn_2,
                                        has_any_mem_func_ptr<fn_1, fn_2>>;

#if utils_cpp20
    template <typename T1, typename T2>
    concept have_compatible_member_fn_first_args =
        requires {
          typename fn_argument_t<T1, 0>;
          typename fn_argument_t<T2, 0>;
        } && have_this<std::remove_cvref_t<fn_argument_t<T1, 0>>,
                       std::remove_cvref_t<fn_argument_t<T2, 0>>>;

    template <typename T1, typename T2>
    concept have_all_args_same =
        fn_arity_v<T1> == fn_arity_v<T2> &&
        all_arguments_same_check_2<std::make_index_sequence<fn_arity_v<T1>>, T1,
                                   T2>;
#else
    template <typename T1, typename T2, typename = void>
    inline constexpr bool have_compatible_member_fn_first_args = false;
    template <typename T1, typename T2>
    inline constexpr bool have_compatible_member_fn_first_args<
        T1, T2, std::void_t<fn_argument_t<T1, 0>, fn_argument_t<T2, 0>>> =
        have_this<remove_cvref_t<fn_argument_t<T1, 0>>,
                  remove_cvref_t<fn_argument_t<T2, 0>>>;

    namespace helpers
    {
      template <typename T1, typename T2,
                bool = fn_arity_v<T1> == fn_arity_v<T2>>
      inline constexpr bool have_all_args_same_impl = false;

      template <typename T1, typename T2>
      inline constexpr bool have_all_args_same_impl<T1, T2, true> =
          all_arguments_same_check_2<std::make_index_sequence<fn_arity_v<T1>>,
                                     T1, T2>;
    } // namespace helpers

    template <typename T1, typename T2>
    inline constexpr bool have_all_args_same =
        helpers::have_all_args_same_impl<T1, T2>;
#endif

#if utils_cpp20
    template <typename T1, typename T2>
    concept have_all_fastcall_args_compatible_with_thiscall =
        have_compatible_member_fn_first_args<T1, T2> &&
        requires { typename fn_argument_t<T1, 1>; } &&
        sizeof(fn_argument_t<T1, 1>) == sizeof(void*) &&
        fn_arity_v<T2> == (fn_arity_v<T1> - 1) &&
        all_arguments_same_check<make_index_sequence_t<fn_arity_v<T1>, 2>, T1,
                                 T2>;
#else
    template <typename T1, typename T2,
              bool = fn_arity_v<T2> == (fn_arity_v<T1> - 1), typename = void>
    inline constexpr bool have_all_fastcall_args_compatible_with_thiscall =
        false;
    template <typename T1, typename T2>
    inline constexpr bool have_all_fastcall_args_compatible_with_thiscall<
        T1, T2, true, std::void_t<fn_argument_t<T1, 1>>> =
        have_compatible_member_fn_first_args<T1, T2> &&
        sizeof(fn_argument_t<T1, 1>) == sizeof(void*) &&
        all_arguments_same_check<make_index_sequence_t<fn_arity_v<T1>, 2>, T1,
                                 T2>;
#endif

    utils_consteval bool is_lambda(std::string_view type) noexcept
    {
      return type.find("lambda") != std::string_view::npos &&
             (type.find(' ') != std::string_view::npos ||
              type.find('(') != std::string_view::npos);
    }

    /*
     * on windows x86 verify that arguments are compatible
     * that means for example if you are trying to hook a thiscall function of
     * arity greater than 1 with a fastcall one you should include an argument
     * of size == sizeof(void*) as a second argument to avoid issues. on other
     * platforms we just check that all arguments are identical, no calling
     * convention headache for them
     */
    template <typename T1, typename T2>
    utils_consteval bool have_compatible_fn_args()
    {
#if utils_cc_assertions
      if constexpr (!compatible_calling_convention_with<T1, T2> ||
                    fn_calling_convention_v<T1> == fn_calling_convention_v<T2>)
        return have_all_args_same<T1, T2>;
      else
      {
        if constexpr (fn_calling_convention_v<T1> ==
                      calling_convention::__FASTCALL)
        {
          if constexpr (fn_arity_v<T2> == 1)
            return fn_arity_v<T1> == fn_arity_v<T2> &&
                   have_compatible_member_fn_first_args<T1, T2>;
          else
            return have_all_fastcall_args_compatible_with_thiscall<T1, T2>;
        }
        else if constexpr (fn_arity_v<T1> == 1 &&
                           fn_arity_v<T1> == fn_arity_v<T2>)
          return have_compatible_member_fn_first_args<T1, T2>;
        return false;
      }
#else
      return have_all_args_same<T1, T2>;
#endif
    }

    template <typename T>
    struct add_thiscall_if_needed
    {
      typedef T type;
    };

#if utils_cc_assertions
    template <typename R, typename... args>
    struct add_thiscall_if_needed<thiscall_pfn_tag<R> (*)(args...)>
    {
      typedef R(__thiscall* type)(args...);
    };

    template <typename R, typename... args>
    struct add_thiscall_if_needed<thiscall_pfn_tag<R> (*)(args...) noexcept>
    {
      typedef R(__thiscall* type)(args...) noexcept;
    };
#endif
  } // namespace helpers
} // namespace alterhook::utils
