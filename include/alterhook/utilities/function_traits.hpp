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
    template <template <typename> typename patcher, typename func>
    struct func_patcher;
    template <typename callable, typename func, typename = void>
    struct generic_callable_disambiguation_type;
    template <typename callable, typename func, typename = void>
    struct try_disambiguate_impl;
    template <template <typename> typename patcher, typename func>
    using func_patcher_t = typename func_patcher<patcher, func>::type;
    template <typename T>
    inline constexpr bool is_stl_function_impl = false;
    template <typename T, typename = void>
    inline constexpr bool no_ambiguous_callable = false;
    template <typename T>
    using remove_first_arg_t = typename remove_first_arg<T>::type;
    template <typename T>
    using call_overload_t = decltype(&T::operator());
#if utils_cc_assertions
    template <typename T>
    using add_thiscall_if_needed_t = typename add_thiscall_if_needed<T>::type;
    template <typename T1, typename T2, typename = void>
    inline constexpr bool compatible_calling_convention_with_impl = false;
#else
    template <typename T>
    using add_thiscall_if_needed_t = T;
#endif
#if !utils_cpp20
    template <typename T, typename = void>
    inline constexpr bool captureless_lambda_impl = false;
#endif
    utils_consteval bool is_lambda(std::string_view type) noexcept;
    template <typename T1, typename T2>
    utils_consteval bool have_compatible_fn_args();
#if !utils_cpp20
    template <typename lambda, typename func>
    struct lambda_disambiguatable_with_impl;
    template <typename callable, typename func>
    struct callable_disambiguatable_with_impl;
#endif
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

  /// Takes any type and evaluates to true if `T` is a lambda type
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

  /// @brief Alias for @ref alterhook::utils::captureless_lambda_func_type but
  /// uses the other typedef instead
  template <typename T>
  using captureless_lambda_actual_func_type_t =
      typename captureless_lambda_func_type<T>::actual_type;

  /**
   * @brief Removes constness and references on any type passed, converts
   * function pointers to function types and tries to get the underlying
   * function-like type from callable objects.
   * @tparam T the type to use (can be anything).
   *
   * Getting the underlying function-like type out of a callable object involves
   * two steps:
   * - First is checking if it meets the requirements of a captureless lambda by
   *   whether it satisfies @ref alterhook::utils::captureless_lambda. If it
   *   does then it uses @ref alterhook::utils::captureless_lambda_func_type to
   *   get the type it can be converted to.
   * - If the above didn't work out it checks if the expression `&T::operator()`
   *   is a valid expression. If it is, then it defines the member function
   *   pointer type of the above expression.
   * If none of the above worked, it's either an object that doesn't define
   * `operator()` or its definition is ambiguous (i.e. templated or overloaded)
   * so it defines it as is.
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
   * @brief Takes a callable type and defines a member function pointer to which
   * its overload of `operator()` can safely be casted based on the
   * function-like type `func`. Otherwise defines nothing and can be used to
   * trigger sfinae.
   * @tparam callable the callable type to check, must be an object that defines
   * at least one overload of `operator()` either templated or not and it must
   * not be an instance of `std::function`.
   * @tparam func the function-like type which will be used as a template to
   * form the member function pointer, it must satisfy
   * @ref alterhook::utils::function_type and must include the implicit `this`
   * pointer either as a first argument on a regular function type/pointer or as
   * the class type of a member function pointer which is allowed to be
   * different than `callable`.
   *
   * The process of forming the member function pointer involves the following
   * steps:
   * - decompose `func` and copy all of its properties which include:
   *   + All arguments but the implicit `this` pointer
   *   + The return type
   *   + the cv qualification from either the implicit `this` of `func` that was
   *     excluded or from the specifiers if it's a member function pointer (the
   *     latter is preferred when available)
   *   + the noexcept specifier
   *   + any calling conventions on windows 32-bit (including `__thiscall`)
   *   to the formed member function pointer.
   * - replace the class type of the member function pointer with `callable`.
   * @note It is not actually checked whether the overload of `operator()` can
   * be converted to the type defined (for that see
   * @ref alterhook::utils::disambiguatable_callable_with), all it does is
   * forming a member function pointer based on the rules mentioned. If either
   * `func` or `callable` do not comply with those rules nothing will be
   * defined, and sfinae may be triggered when possible.
   * @par Example
   * @code{.cpp}
   * struct prototype
   * {
   *   template <typename T>
   *   void operator()(T var) const
   *   {
   *     std::cout << var;
   *   }
   * };
   *
   * void func()
   * {
   *   // note the implicit this is ignored for `func` therefore it doesn't
   * matter
   *   // that we are using void*, what matters is that it's const which will
   *   // make the result marked as const as well.
   *   typedef alterhook::utils::generic_callable_disambiguation_type_t<
   *       prototype, void(__thiscall*)(const void*, int)>
   *       type;
   *   // should work
   *   auto var = static_cast<type>(&prototype::operator());
   * }
   * @endcode
   */
  template <typename callable, typename func>
  using generic_callable_disambiguation_type_t =
      typename helpers::generic_callable_disambiguation_type<
          remove_cvref_t<callable>, remove_cvref_t<func>>::type;

  /**
   * @brief Takes a function-like type and forms a function pointer to which a
   * generic lambda (or a user-defined type that mimics one) can be converted
   * using its conversion operator.
   * @tparam func the function-like type based on which the function pointer
   * will be formed (must satisfy @ref alterhook::utils::function_type)
   *
   * The process of forming the function pointer involves copying all of the
   * properties of `func` (which include the calling convention, the return
   * type, the argument types and the noexcept specifier) to the type formed. If
   * `func` is a member function pointer then the implicit `this` is added as a
   * first parameter with any cv specifiers provided.
   * @note Since it does not accept any callable as an argument it does not
   * check whether the callable of interest can be converted to the type formed
   * either (see @ref alterhook::utils::disambiguatable_lambda_with for that).
   * @par Example
   * @code{.cpp}
   * auto lambda = [](auto var) { return var; };
   * // note `__fastcall` is optional here, as lambdas can be converted to a
   * // function pointer of any calling convention
   * typedef alterhook::utils::generic_lambda_disambiguation_type_t<int
   *     __fastcall(int)> type;
   *
   * auto raw_func = static_cast<type>(lambda);
   * // should print 5
   * std::cout << raw_func(5) << '\n';
   * @endcode
   */
  template <typename func>
  using generic_lambda_disambiguation_type_t =
      helpers::add_thiscall_if_needed_t<std::add_pointer_t<
          helpers::func_patcher_t<type_identity_t, remove_cvref_t<func>>>>;

#if utils_cpp20
  /**
   * @brief Checks if `lambda` is a possible generic lambda (or it mimics one)
   * by ensuring that `operator()` cannot be accessed normally but it is
   * possible to cast the callable type to a function pointer generated from
   * `func`.
   * @tparam lambda the type to check (can be any type)
   * @tparam func the function-like type from which a function pointer will be
   * generated (should satisfy @ref alterhook::utils::function_type or otherwise
   * this concept yields false regardless of `lambda`)
   *
   * As mentioned, the type `lambda` may not necessarily be a lambda type and
   * still yield true. All it checks for is whether static casting the instance
   * to a function pointer generated from `func` is a valid expression, that is
   * when `lambda` is a type that defines a conversion operator to a function
   * pointer. This is always true for **captureless lambdas** regardless if they
   * are generic or not. Therefore in order to only yield true for generic
   * lambdas (or types that mimic them), `&lambda::operator()` should be an
   * invalid expression.
   *
   * The function-like type `func` does not necessarily have to be a function
   * pointer but the one generated from it is. See
   * @ref alterhook::utils::generic_lambda_disambiguation_type_t to get an idea
   * about how the function pointer is generated.
   * @note For generic lambdas that are NOT captureless this will always yield
   * false as they don't define a conversion operator. This is also true for
   * user-defined types that do not define a conversion operator to a function
   * pointer either.
   */
  template <typename lambda, typename func>
  concept disambiguatable_lambda_with =
      !requires { &lambda::operator(); } && requires(lambda instance) {
        static_cast<generic_lambda_disambiguation_type_t<func>>(instance);
      };

  /**
   * @brief Checks if the `operator()` overload of the callable type `callable`
   * can be disambiguated by static casting it to a member function pointer
   * which is generated based on `func`. Yields false if the overload can be
   * accessed normally (i.e. it's not ambiguous).
   * @tparam callable the callable type with the ambiguous overload of
   * `operator()`. The concept yields false if it satisfies either
   * @ref alterhook::utils::function_type or
   * @ref alterhook::utils::callable_type.
   * @tparam func the function-like type from which the member function pointer
   * will be generated (see
   * @ref alterhook::utils::generic_callable_disambiguation_type_t for how this
   * is done). The concept yields false if it does not satisfy
   * @ref alterhook::utils::function_type.
   *
   * Unlike @ref alterhook::utils::disambiguatable_lambda_with which checks if a
   * conversion operator is provided, this one directly accesses the
   * `operator()` and therefore does not require any conversion operator to be
   * provided. As mentioned though, the overload should not be accessible
   * normally but through a static cast to the member function pointer formed.
   * If this requirement isn't meant, it yields false.
   * @note This should NOT be used for captureless generic lambdas as they
   * provide a conversion operator to a function pointer independent of the
   * lambda instance (unlike the `operator()` overload which takes the implicit
   * `this` pointer). Use @ref alterhook::utils::disambiguatable_lambda_with
   * instead.
   */
  template <typename callable, typename func>
  concept disambiguatable_callable_with =
      !requires { &callable::operator(); } && requires {
        static_cast<generic_callable_disambiguation_type_t<callable, func>>(
            &callable::operator());
      };
#else
  template <typename lambda, typename func>
  inline constexpr bool disambiguatable_lambda_with =
      helpers::lambda_disambiguatable_with_impl<lambda, func>::value;

  template <typename callable, typename func>
  inline constexpr bool disambiguatable_callable_with =
      helpers::callable_disambiguatable_with_impl<callable, func>::value;
#endif

  /// @brief checks if either @ref alterhook::utils::disambiguatable_lambda_with
  /// or @ref alterhook::utils::disambiguatable_callable_with is satisfied using
  /// the two types passed.
  template <typename callable, typename func>
  utils_concept disambiguatable_with =
      disambiguatable_lambda_with<callable, func> ||
      disambiguatable_callable_with<callable, func>;

  /// @brief tries to disambiguate `callable` with `func` using either
  /// @ref alterhook::utils::generic_lambda_disambiguation_type_t or
  /// @ref alterhook::utils::generic_callable_disambiguation_type_t and defines
  /// the result. On failure it defines `callable` itself.
  template <typename callable, typename func>
  using try_disambiguate_t =
      typename helpers::try_disambiguate_impl<callable, func>::type;

  /**
   * @brief Takes any type that meets the requirements of
   * @ref alterhook::utils::callable_type and defines a few members that contain
   * info about the callable type specified.
   * @tparam T the callable type to use
   */
  template <typename T>
  struct function_traits : helpers::function_traits_impl<clean_type_t<T>>
  {
    /// @brief specifies whether `T` is an object (which is true when
    /// @ref alterhook::utils::function_type is not satisfied)
    static constexpr bool object = !function_type<T>;
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

  /// @brief Just like `std::add_pointer_t` except it also handles the internal
  /// thiscall tag
  template <typename T>
  using add_pointer_t =
      helpers::add_thiscall_if_needed_t<std::add_pointer_t<T>>;

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
#if utils_cc_assertions
    template <typename T>
    struct remove_pointer_and_thiscall : std::remove_pointer<T>
    {
    };

    template <typename R, typename... args>
    struct remove_pointer_and_thiscall<R(__thiscall*)(args...)>
    {
      typedef thiscall_pfn_tag<R> type(args...);
    };

    template <typename R, typename... args>
    struct remove_pointer_and_thiscall<R(__thiscall*)(args...) noexcept>
    {
      typedef thiscall_pfn_tag<R> type(args...) noexcept;
    };

    template <typename T>
    using remove_pointer_and_thiscall_t =
        typename remove_pointer_and_thiscall<T>::type;
#else
    template <typename T>
    using remove_pointer_and_thiscall = std::remove_pointer<T>;
    template <typename T>
    using remove_pointer_and_thiscall_t = std::remove_pointer_t<T>;
#endif

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

    template <typename T>
    struct clean_function_type_helper<std::function<T>>
        : clean_function_type_helper<T>
    {
    };

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

#define __utils_has_cv_const    ~, true,
#define __utils_has_cv_volatile ~, true,
#define __utils_has_cv(x)                                                      \
  __utils_check_expanded(utils_concat(__utils_has_cv_, x))

#if utils_cc_assertions
  #define __utils_func_patcher_thiscall_extra_overload_impl(cv, ref,           \
                                                            exception)         \
    template <typename R2, typename cls2, typename... args2,                   \
              typename original_arg, typename... original_args>                \
    static auto process(                                                       \
        type_identity<thiscall_pfn_tag<R2> (cls2::*)(args2...)>,               \
        type_identity<R(cv original_arg*, original_args...)>)                  \
        -> type_identity<R2 (__thiscall cls2::*)(args2...) cv ref exception>;
#else
  #define __utils_func_patcher_thiscall_extra_overload_impl(cv, ref, exception)
#endif

#define __utils_func_patcher_extra_overloads_impl(cc, cv, ref, exception)      \
  template <typename R2, typename cls2, typename... args2,                     \
            typename original_arg, typename... original_args>                  \
  static auto process(type_identity<R2 (cls2::*)(args2...)>,                   \
                      type_identity<R(cv original_arg*, original_args...)>)    \
      -> type_identity<R2 (cc cls2::*)(args2...) cv ref exception>;            \
  __utils_func_patcher_thiscall_extra_overload_impl(cv, ref, exception)
#define __utils_func_patcher_extra_overloads(cc, ref, exception)               \
  __utils_func_patcher_extra_overloads_impl(cc, , ref, exception)              \
      __utils_func_patcher_extra_overloads_impl(cc, const, ref, exception)     \
          __utils_func_patcher_extra_overloads_impl(cc, volatile, ref,         \
                                                    exception)                 \
              __utils_func_patcher_extra_overloads_impl(cc, const volatile,    \
                                                        ref, exception)

#define __utils_func_no_cv_overloads(cc, ref, exception)                       \
  template <typename T1, typename T2>                                          \
  static auto process(type_identity<T1>, type_identity<T2>)                    \
      -> decltype(process(std::declval<type_identity<T1>>()));                 \
  __utils_func_patcher_extra_overloads(cc, ref, exception) typedef             \
      typename decltype(process(                                               \
          std::declval<type_identity<patcher<R(args...)>>>(),                  \
          std::declval<type_identity<R(args...)>>()))::type type;

#define __utils_func_cv_overloads(...)                                         \
  typedef typename decltype(process(                                           \
      std::declval<type_identity<patcher<R(args...)>>>()))::type type;

#if utils_cc_assertions
  #define __utils_thiscall_process_overload(cv, ref, exception)                \
    template <typename R2, typename cls2, typename... args2>                   \
    static auto process(                                                       \
        type_identity<thiscall_pfn_tag<R2> (cls2::*)(args2...)>)               \
        -> type_identity<R2 (__thiscall cls2::*)(args2...) cv ref exception>;
#else
  #define __utils_thiscall_process_overload(cv, ref, exception)
#endif

#define __utils_func_patcher(cc, cv, ref, exception)                           \
  template <template <typename> typename patcher, typename R,                  \
            typename... args>                                                  \
  struct func_patcher<patcher, R cc(args...) cv ref exception>                 \
  {                                                                            \
    template <typename R2, typename... args2>                                  \
    static auto process(type_identity<R2(args2...)>)                           \
        -> type_identity<R2 cc(args2...) exception>;                           \
    template <typename R2, typename cls2, typename... args2>                   \
    static auto process(type_identity<R2 (cls2::*)(args2...)>)                 \
        -> type_identity<R2 (cc cls2::*)(args2...) cv ref exception>;          \
    __utils_thiscall_process_overload(cv, ref, exception)                      \
        utils_if(__utils_has_cv(cv _))(__utils_func_cv_overloads,              \
                                       __utils_func_no_cv_overloads)(          \
            cc, ref, exception)                                                \
  };

#define __utils_func_patcher_member_default(cc, cv, ref, exception)            \
  template <template <typename> typename patcher, typename R, typename cls,    \
            typename... args>                                                  \
  struct func_patcher<patcher, R (cc cls::*)(args...) cv ref exception>        \
      : func_patcher<patcher, R cc(cv cls*, args...) cv ref exception>         \
  {                                                                            \
  };

#define __utils_func_patcher_member_thiscall(cc, cv, ref, exception)           \
  template <template <typename> typename patcher, typename R, typename cls,    \
            typename... args>                                                  \
  struct func_patcher<patcher,                                                 \
                      R (__thiscall cls::*)(args...) cv ref exception>         \
      : func_patcher<patcher,                                                  \
                     thiscall_pfn_tag<R>(cv cls*, args...) cv ref exception>   \
  {                                                                            \
  };

    template <template <typename> typename patcher, typename T>
    struct func_patcher<patcher, std::function<T>> : func_patcher<patcher, T>
    {
    };

    template <template <typename> typename patcher, typename T,
              bool = std::is_function_v<remove_pointer_and_thiscall_t<T>>>
    struct func_patcher_or_empty
    {
    };

    template <template <typename> typename patcher, typename T>
    struct func_patcher_or_empty<patcher, T, true>
        : func_patcher<patcher, remove_pointer_and_thiscall_t<T>>
    {
    };

    // handle case where function pointer was passed
    template <template <typename> typename patcher, typename T>
    struct func_patcher : func_patcher_or_empty<patcher, T>
    {
    };

#if utils_cc_assertions
  #define __utils_func_patcher_member(cc, cv, ref, exception)                  \
    utils_if(utils_equal(cc, __thiscall))(                                     \
        __utils_func_patcher_member_thiscall,                                  \
        __utils_func_patcher_member_default)(cc, cv, ref, exception)
#else
  #define __utils_func_patcher_member(cc, cv, ref, exception)                  \
    __utils_func_patcher_member_default(cc, cv, ref, exception)
#endif

    __utils_non_member_call_cv_ref_noexcept(__utils_func_patcher);
    __utils_member_call_cv_ref_noexcept(__utils_func_patcher_member);

    template <typename callable, typename func>
    struct generic_callable_disambiguation_type<
        callable, func,
        std::enable_if_t<std::is_pointer_v<fn_argument_t<func, 0>> &&
                         !utils::function_type<callable>>>
    {
      template <typename R, typename othercls, typename... args>
      static auto process(type_identity<R(othercls, args...)>)
          -> type_identity<R (callable::*)(args...)>;

      template <typename T>
      using generic_callable_patcher_t =
          typename decltype(process(std::declval<type_identity<T>>()))::type;

      typedef func_patcher_t<generic_callable_patcher_t, func> type;
    };

#define __utils_forward_cv(func, exception)                                    \
  func(const, exception) func(, exception)
#define __utils_gen_clct_impl_overloads(func)                                  \
  __utils_forward_cv(func, ) __utils_forward_cv(func, noexcept)

    template <typename T>
    struct captureless_lambda_clean_type_impl
    {
      typedef remove_first_arg_t<clean_function_type_t<T>> type, actual_type;
    };

#if !utils_cpp20
    template <typename callable_t, typename func_t>
    struct disambiguatable_with_impl
    {
      template <typename callable = callable_t, typename func = func_t>
      static constexpr auto check_impl(rank<0>) -> rank<0>;
      template <typename callable = callable_t, typename func = func_t>
      static constexpr auto check_impl(rank<2>)
          -> decltype(&callable::operator(), rank<2>{});
    };

    template <typename lambda_t, typename func_t>
    struct lambda_disambiguatable_with_impl
        : disambiguatable_with_impl<lambda_t, func_t>
    {
      using disambiguatable_with_impl<lambda_t, func_t>::check_impl;
      template <typename lambda = lambda_t, typename func = func_t>
      static constexpr auto check_impl(rank<1>)
          -> decltype(static_cast<generic_lambda_disambiguation_type_t<func>>(
                          std::declval<lambda>()),
                      rank<1>{});

      static constexpr bool value = decltype(check_impl(rank<2>{}))::index == 1;
    };

    template <typename callable_t, typename func_t>
    struct callable_disambiguatable_with_impl
        : disambiguatable_with_impl<callable_t, func_t>
    {
      using disambiguatable_with_impl<callable_t, func_t>::check_impl;
      template <typename callable = callable_t, typename func = func_t>
      static constexpr auto check_impl(rank<1>)
          -> decltype(static_cast<generic_callable_disambiguation_type_t<
                          callable, func>>(&callable::operator()),
                      rank<1>{});

      static constexpr bool value = decltype(check_impl(rank<2>{}))::index == 1;
    };
#endif

    template <typename callable, typename func, typename>
    struct try_disambiguate_impl : type_identity<callable>
    {
    };

    template <typename callable, typename func>
    struct try_disambiguate_impl<
        callable, func, std::enable_if_t<disambiguatable_with<callable, func>>>
    {
      template <
          typename callable_t = callable, typename func_t = func,
          std::enable_if_t<disambiguatable_callable_with<callable_t, func_t>,
                           size_t> = 0>
      static auto select(rank<0>) -> type_identity<
          generic_callable_disambiguation_type_t<callable_t, func_t>>;

      template <
          typename callable_t = callable, typename func_t = func,
          std::enable_if_t<disambiguatable_lambda_with<callable_t, func_t>,
                           size_t> = 0>
      static auto select(rank<1>)
          -> type_identity<generic_lambda_disambiguation_type_t<func_t>>;

      typedef typename decltype(select(rank<1>{}))::type type;
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

#if utils_cc_assertions
    template <typename T>
    struct unwrap_thiscall_tag
    {
      typedef T type;
    };

    template <typename R>
    struct unwrap_thiscall_tag<thiscall_pfn_tag<R>>
    {
      typedef R type;
    };

    template <typename T>
    using unwrap_thiscall_tag_t = typename unwrap_thiscall_tag<T>::type;
#else
    template <typename T>
    using unwrap_thiscall_tag_t = T;
#endif

    template <typename T, typename>
    struct function_traits_impl
    {
    };

    template <typename T>
    struct function_traits_impl<
        T, std::enable_if_t<function_type<T> && !simple_function_v<T>>>
        : function_traits<clean_function_type_t<T>>
    {
#if utils_cc_assertions
      static constexpr calling_convention calling_convention =
          get_calling_convention<T>();
#endif
    };

    template <typename R, typename... args>
    struct function_traits_impl<R(args...), void>
    {
      typedef unwrap_thiscall_tag_t<R> return_type;
      static constexpr size_t          arity = sizeof...(args);
      template <size_t i>
      using argument = type_at_t<i, args...>;
#if utils_cc_assertions
      static constexpr calling_convention calling_convention =
          get_calling_convention<R(args...)>();
#endif
    };

    template <typename T, typename>
    struct clean_type_impl
    {
      typedef T type;
    };

    template <typename T>
    struct clean_type_impl<
        T,
        std::enable_if_t<std::is_function_v<remove_pointer_and_thiscall_t<T>>>>
        : remove_pointer_and_thiscall<T>
    {
    };

    template <typename T>
    struct clean_type_impl<T, std::enable_if_t<captureless_lambda<T>>>
        : captureless_lambda_func_type<T>
    {
    };

    template <typename T>
    struct clean_type_impl<
        T, std::enable_if_t<no_ambiguous_callable<T> && !captureless_lambda<T>>>
    {
      typedef call_overload_t<T> type;
    };

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

    utils_consteval bool is_lambda(std::string_view type) noexcept
    {
      return type.find("lambda") != std::string_view::npos &&
             (type.find(' ') != std::string_view::npos ||
              type.find('(') != std::string_view::npos);
    }

    template <typename T1, typename T2>
    utils_concept has_any_mem_func_ptr =
        std::is_member_function_pointer_v<T1> ||
        std::is_member_function_pointer_v<T2>;

    template <typename cls1, typename cls2>
    utils_concept compatible_implicit_this =
        same_cv_qualification_v<cls1, cls2> &&
        (std::is_base_of_v<cls1, cls2> || std::is_base_of_v<cls2, cls1>);

    template <typename T1, typename T2, bool = has_any_mem_func_ptr<T1, T2>,
              typename func1 = clean_function_type_t<clean_type_t<T1>>,
              typename func2 = clean_function_type_t<clean_type_t<T2>>>
    inline constexpr bool same_args = false;
    template <typename T1, typename T2, typename R1, typename R2, typename cls1,
              typename cls2, typename... args>
    inline constexpr bool
        same_args<T1, T2, true, R1(cls1*, args...), R2(cls2*, args...)> =
            compatible_implicit_this<cls1, cls2>;
    template <typename T1, typename T2, typename R1, typename R2,
              typename... args>
    inline constexpr bool same_args<T1, T2, false, R1(args...), R2(args...)> =
        true;

    template <typename T1, typename T2, bool = has_any_mem_func_ptr<T1, T2>,
              typename fastcallfunc = clean_function_type_t<clean_type_t<T1>>,
              typename thiscallfunc = clean_function_type_t<clean_type_t<T2>>>
    inline constexpr bool fastcall_with_thiscall_compatible_args = false;
    template <typename T1, typename T2, typename R1, typename R2, typename cls1,
              typename cls2, typename unused, typename... args>
    inline constexpr bool fastcall_with_thiscall_compatible_args<
        T1, T2, true, R1(cls1*, unused, args...), R2(cls2*, args...)> =
        compatible_implicit_this<cls1, cls2> &&
        sizeof(unused) == sizeof(void*) && sizeof...(args) != 0;
    template <typename T1, typename T2, typename R1, typename R2, typename cls1,
              typename cls2>
    inline constexpr bool fastcall_with_thiscall_compatible_args<
        T1, T2, true, R1(cls1*), R2(cls2*)> =
        compatible_implicit_this<cls1, cls2>;
    template <typename T1, typename T2, typename R1, typename R2,
              typename first, typename unused, typename... args>
    inline constexpr bool fastcall_with_thiscall_compatible_args<
        T1, T2, false, R1(first, unused, args...), R2(first, args...)> =
        sizeof(unused) == sizeof(void*) && sizeof...(args) != 0;
    template <typename T1, typename T2, typename R1, typename R2,
              typename first>
    inline constexpr bool fastcall_with_thiscall_compatible_args<
        T1, T2, false, R1(first), R2(first)> = true;

    template <typename T1, typename T2, bool = has_any_mem_func_ptr<T1, T2>,
              typename thiscallfunc = clean_function_type_t<clean_type_t<T1>>,
              typename fastcallfunc = clean_function_type_t<clean_type_t<T2>>>
    inline constexpr bool thiscall_with_fastcall_compatible_args = false;
    template <typename T1, typename T2, typename R1, typename R2, typename cls1,
              typename cls2>
    inline constexpr bool thiscall_with_fastcall_compatible_args<
        T1, T2, true, R1(cls1*), R2(cls2*)> =
        compatible_implicit_this<cls1, cls2>;
    template <typename T1, typename T2, typename R1, typename R2,
              typename... args>
    inline constexpr bool thiscall_with_fastcall_compatible_args<
        T1, T2, false, R1(args...), R2(args...)> = sizeof...(args) <= 1;

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
        return same_args<T1, T2>;
      else if constexpr (fn_calling_convention_v<T1> ==
                         calling_convention::__FASTCALL)
        return fastcall_with_thiscall_compatible_args<T1, T2>;
      else
        return thiscall_with_fastcall_compatible_args<T1, T2>;
#else
      return same_args<T1, T2>;
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
