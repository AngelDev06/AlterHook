/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include <cstddef>
#include <utility>
#include <functional>
#include "other.h"
#include "type_sequence.h"
#include "calling_conventions.h"

namespace alterhook::utils
{
  namespace helpers
  {
    template <typename T>
    struct clean_function_type_helper;

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

    __utils_non_member_call_cv_ref_noexcept(__utils_clean_stl_function)
        __utils_non_member_call_cv_ref_noexcept(__utils_clean_function)
            __utils_member_call_cv_ref_noexcept(__utils_clean_member_function)
  } // namespace helpers

  // takes any kind of function (including regular ones and methods) with any
  // calling convention/cv qualification/references/exception settings and
  // defines the clean function type which means that it's an as simple as
  // possible function type (includes none of what was mentioned above and looks
  // like "ret_type(args...)"). This is useful when we only care about its
  // return and argument types and want to do checks on them without having
  // overloads breaking.
  template <typename T>
  struct clean_function_type
      : helpers::clean_function_type_helper<std::remove_pointer_t<T>>
  {
  };

  template <typename T>
  using clean_function_type_t = typename helpers::clean_function_type_helper<
      std::remove_pointer_t<T>>::type;

  namespace helpers
  {
    template <typename T>
    inline constexpr bool is_stl_function_impl = false;

#define __utils_stl_fn_check(calling_convention, cv, ref, exception)           \
  template <typename R, typename... args>                                      \
  inline constexpr bool is_stl_function_impl<                                  \
      std::function<R calling_convention(args...) cv ref exception>> = true;

    __utils_non_member_call_cv_ref_noexcept(__utils_stl_fn_check)

        template <typename T>
        struct unwrap_stl_function_impl;

#define __utils_unwrap_stl_function(calling_convention, cv, ref, exception)    \
  template <typename R, typename... args>                                      \
  struct unwrap_stl_function_impl<                                             \
      std::function<R calling_convention(args...) cv ref exception>>           \
  {                                                                            \
    typedef R calling_convention type(args...) cv ref exception;               \
  };

    __utils_non_member_call_cv_ref_noexcept(__utils_unwrap_stl_function)
  } // namespace helpers

  template <typename T>
  inline constexpr bool is_stl_function_v =
      helpers::is_stl_function_impl<remove_cvref_t<T>>;

  template <typename T>
  struct is_stl_function
  {
    static constexpr bool value =
        helpers::is_stl_function_impl<remove_cvref_t<T>>;
  };

  template <typename T>
  utils_concept stl_function_type = is_stl_function_v<T>;

  template <typename T>
  struct unwrap_stl_function
      : std::add_pointer<
            typename helpers::unwrap_stl_function_impl<remove_cvref_t<T>>::type>
  {
  };

  namespace helpers
  {
    template <typename T>
    struct remove_first_arg;

    template <typename R, typename first, typename... rest>
    struct remove_first_arg<R(first, rest...)>
    {
      typedef R type(rest...);
    };

    template <typename T>
    using remove_first_arg_t = typename remove_first_arg<T>::type;

#if !utils_cpp20
    template <typename T, typename = void>
    inline constexpr bool captureless_lambda_impl = false;
    template <typename T>
    inline constexpr bool captureless_lambda_impl<
        T,
        std::void_t<
            decltype(&T::operator()),
            clean_function_type_t<decltype(&T::operator())>,
            decltype(static_cast<std::add_pointer_t<helpers::remove_first_arg_t<
                         clean_function_type_t<decltype(&T::operator())>>>>(
                std::declval<T>()))>> = true;
#endif
  } // namespace helpers

#if utils_cpp20
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

  namespace helpers
  {
    template <typename T>
    struct captureless_lambda_clean_type_impl;

#define __utils_forward_cv(func, exception)                                    \
  func(const, exception) func(, exception)
#define __utils_gen_clct_impl_overloads(func)                                  \
  __utils_forward_cv(func, ) __utils_forward_cv(func, noexcept)

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
    __utils_gen_clct_impl_overloads(__utils_emit_cc)
#endif

#define __utils_emit_non_cc(cv, exception)                                     \
  template <typename R, typename cls, typename... args>                        \
  struct captureless_lambda_clean_type_impl<R (cls::*)(args...) cv exception>  \
  {                                                                            \
    typedef R type(args...) exception;                                         \
    typedef R actual_type(args...) exception;                                  \
  };

        __utils_gen_clct_impl_overloads(__utils_emit_non_cc)
  } // namespace helpers

  template <typename T>
  struct captureless_lambda_func_type
      : helpers::captureless_lambda_clean_type_impl<decltype(&T::operator())>
  {
  };

  template <typename T>
  using capturless_lambda_func_type_t =
      typename captureless_lambda_func_type<T>::type;

  template <typename T>
  using captureless_lambda_actual_func_type_t =
      typename captureless_lambda_func_type<T>::actual_type;

  template <typename T>
  using unwrap_stl_function_t = typename unwrap_stl_function<T>::type;

  namespace helpers
  {
    template <typename T>
    using call_overload_t = decltype(&T::operator());
#if utils_cpp20
    template <typename T>
    concept no_ambiguous_callable =
        requires { typename call_overload_t<T>; } && !stl_function_type<T>;
#else
    template <typename T, typename = void>
    inline constexpr bool no_ambiguous_callable = false;
    template <typename T>
    inline constexpr bool
        no_ambiguous_callable<T, std::void_t<call_overload_t<T>>> =
            !stl_function_type<T>;
#endif

    template <typename T>
    struct function_traits_impl
    {
    public:
      typedef function_traits_impl<clean_function_type_t<call_overload_t<T>>>
                                              call_type;
      typedef typename call_type::return_type return_type;
      static constexpr size_t                 arity = call_type::arity;
      template <size_t i>
      using argument               = typename call_type::template argument<i>;
      static constexpr bool object = true;
    };

    template <typename R, typename... args>
    struct function_traits_impl<R(args...)>
    {
      typedef R               return_type;
      static constexpr size_t arity = sizeof...(args);
      template <size_t i>
      using argument               = type_at_t<i, args...>;
      static constexpr bool object = false;
    };

#if utils_cc_assertions
    template <typename R, typename... args>
    struct function_traits_impl<thiscall_pfn_tag<R>(args...)>
        : function_traits_impl<R(args...)>
    {
    };
#endif

#if utils_cpp20
    template <typename T>
    struct clean_type
    {
      typedef T type;
    };

    template <typename T>
    requires std::is_function_v<std::remove_pointer_t<T>>
    struct clean_type<T> : std::remove_pointer<T>
    {
    };

    template <captureless_lambda T>
    struct clean_type<T> : captureless_lambda_func_type<T>
    {
    };

  #if utils_cc_assertions
    template <typename R, typename... args>
    struct clean_type<R(__thiscall*)(args...)>
    {
      typedef thiscall_pfn_tag<R> type(args...);
    };

    template <typename R, typename... args>
    struct clean_type<R(__thiscall*)(args...) noexcept>
    {
      typedef thiscall_pfn_tag<R> type(args...) noexcept;
    };
  #endif
#else
    template <typename T, bool = std::is_function_v<std::remove_pointer_t<T>>,
              bool = captureless_lambda<T>>
    struct clean_type
    {
      typedef T type;
    };

    template <typename T>
    struct clean_type<T, true, false> : std::remove_pointer<T>
    {
    };

    template <typename T>
    struct clean_type<T, false, true>
    {
      typedef capturless_lambda_func_type_t<T> type;
    };

  #if utils_cc_assertions
    template <typename R, typename... args>
    struct clean_type<R(__thiscall*)(args...), false, false>
    {
      typedef thiscall_pfn_tag<R> type(args...);
    };

    template <typename R, typename... args>
    struct clean_type<R(__thiscall*)(args...) noexcept, false, false>
    {
      typedef thiscall_pfn_tag<R> type(args...) noexcept;
    };
  #endif
#endif
  } // namespace helpers

  template <typename T>
  struct clean_type : helpers::clean_type<T>
  {
  };

  template <typename T>
  using clean_type_t = typename clean_type<remove_cvref_t<T>>::type;

  template <typename T>
  utils_concept function_type =
      std::is_function_v<clean_type_t<T>> ||
      std::is_member_function_pointer_v<remove_cvref_t<T>> ||
      is_stl_function_v<T>;

  template <typename T>
  utils_concept callable_type =
      function_type<T> || helpers::no_ambiguous_callable<remove_cvref_t<T>>;

  template <typename T>
  utils_concept callable_but_stl_function =
      callable_type<T> && !stl_function_type<T>;

#if utils_cpp20
  template <typename T>
  struct function_traits;

  template <helpers::no_ambiguous_callable T>
  struct function_traits<T> : helpers::function_traits_impl<T>
  {
  #if utils_cc_assertions
    static constexpr calling_convention calling_convention =
        helpers::get_calling_convention<helpers::call_overload_t<T>>();
  #endif
  };

  template <function_type T>
  struct function_traits<T>
      : helpers::function_traits_impl<clean_function_type_t<T>>
  {
  #if utils_cc_assertions
    static constexpr calling_convention calling_convention =
        helpers::get_calling_convention<T>();
  #endif
  };
#else
  namespace helpers
  {
    template <typename T, typename = void>
    struct function_traits_sfinae;

    template <typename T>
    struct function_traits_sfinae<T, std::enable_if_t<no_ambiguous_callable<T>>>
        : function_traits_impl<T>
    {
  #if utils_cc_assertions
      static constexpr calling_convention calling_convention =
          get_calling_convention<call_overload_t<T>>();
  #endif
    };

    template <typename T>
    struct function_traits_sfinae<T, std::enable_if_t<function_type<T>>>
        : function_traits_impl<clean_function_type_t<T>>
    {
  #if utils_cc_assertions
      static constexpr calling_convention calling_convention =
          get_calling_convention<T>();
  #endif
    };
  } // namespace helpers

  template <typename T>
  struct function_traits : helpers::function_traits_sfinae<T>
  {
  };
#endif

  template <typename T>
  using fn_return_t = typename function_traits<T>::return_type;
  template <typename T>
  inline constexpr size_t fn_arity_v = function_traits<T>::arity;
  template <typename T, size_t i>
  using fn_argument_t = typename function_traits<T>::template argument<i>;
  template <typename T>
  inline constexpr bool fn_object_v = function_traits<T>::object;
#if utils_cc_assertions
  template <typename T>
  inline constexpr calling_convention fn_calling_convention_v =
      function_traits<T>::calling_convention;
#endif
  template <typename T>
  using fn_class_t =
      std::remove_const_t<std::remove_pointer_t<fn_argument_t<T, 0>>>;

#if utils_cc_assertions
  #if utils_cpp20
  template <typename T1, typename T2>
  concept compatible_calling_convention_with =
      requires {
        typename function_traits<T1>::return_type;
        typename function_traits<T2>::return_type;
      } && ((fn_calling_convention_v<T1> == fn_calling_convention_v<T2>) ||
            ((fn_calling_convention_v<T1> == calling_convention::__THISCALL &&
              fn_calling_convention_v<T2> == calling_convention::__FASTCALL) ||
             (fn_calling_convention_v<T1> == calling_convention::__FASTCALL &&
              fn_calling_convention_v<T2> == calling_convention::__THISCALL)));
  #else
  namespace helpers
  {
    template <typename T1, typename T2, typename = void>
    inline constexpr bool compatible_calling_convention_with_sfinae = false;
    template <typename T1, typename T2>
    inline constexpr bool compatible_calling_convention_with_sfinae<
        T1, T2, std::void_t<fn_return_t<T1>, fn_return_t<T2>>> =
        (fn_calling_convention_v<T1> == fn_calling_convention_v<T2>) ||
        ((fn_calling_convention_v<T1> == calling_convention::__THISCALL &&
          fn_calling_convention_v<T2> == calling_convention::__FASTCALL) ||
         (fn_calling_convention_v<T1> == calling_convention::__FASTCALL &&
          fn_calling_convention_v<T2> == calling_convention::__THISCALL));
  } // namespace helpers

  template <typename T1, typename T2>
  inline constexpr bool compatible_calling_convention_with =
      helpers::compatible_calling_convention_with_sfinae<T1, T2>;
  #endif
#endif

  namespace helpers
  {
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
  } // namespace helpers

  template <typename fn_1, typename fn_2>
  utils_concept compatible_function_arguments_with =
      helpers::have_compatible_fn_args<fn_1, fn_2>();

  template <typename T>
  utils_concept member_function_type = std::is_member_function_pointer_v<T>;

  namespace helpers
  {
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

  template <typename T>
  using captureless_lambda_func_ptr_type_t =
      typename helpers::add_thiscall_if_needed<
          std::add_pointer_t<capturless_lambda_func_type_t<T>>>::type;

  template <typename T>
  using captureless_lambda_actual_func_ptr_type_t =
      typename helpers::add_thiscall_if_needed<
          std::add_pointer_t<captureless_lambda_actual_func_type_t<T>>>::type;
} // namespace alterhook::utils
