/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include <cstddef>
#include <utility>
#include <functional>
#include "other.h"
#include "type_sequence.h"
#include "calling_conventions.h"

namespace utils
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
    struct function_traits_impl<helpers::thiscall_pfn_tag<R>(args...)>
        : function_traits_impl<R(args...)>
    {
    };
#endif
  } // namespace helpers

  template <typename T, bool = std::is_function_v<std::remove_pointer_t<T>>>
  struct clean_type
  {
    typedef T type;
  };

  template <typename T>
  struct clean_type<T, true> : std::remove_pointer<T>
  {
  };
#if utils_cc_assertions
  template <typename R, typename... args>
  struct clean_type<R(__thiscall*)(args...), false>
  {
    typedef helpers::thiscall_pfn_tag<R> type(args...);
  };

  template <typename R, typename... args>
  struct clean_type<R(__thiscall*)(args...) noexcept, false>
  {
    typedef helpers::thiscall_pfn_tag<R> type(args...) noexcept;
  };
#endif
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
    utils_concept have_this_and_eq_size =
        are_pointers<PT1, PT2> &&
        (std::is_base_of_v<T1, T2> || std::is_base_of_v<T2, T1>)&&sizeof(T1) ==
            sizeof(T2) &&
        same_cv_qualification_v<T1, T2>;

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
        have_this_and_eq_size<remove_cvref_t<fn_argument_t<fn_1, index>>,
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
        } && have_this_and_eq_size<std::remove_cvref_t<fn_argument_t<T1, 0>>,
                                   std::remove_cvref_t<fn_argument_t<T2, 0>>>;
#else
    template <typename T1, typename T2, typename = void>
    inline constexpr bool have_compatible_member_fn_first_args = false;
    template <typename T1, typename T2>
    inline constexpr bool have_compatible_member_fn_first_args<
        T1, T2, std::void_t<fn_argument_t<T1, 0>, fn_argument_t<T2, 0>>> =
        have_this_and_eq_size<remove_cvref_t<fn_argument_t<T1, 0>>,
                              remove_cvref_t<fn_argument_t<T2, 0>>>;
#endif

    template <typename T1, typename T2>
    utils_concept have_all_args_same =
        fn_arity_v<T1> == fn_arity_v<T2> &&
        all_arguments_same_check_2<std::make_index_sequence<fn_arity_v<T1>>, T1,
                                   T2>;

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
    template <typename T1, typename T2, typename = void>
    inline constexpr bool have_all_fastcall_args_compatible_with_thiscall =
        false;
    template <typename T1, typename T2>
    inline constexpr bool have_all_fastcall_args_compatible_with_thiscall<
        T1, T2, std::void_t<fn_argument_t<T1, 1>>> =
        have_compatible_member_fn_first_args<T1, T2> &&
        sizeof(fn_argument_t<T1, 1>) == sizeof(void*) &&
        fn_arity_v<T2> == (fn_arity_v<T1> - 1) &&
        all_arguments_same_check<make_index_sequence_t<fn_arity_v<T1>, 2>, T1,
                                 T2>;
#endif

    template <typename T1, typename T2>
    utils_consteval bool have_compatible_fn_args()
    {
// on x64 the calling convention is defaulted to 4-register parameter passing
// and we can't get the right results via template overloading. so best we can
// do is verify that all args are the same (it is pretty much enough since there
// is no such need as an additional argument to store 'edx' when trying to hook
// a __thiscall function with a __fastcall one on x64)
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
    struct convert_to_fn_pointer_impl;
#define __utils_convert_to_fn_pointer_impl(calling_convention, cv, ref,        \
                                           exception)                          \
  template <typename R, typename cls, typename... args>                        \
  struct convert_to_fn_pointer_impl<R (calling_convention cls::*)(args...)     \
                                        cv ref exception>                      \
  {                                                                            \
    typedef R(calling_convention* type)(cv cls*, args...) exception;           \
  };

    __utils_member_call_cv_ref_noexcept(__utils_convert_to_fn_pointer_impl)
  } // namespace helpers

#if utils_cpp20
  template <member_function_type T>
  struct convert_to_fn_pointer : helpers::convert_to_fn_pointer_impl<T>
  {
  };
#else
  template <typename T, typename = void>
  struct convert_to_fn_pointer;

  template <typename T>
  struct convert_to_fn_pointer<T, std::enable_if_t<member_function_type<T>>>
      : helpers::convert_to_fn_pointer_impl<T>
  {
  };
#endif
  template <typename T>
  using convert_to_fn_pointer_t = typename convert_to_fn_pointer<T>::type;

  namespace helpers
  {
    template <typename T>
    struct lambda_to_fn;

#define __utils_lambda_to_fn_overloads(cc, cv, ref, exception)                 \
  template <typename ret, typename cls, typename... args>                      \
  struct lambda_to_fn<ret (cc cls::*)(args...) cv ref exception>               \
  {                                                                            \
    typedef ret cc type(args...) exception;                                    \
  };
#define __utils_lambda_to_fn(cc, cv, ref, exception)                           \
  __utils_lambda_to_fn_overloads(, cv, ref, exception)
#define __utils_lambda_to_fn__cdecl(cc, cv, ref, exception)                    \
  __utils_lambda_to_fn_overloads(cc, cv, ref, exception)
#define __utils_lambda_to_fn__clrcall(cc, cv, ref, exception)                  \
  __utils_lambda_to_fn_overloads(cc, cv, ref, exception)
#define __utils_lambda_to_fn__fastcall(cc, cv, ref, exception)                 \
  __utils_lambda_to_fn_overloads(cc, cv, ref, exception)
#define __utils_lambda_to_fn__stdcall(cc, cv, ref, exception)                  \
  __utils_lambda_to_fn_overloads(cc, cv, ref, exception)
#define __utils_lambda_to_fn__thiscall(cc, cv, ref, exception)                 \
  template <typename ret, typename cls, typename... args>                      \
  struct lambda_to_fn<ret (cc cls::*)(args...) cv ref exception>               \
  {                                                                            \
    typedef ret type(args...) exception;                                       \
  };
#define __utils_lambda_to_fn__vectorcall(cc, cv, ref, exception)               \
  __utils_lambda_to_fn_overloads(cc, cv, ref, exception)

#define __utils_lambda_to_fn_all_overloads(cc, cv, ref, exception)             \
  utils_concat(__utils_lambda_to_fn, cc)(cc, cv, ref, exception)

    __utils_member_call_cv_ref_noexcept(__utils_lambda_to_fn_all_overloads)

        template <typename T>
        using lambda_to_fn_t = typename lambda_to_fn<T>::type;
  } // namespace helpers

// only non-capturing lambdas are objects that can be casted to function
// pointers (and maybe user types that define operator ret(*)(args...) but we
// can't check these somehow)
#if utils_cpp20
  template <typename T>
  concept non_capturing_lambda = requires(std::remove_cvref_t<T> lmbd) {
    typename fn_return_t<std::remove_cvref_t<T>>;
    requires utils::fn_object_v<std::remove_cvref_t<T>>;
    {
      static_cast<std::add_pointer_t<helpers::lambda_to_fn_t<
          helpers::call_overload_t<std::remove_cvref_t<T>>>>>(lmbd)
    };
  };
#else
  namespace helpers
  {
    template <typename T, typename = void>
    inline constexpr bool non_capturing_lambda_sfinae_2 = false;
    template <typename T>
    inline constexpr bool non_capturing_lambda_sfinae_2<
        T, std::void_t<
               decltype(static_cast<std::add_pointer_t<helpers::lambda_to_fn_t<
                            helpers::call_overload_t<remove_cvref_t<T>>>>>(
                   std::declval<remove_cvref_t<T>>()))>> = true;

    template <typename T, typename = void>
    inline constexpr bool non_capturing_lambda_sfinae = false;
    template <typename T>
    inline constexpr bool non_capturing_lambda_sfinae<
        T, std::void_t<fn_return_t<remove_cvref_t<T>>>> =
        fn_object_v<remove_cvref_t<T>> && non_capturing_lambda_sfinae_2<T>;
  } // namespace helpers

  template <typename T>
  inline constexpr bool non_capturing_lambda =
      helpers::non_capturing_lambda_sfinae<T>;
#endif

  namespace helpers
  {
    template <typename seq, typename... types>
    struct make_type_pairs_impl;

    template <typename... current_pairs, typename first, typename second,
              typename... rest>
    struct make_type_pairs_impl<type_sequence<current_pairs...>, first, second,
                                rest...>
        : make_type_pairs_impl<
              type_sequence<current_pairs..., std::pair<first, second>>,
              rest...>
    {
    };

    template <typename... current_pairs>
    struct make_type_pairs_impl<type_sequence<current_pairs...>>
    {
      typedef type_sequence<current_pairs...> type;
    };

    template <typename seq, typename... types>
    struct make_type_triplets_impl;

    template <typename... current_triplets, typename first, typename second,
              typename third, typename... rest>
    struct make_type_triplets_impl<type_sequence<current_triplets...>, first,
                                   second, third, rest...>
        : make_type_triplets_impl<
              type_sequence<current_triplets...,
                            std::tuple<first, second, third>>,
              rest...>
    {
    };

    template <typename... current_triplets>
    struct make_type_triplets_impl<type_sequence<current_triplets...>>
    {
      typedef type_sequence<current_triplets...> type;
    };

    template <typename seq>
    inline constexpr bool dtr_storage_pairs_helper = false;

    template <typename first_elem, typename second_elem, typename... rest_pairs>
    inline constexpr bool dtr_storage_pairs_helper<
        type_sequence<std::pair<first_elem, second_elem>, rest_pairs...>> =
        (callable_type<first_elem> &&
         function_type<remove_cvref_t<second_elem>> &&
         std::is_lvalue_reference_v<
             second_elem>)&&dtr_storage_pairs_helper<type_sequence<rest_pairs...>>;

    template <typename first_elem, typename second_elem, typename... rest_pairs>
    inline constexpr bool dtr_storage_pairs_helper<
        type_sequence<std::tuple<first_elem, second_elem>, rest_pairs...>> =
        dtr_storage_pairs_helper<
            type_sequence<std::pair<first_elem, second_elem>, rest_pairs...>>;

    template <>
    inline constexpr bool dtr_storage_pairs_helper<type_sequence<>> = true;

    template <typename key, typename seq>
    inline constexpr bool key_dtr_storage_triplet_helper = false;

    template <typename key, typename first_key, typename first_elem,
              typename second_elem, typename... rest_triplets>
    inline constexpr bool key_dtr_storage_triplet_helper<
        key, type_sequence<std::tuple<first_key, first_elem, second_elem>,
                           rest_triplets...>> =
        std::is_same_v<remove_cvref_t<key>, remove_cvref_t<first_key>> &&
        callable_type<first_elem> &&
        function_type<remove_cvref_t<second_elem>> &&
        std::is_lvalue_reference_v<second_elem> &&
        key_dtr_storage_triplet_helper<key, type_sequence<rest_triplets...>>;

    template <typename key>
    inline constexpr bool key_dtr_storage_triplet_helper<key, type_sequence<>> =
        true;
  } // namespace helpers

  template <typename... types>
  struct make_type_pairs
      : helpers::make_type_pairs_impl<type_sequence<>, types...>
  {
    static_assert(!(sizeof...(types) % 2), "can't make pairs with given types");
  };

  template <typename... types>
  using make_type_pairs_t = typename make_type_pairs<types...>::type;

  template <typename... types>
  struct make_type_triplets
      : helpers::make_type_triplets_impl<type_sequence<>, types...>
  {
    static_assert(!(sizeof...(types) % 3),
                  "can't make triplets with given types");
  };

  template <typename... types>
  using make_type_triplets_t = typename make_type_triplets<types...>::type;

#if !utils_cpp20
  namespace helpers
  {
    template <bool, typename... types>
    inline constexpr bool dtr_storage_pairs_helper2 = false;

    template <typename... types>
    inline constexpr bool dtr_storage_pairs_helper2<true, types...> =
        dtr_storage_pairs_helper<make_type_pairs_t<types...>>;

    template <bool, typename key, typename... types>
    inline constexpr bool key_dtr_storage_pairs_helper2 = false;

    template <typename key, typename... types>
    inline constexpr bool key_dtr_storage_pairs_helper2<true, key, types...> =
        key_dtr_storage_triplet_helper<key, make_type_triplets_t<types...>>;
  }

  template <typename... types>
  inline constexpr bool detour_and_storage_pairs =
      helpers::dtr_storage_pairs_helper2<!stl_tuples_or_pairs<types...>,
                                         types...>;

  template <typename key, typename... types>
  inline constexpr bool key_detour_and_storage_triplets =
      helpers::key_dtr_storage_pairs_helper2<!(stl_tuple<types> && ...), key,
                                             types...>;
#else
  template <typename... types>
  concept detour_and_storage_pairs =
      !stl_tuples_or_pairs<types...> &&
      helpers::dtr_storage_pairs_helper<make_type_pairs_t<types...>>;

  template <typename key, typename... types>
  concept key_detour_and_storage_triplets =
      !(stl_tuple<types> && ...) &&
      helpers::key_dtr_storage_triplet_helper<key,
                                              make_type_triplets_t<types...>>;

  template <typename T1, typename T2>
  concept clean_same_as =
      std::same_as<std::remove_cvref_t<T1>, std::remove_cvref_t<T2>>;
#endif

  template <typename... types>
  utils_concept detour_and_storage_stl_pairs =
      stl_tuples_or_pairs<types...> &&
      helpers::dtr_storage_pairs_helper<
          type_sequence<remove_cvref_t<types>...>>;
} // namespace utils
