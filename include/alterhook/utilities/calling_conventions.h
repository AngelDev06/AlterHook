/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include <functional>
#include "utils_macros.h"

#if utils_cc_assertions
namespace utils
{
  // All the supported windows x86 calling conventions
  enum class calling_convention
  {
    __CDECL,
    __CLRCALL,
    __FASTCALL,
    __STDCALL,
    __THISCALL,
    __VECTORCALL
  };

  namespace helpers
  {
    // Since a function pointer with calling convention `__thiscall` can't be
    // safely converted to a function type with same calling convention due to
    // msvc not allowing it, we will use this flag to store the function type as
    // template param T without __thiscall and to denote that this function type
    // originally had the __thiscall cc.
    template <typename T>
    struct thiscall_pfn_tag
    {
    };

  #define __utils_define_default_cc_checks(cc)                                 \
    template <typename T>                                                      \
    inline constexpr bool utils_concat(cc, _check) = false;

    utils_map(__utils_define_default_cc_checks, __cdecl, __clrcall, __fastcall,
              __stdcall, __thiscall, __vectorcall)

  // we keep this overload in its own macro as its the only one to be used for
  // __thiscall
  #define __utils_define_member_function_cc_overload(cc, cv, ref, exception)   \
    template <typename ret, typename cls, typename... args>                    \
    inline constexpr bool utils_concat(                                        \
        cc, _check)<ret (cc cls::*)(args...) cv ref exception> = true;

  #define __utils_define_cc_overloads(cc, cv, ref, exception)                  \
    template <typename ret, typename... args>                                  \
    inline constexpr bool utils_concat(                                        \
        cc, _check)<ret cc(args...) cv ref exception> = true;                  \
    template <typename ret, typename... args>                                  \
    inline constexpr bool utils_concat(                                        \
        cc, _check)<std::function<ret cc(args...) cv ref exception>> = true;   \
    __utils_define_member_function_cc_overload(cc, cv, ref, exception)

  #define __utils_define__cdecl_overloads(cc, cv, ref, exception)              \
    __utils_define_cc_overloads(cc, cv, ref, exception)
  #define __utils_define__clrcall_overloads(cc, cv, ref, exception)            \
    __utils_define_cc_overloads(cc, cv, ref, exception)
  #define __utils_define__fastcall_overloads(cc, cv, ref, exception)           \
    __utils_define_cc_overloads(cc, cv, ref, exception)
  #define __utils_define__stdcall_overloads(cc, cv, ref, exception)            \
    __utils_define_cc_overloads(cc, cv, ref, exception)
  #define __utils_define__thiscall_overloads(cc, cv, ref, exception)           \
    __utils_define_member_function_cc_overload(cc, cv, ref, exception)
  #define __utils_define__vectorcall_overloads(cc, cv, ref, exception)         \
    __utils_define_cc_overloads(cc, cv, ref, exception)

  #define __utils_define_all_cc_overloads(cc, cv, ref, exception)              \
    utils_concat(utils_concat(__utils_define, cc), _overloads)(cc, cv, ref,    \
                                                               exception)

        // clang-format off
    __utils_member_call_cv_ref_noexcept(__utils_define_all_cc_overloads) 
      
    template <typename R, typename... args>
    inline constexpr bool __thiscall_check<thiscall_pfn_tag<R>(args...)> = true;
    // clang-format on

    template <typename R, typename... args>
    inline constexpr bool
        __thiscall_check<thiscall_pfn_tag<R>(args...) noexcept> = true;

  } // namespace helpers

  #define __utils_define_cc_checks_api(name)                                   \
    template <typename T>                                                      \
    inline constexpr bool utils_concat(utils_concat(is_, name), _v) =          \
        helpers::utils_concat(utils_concat(__, name),                          \
                              _check)<std::remove_pointer_t<T>>;               \
    template <typename T>                                                      \
    struct utils_concat(is_, name)                                             \
    {                                                                          \
      static constexpr bool value =                                            \
          utils_concat(utils_concat(is_, name), _v)<T>;                        \
    };

  utils_map(__utils_define_cc_checks_api, cdecl, clrcall, fastcall, stdcall,
            thiscall, vectorcall)

      namespace helpers
  {
    template <typename T>
    utils_consteval calling_convention get_calling_convention()
    {
  #define __utils_ret_cc0(name, name2)                                         \
    if constexpr (name<T>)                                                     \
      return calling_convention::utils_concat(__, name2);
  #define __utils_ret_cc(pair) __utils_ret_cc0 pair
      utils_map(__utils_ret_cc, (is_thiscall_v, THISCALL), (is_cdecl_v, CDECL),
                (is_clrcall_v, CLRCALL), (is_fastcall_v, FASTCALL),
                (is_vectorcall_v, VECTORCALL))
    }
  }

  #define __utils_decl_add_cc(name)                                            \
    template <typename T>                                                      \
    struct utils_concat(add_, name);
  utils_map(__utils_decl_add_cc, cdecl, clrcall, fastcall, stdcall, thiscall,
            vectorcall)

  #define __utils_cc_extract_ccold(ccold, cv) ccold
  #define __utils_cc_extract_cv(ccold, cv)    cv
  #define __utils_cc_extract_name__cdecl      cdecl
  #define __utils_cc_extract_name__clrcall    clrcall
  #define __utils_cc_extract_name__fastcall   fastcall
  #define __utils_cc_extract_name__stdcall    stdcall
  #define __utils_cc_extract_name__thiscall   thiscall
  #define __utils_cc_extract_name__vectorcall vectorcall
  #define __utils_add_cc_fetch_name(cc)                                        \
    utils_concat(add_, utils_concat(__utils_cc_extract_name, cc))

  #define __utils_define_add_cc_member_overload0(ccnew, ccold, cv, ref,        \
                                                 exception)                    \
    template <typename ret, typename cls, typename... args>                    \
    struct __utils_add_cc_fetch_name(                                          \
        ccnew)<ret (ccold cls::*)(args...) cv ref exception>                   \
    {                                                                          \
      typedef ret (ccnew cls::*type)(args...) cv ref exception;                \
    };

  #define __utils_define_add_cc_member_overload(cc, cv_ccold, ref, exception)  \
    __utils_define_add_cc_member_overload0(                                    \
        cc, __utils_cc_extract_ccold cv_ccold, __utils_cc_extract_cv cv_ccold, \
        ref, exception)

  #define __utils_define_add_cc_non_member_overload0(ccnew, ccold, cv, ref,    \
                                                     exception)                \
    template <typename ret, typename... args>                                  \
    struct __utils_add_cc_fetch_name(                                          \
        ccnew)<ret ccold(args...) cv ref exception>                            \
    {                                                                          \
      typedef ret ccnew type(args...) exception;                               \
    };

  #define __utils_define_add_cc_non_member_overload(cc, cv_ccold, ref,         \
                                                    exception)                 \
    __utils_define_add_cc_non_member_overload0(                                \
        cc, __utils_cc_extract_ccold cv_ccold, __utils_cc_extract_cv cv_ccold, \
        ref, exception)

  #define __utils_define_all_add_cc_member_overloads(cc, cv, ref, exception)   \
    __utils_emit_cdecl2(__utils_define_add_cc_member_overload, (cc, cv), ref,  \
                        exception)                                             \
        __utils_emit_clrcall2(__utils_define_add_cc_member_overload, (cc, cv), \
                              ref, exception)                                  \
            __utils_emit_fastcall2(__utils_define_add_cc_member_overload,      \
                                   (cc, cv), ref, exception)                   \
                __utils_emit_stdcall2(__utils_define_add_cc_member_overload,   \
                                      (cc, cv), ref, exception)                \
                    __utils_emit_thiscall2(                                    \
                        __utils_define_add_cc_member_overload, (cc, cv), ref,  \
                        exception)                                             \
                        __utils_emit_vectorcall2(                              \
                            __utils_define_add_cc_member_overload, (cc, cv),   \
                            ref, exception)

  #define __utils_define_all_add_cc_non_member_overloads(cc, cv, ref,          \
                                                         exception)            \
    __utils_emit_cdecl2(__utils_define_add_cc_non_member_overload, (cc, cv),   \
                        ref, exception)                                        \
        __utils_emit_clrcall2(__utils_define_add_cc_non_member_overload,       \
                              (cc, cv), ref, exception)                        \
            __utils_emit_fastcall2(__utils_define_add_cc_non_member_overload,  \
                                   (cc, cv), ref, exception)                   \
                __utils_emit_stdcall2(                                         \
                    __utils_define_add_cc_non_member_overload, (cc, cv), ref,  \
                    exception)                                                 \
                    __utils_emit_vectorcall2(                                  \
                        __utils_define_add_cc_non_member_overload, (cc, cv),   \
                        ref, exception)

      __utils_member_call_cv_ref_noexcept(
          __utils_define_all_add_cc_member_overloads)
          __utils_non_member_call_cv_ref_noexcept(
              __utils_define_all_add_cc_non_member_overloads)

  #define __utils_decl_add_cc_t(name)                                          \
    template <typename T>                                                      \
    using utils_concat(add_, utils_concat(name, _t)) =                         \
        typename utils_concat(add_, name)<T>::type;
              utils_map(__utils_decl_add_cc_t, cdecl, clrcall, fastcall,
                        stdcall, thiscall, vectorcall)

                  template <calling_convention cc, typename T>
                  struct add_calling_convention;
  #define __utils_define_add_cc_overload0(name1, name2)                        \
    template <typename T>                                                      \
    struct add_calling_convention<calling_convention::utils_concat(__, name2), \
                                  T>                                           \
    {                                                                          \
      typedef utils_concat(add_, utils_concat(name1, _t))<T> type;             \
    };
  #define __utils_define_add_cc_overload(pair)                                 \
    __utils_define_add_cc_overload0 pair
  utils_map(__utils_define_add_cc_overload, (cdecl, CDECL), (clrcall, CLRCALL),
            (fastcall, FASTCALL), (stdcall, STDCALL), (thiscall, THISCALL),
            (vectorcall, VECTORCALL))

      template <calling_convention cc, typename T>
      using add_calling_convention_t =
          typename add_calling_convention<cc, T>::type;

  namespace helpers
  {
    template <typename T, calling_convention cc>
    struct value_wrapper
    {
      T value;

      template <typename... types>
      value_wrapper(types&&... args) : value(std::forward<types>(args)...)
      {
      }

      value_wrapper(const T& arg) : value(arg) {}

      value_wrapper(T&& arg) : value(std::move(arg)) {}

      operator T() const noexcept { return value; }

      operator T&() noexcept { return value; }

      operator const T&() const noexcept { return value; }
    };

    template <calling_convention cc>
    struct value_wrapper<void, cc>
    {
    };
  } // namespace helpers

  #define __utils_add_cc_tag(cc, name, enum_val, ...)                          \
    template <typename R>                                                      \
    using name = helpers::value_wrapper<R, calling_convention::enum_val>;

  #define __utils_emit_tags_impl(emit_name, name, enum_val)                    \
    utils_concat(__utils_emit_, emit_name)(__utils_add_cc_tag, name, enum_val, )
  #define __utils_emit_tags(args) __utils_emit_tags_impl args

  utils_map(__utils_emit_tags, (cdecl, c_decl, __CDECL),
            (clrcall, clrcall, __CLRCALL), (fastcall, fastcall, __FASTCALL),
            (stdcall, stdcall, __STDCALL), (thiscall, thiscall, __THISCALL),
            (vectorcall, vectorcall, __VECTORCALL))
} // namespace utils
#endif
