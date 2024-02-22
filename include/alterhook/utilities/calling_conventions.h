/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include <functional>
#include "utils_macros.h"

#if utils_cc_assertions
namespace alterhook::utils
{
  namespace helpers
  {
    // tag for __thiscall cuz msvc is annoyed
    template <typename T>
    struct thiscall_pfn_tag;
    template <typename T>
    struct unwrap_stdfunc_impl;
    template <typename T>
    using unwrap_stdfunc_t = typename unwrap_stdfunc_impl<T>::type;
    template <typename T>
    inline constexpr bool __cdecl_check = false;
    template <typename T>
    inline constexpr bool __clrcall_check = false;
    template <typename T>
    inline constexpr bool __fastcall_check = false;
    template <typename T>
    inline constexpr bool __stdcall_check = false;
    template <typename T>
    inline constexpr bool __thiscall_check = false;
    template <typename T>
    inline constexpr bool __vectorcall_check = false;
  } // namespace helpers

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

  template <typename T>
  inline constexpr bool is_cdecl_v =
      helpers::__cdecl_check<helpers::unwrap_stdfunc_t<T>>;

  template <typename T>
  struct is_cdecl
  {
    static constexpr bool value = is_cdecl_v<T>;
  };

  template <typename T>
  inline constexpr bool is_clrcall_v =
      helpers::__clrcall_check<helpers::unwrap_stdfunc_t<T>>;

  template <typename T>
  struct is_clrcall
  {
    static constexpr bool value = is_clrcall_v<T>;
  };

  template <typename T>
  inline constexpr bool is_fastcall_v =
      helpers::__fastcall_check<helpers::unwrap_stdfunc_t<T>>;

  template <typename T>
  struct is_fastcall
  {
    static constexpr bool value = is_fastcall_v<T>;
  };

  template <typename T>
  inline constexpr bool is_stdcall_v =
      helpers::__stdcall_check<helpers::unwrap_stdfunc_t<T>>;

  template <typename T>
  struct is_stdcall
  {
    static constexpr bool value = is_stdcall_v<T>;
  };

  template <typename T>
  inline constexpr bool is_thiscall_v =
      helpers::__thiscall_check<helpers::unwrap_stdfunc_t<T>>;

  template <typename T>
  struct is_thiscall
  {
    static constexpr bool value = is_thiscall_v<T>;
  };

  template <typename T>
  inline constexpr bool is_vectorcall_v =
      helpers::__vectorcall_check<helpers::unwrap_stdfunc_t<T>>;

  template <typename T>
  struct is_vectorcall
  {
    static constexpr bool value = is_vectorcall_v<T>;
  };

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
  } // namespace helpers

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
            (vectorcall, vectorcall, __VECTORCALL));

  namespace helpers
  {
    template <typename T>
    struct thiscall_pfn_tag
    {
    };

    template <typename T>
    struct unwrap_stdfunc_impl
    {
      typedef T type;
    };

    template <typename T>
    struct unwrap_stdfunc_impl<std::function<T>>
    {
      typedef T type;
    };

  #define utils_equal___thiscall___thiscall ~, true

  #define __utils_cc_check_impl_member(cc, cv, ref, exception)                 \
    template <typename ret, typename cls, typename... args>                    \
    inline constexpr bool                                                      \
        cc##_check<ret (cc cls::*)(args...) cv ref exception> = true;
  #define __utils_cc_check_impl_regular(cc, cv, ref, exception)                \
    template <typename ret, typename... args>                                  \
    inline constexpr bool cc##_check<ret cc(args...) cv ref exception> = true;
  #define __utils_cc_check_impl_overloads(cc, cv, ref, exception)              \
    __utils_cc_check_impl_member(cc, cv, ref, exception)                       \
        utils_if(utils_not(utils_equal(cc, __thiscall)))(                      \
            __utils_cc_check_impl_regular, utils_del)(cc, cv, ref, exception)

    __utils_member_call_cv_ref_noexcept(__utils_cc_check_impl_overloads)

        template <typename R, typename... args>
        inline constexpr bool __thiscall_check<thiscall_pfn_tag<R>(args...)> =
            true;

    template <typename R, typename... args>
    inline constexpr bool
        __thiscall_check<thiscall_pfn_tag<R>(args...) noexcept> = true;
  } // namespace helpers
} // namespace alterhook::utils
#endif
