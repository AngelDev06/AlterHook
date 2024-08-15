/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include <functional>
#include "utils_macros.h"

namespace alterhook::utils
{
#if utils_cc_assertions
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
    // tag for __thiscall cuz msvc is annoyed
    template <typename T>
    struct thiscall_pfn_tag;
    template <typename T>
    struct unwrap_stdfunc_impl;
    template <typename T, calling_convention cc>
    struct value_wrapper;
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
    template <typename T>
    utils_consteval calling_convention get_calling_convention();
  } // namespace helpers

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

  template <typename T>
  struct add_cdecl;

  template <typename T>
  using add_cdecl_t = typename add_cdecl<T>::type;

  template <typename T>
  struct add_clrcall;

  template <typename T>
  using add_clrcall_t = typename add_clrcall<T>::type;

  template <typename T>
  struct add_fastcall;

  template <typename T>
  using add_fastcall_t = typename add_fastcall<T>::type;

  template <typename T>
  struct add_stdcall;

  template <typename T>
  using add_stdcall_t = typename add_stdcall<T>::type;

  template <typename T>
  struct add_thiscall;

  template <typename T>
  using add_thiscall_t = typename add_thiscall<T>::type;

  template <typename T>
  struct add_vectorcall;

  template <typename T>
  using add_vectorcall_t = typename add_vectorcall<T>::type;

  template <calling_convention cc, typename T>
  struct add_calling_convention;

  template <calling_convention cc, typename T>
  using add_calling_convention_t = typename add_calling_convention<cc, T>::type;

  template <typename R>
  using c_decl = helpers::value_wrapper<R, calling_convention::__CDECL>;
  template <typename R>
  using clrcall = helpers::value_wrapper<R, calling_convention::__CLRCALL>;
  template <typename R>
  using fastcall = helpers::value_wrapper<R, calling_convention::__FASTCALL>;
  template <typename R>
  using stdcall = helpers::value_wrapper<R, calling_convention::__STDCALL>;
  template <typename R>
  using thiscall = helpers::value_wrapper<R, calling_convention::__THISCALL>;
  template <typename R>
  using vectorcall =
      helpers::value_wrapper<R, calling_convention::__VECTORCALL>;

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

  template <typename T>
  struct add_calling_convention<calling_convention::__CDECL, T>
  {
    typedef add_cdecl_t<T> type;
  };

  template <typename T>
  struct add_calling_convention<calling_convention::__CLRCALL, T>
  {
    typedef add_clrcall_t<T> type;
  };

  template <typename T>
  struct add_calling_convention<calling_convention::__FASTCALL, T>
  {
    typedef add_fastcall_t<T> type;
  };

  template <typename T>
  struct add_calling_convention<calling_convention::__STDCALL, T>
  {
    typedef add_stdcall_t<T> type;
  };

  template <typename T>
  struct add_calling_convention<calling_convention::__THISCALL, T>
  {
    typedef add_thiscall_t<T> type;
  };

  template <typename T>
  struct add_calling_convention<calling_convention::__VECTORCALL, T>
  {
    typedef add_vectorcall_t<T> type;
  };

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
#else
  // for compatibility with other platforms
  template <typename R>
  using c_decl = R;

  template <typename R>
  using clrcall = R;

  template <typename R>
  using fastcall = R;

  template <typename R>
  using stdcall = R;

  template <typename R>
  using thiscall = R;

  template <typename R>
  using vectorcall = R;
#endif
} // namespace alterhook::utils
