/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include "boilerplate.h"
#include <cassert>

#define utils_assert(expr, msg) assert(((void)msg, expr))

#if defined(__WIN32__) || defined(_WIN32) || defined(_MSC_VER)
  #define utils_windows true
  #if defined(_M_X64) || defined(__x86_x64__)
    #define utils_windows64 true
  #else
    #define utils_windows64 false
  #endif
#else
  #define utils_windows   false
  #define utils_windows64 false
#endif

#ifdef __ANDROID__
  #define utils_android true
#else
  #define utils_android false
#endif

// determines which compiler is used
// the order matters since some compilers may
// define the flags of other compilers
// for example clang may define _MSC_VER
// and icc may define __GNUC__
#ifdef __clang__
  #define utils_clang true
  #define utils_icc   false
  #define utils_gcc   false
  #define utils_msvc  false
  #define utils_other false
#else
  #define utils_clang false
  #ifdef __INTEL_COMPILER
    #define utils_icc   true
    #define utils_gcc   false
    #define utils_msvc  false
    #define utils_other false
  #else
    #define utils_icc false
    #ifdef __GNUC__
      #define utils_gcc   true
      #define utils_msvc  false
      #define utils_other false
    #else
      #define has_gcc false
      #if defined(_MSC_VER) || defined(_MSVC_LANG)
        #define utils_msvc  true
        #define utils_other false
      #else
        #define utils_msvc  false
        #define utils_other true
      #endif
    #endif
  #endif
#endif

#if utils_gcc || utils_clang
  #define utils_packed __attribute__((packed))
#else
  #define utils_packed
#endif

#if defined(__x86_64__) || defined(_M_X64)
  #define utils_x64   true
  #define utils_x86   false
  #define utils_arm64 false
  #define utils_arm   false
#else
  #define utils_x64 false
  #if defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86)
    #define utils_x86   true
    #define utils_arm64 false
    #define utils_arm   false
  #else
    #define utils_x86 false
    #if defined(__aarch64__) || defined(_M_ARM64)
      #define utils_arm64 true
      #define utils_arm   false
    #else
      #define utils_arm64 false
      #if defined(__ARM_ARCH_7__) || defined(__ARM_ARCH_7A__) ||               \
          defined(__ARM_ARCH_7R__) || defined(__ARM_ARCH_7M__) ||              \
          (defined(__TARGET_ARCH_ARM) && __TARGET_ARCH_ARM - 0 >= 7)
        #define utils_arm true
      #else
        #define utils_arm false
      #endif
    #endif
  #endif
#endif

#if utils_arm64 || utils_x64
  #define utils_64bit true
  #define utils_32bit false
#else
  #define utils_64bit false
  #define utils_32bit true
#endif

#if utils_msvc
  #ifdef _MSVC_LANG
    #define utils_cpp_version _MSVC_LANG
  #else
    #define utils_cpp_version __cplusplus
  #endif
#else
  #define utils_cpp_version __cplusplus
#endif

// determines whether we have access to c++17 or even c++20 features
#if utils_cpp_version >= 202'002L
  #define utils_cpp20 true
  #define utils_cpp17 true
#else
  #define utils_cpp20 false
  #if utils_cpp_version >= 201'703L
    #define utils_cpp17 true
  #else
    #define utils_cpp17 false
  #endif
#endif

#define utils_array_size(array) (sizeof(array) / sizeof(array[0]))

#if utils_cpp20
  #define utils_concept   concept
  #define utils_consteval consteval
#else
  #define utils_concept   inline constexpr bool
  #define utils_consteval constexpr
#endif

// clang & msvc x86 windows support our trick to determine calling convention
#if (utils_msvc || utils_clang) && utils_windows && !utils_windows64
  #define utils_cc_assertions true
#else
  #define utils_cc_assertions false
#endif

#define __utils_stringify(x) #x
#define utils_stringify(x)   __utils_stringify(x)

#if (utils_msvc || utils_clang) && utils_windows
  #define __utils_emit_cdecl(fn, cv, ref, exception)                           \
    fn(__cdecl, cv, ref, exception)
  #define __utils_emit_cdecl2(fn, cv, ref, exception)                          \
    fn(__cdecl, cv, ref, exception)

  #ifdef _M_CEE
    #define __utils_emit_clrcall(fn, cv, ref, exception)                       \
      fn(__clrcall, cv, ref, exception)
    #define __utils_emit_cdecl2(fn, cv, ref, exception)                        \
      fn(__clrcall, cv, ref, exception)
  #else
    #define __utils_emit_clrcall(fn, cv, ref, exception)
    #define __utils_emit_clrcall2(fn, cv, ref, exception)
  #endif

  #if !utils_windows64 && !defined(_M_CEE)
    #define __utils_emit_fastcall(fn, cv, ref, exception)                      \
      fn(__fastcall, cv, ref, exception)
    #define __utils_emit_fastcall2(fn, cv, ref, exception)                     \
      fn(__fastcall, cv, ref, exception)
  #else
    #define __utils_emit_fastcall(fn, cv, ref, exception)
    #define __utils_emit_fastcall2(fn, cv, ref, exception)
  #endif

  #if !utils_windows64
    #define __utils_emit_stdcall(fn, cv, ref, exception)                       \
      fn(__stdcall, cv, ref, exception)
    #define __utils_emit_stdcall2(fn, cv, ref, exception)                      \
      fn(__stdcall, cv, ref, exception)
    #define __utils_emit_thiscall(fn, cv, ref, exception)                      \
      fn(__thiscall, cv, ref, exception)
    #define __utils_emit_thiscall2(fn, cv, ref, exception)                     \
      fn(__thiscall, cv, ref, exception)
  #else
    #define __utils_emit_stdcall(fn, cv, ref, exception)
    #define __utils_emit_stdcall2(fn, cv, ref, exception)
    #define __utils_emit_thiscall(fn, cv, ref, exception)
    #define __utils_emit_thiscall2(fn, cv, ref, exception)
  #endif

  #if ((!utils_windows64 && _M_IX86_FP >= 2) || utils_windows64) &&            \
      !defined(_M_CEE)
    #define __utils_emit_vectorcall(fn, cv, ref, exception)                    \
      fn(__vectorcall, cv, ref, exception)
    #define __utils_emit_vectorcall2(fn, cv, ref, exception)                   \
      fn(__vectorcall, cv, ref, exception)
  #else
    #define __utils_emit_vectorcall(fn, cv, ref, exception)
    #define __utils_emit_vectorcall2(fn, cv, ref, exception)
  #endif
#else
  #define __utils_emit_cdecl(fn, cv, ref, exception)
  #define __utils_emit_cdecl2(fn, cv, ref, exception)
  #define __utils_emit_clrcall(fn, cv, ref, exception)
  #define __utils_emit_clrcall2(fn, cv, ref, exception)
  #define __utils_emit_fastcall(fn, cv, ref, exception)
  #define __utils_emit_fastcall2(fn, cv, ref, exception)
  #define __utils_emit_stdcall(fn, cv, ref, exception)
  #define __utils_emit_stdcall2(fn, cv, ref, exception)
  #define __utils_emit_thiscall(fn, cv, ref, exception)
  #define __utils_emit_thiscall2(fn, cv, ref, exception)
  #define __utils_emit_vectorcall(fn, cv, ref, exception)
  #define __utils_emit_vectorcall2(fn, cv, ref, exception)
#endif

// These are used for code generation purposes
#if utils_windows
  #define __utils_non_member_call(fn, cv, ref, exception)                      \
    __utils_emit_cdecl(fn, cv, ref, exception)                                 \
        __utils_emit_clrcall(fn, cv, ref, exception)                           \
            __utils_emit_fastcall(fn, cv, ref, exception)                      \
                __utils_emit_stdcall(fn, cv, ref, exception)                   \
                    __utils_emit_vectorcall(fn, cv, ref, exception)
#else
  #define __utils_non_member_call(fn, cv, ref, exception)                      \
    fn(, cv, ref, exception)
#endif

#define __utils_non_member_call_cv(fn, ref, exception)                         \
  __utils_non_member_call(fn, , ref, exception)                                \
      __utils_non_member_call(fn, const, ref, exception)                       \
          __utils_non_member_call(fn, volatile, ref, exception)                \
              __utils_non_member_call(fn, const volatile, ref, exception)

#define __utils_non_member_call_cv_ref(fn, exception)                          \
  __utils_non_member_call_cv(fn, , exception)                                  \
      __utils_non_member_call_cv(fn, &, exception)                             \
          __utils_non_member_call_cv(fn, &&, exception)

#define __utils_non_member_call_cv_ref_noexcept(fn)                            \
  __utils_non_member_call_cv_ref(fn, )                                         \
      __utils_non_member_call_cv_ref(fn, noexcept)

#if utils_windows
  #define __utils_member_call(fn, cv, ref, exception)                          \
    __utils_emit_cdecl(fn, cv, ref, exception)                                 \
        __utils_emit_clrcall(fn, cv, ref, exception)                           \
            __utils_emit_fastcall(fn, cv, ref, exception)                      \
                __utils_emit_stdcall(fn, cv, ref, exception)                   \
                    __utils_emit_thiscall(fn, cv, ref, exception)              \
                        __utils_emit_vectorcall(fn, cv, ref, exception)
#else
  #define __utils_member_call(fn, cv, ref, exception) fn(, cv, ref, exception)
#endif

#define __utils_member_call_cv(fn, ref, exception)                             \
  __utils_member_call(fn, , ref, exception)                                    \
      __utils_member_call(fn, const, ref, exception)                           \
          __utils_member_call(fn, volatile, ref, exception)                    \
              __utils_member_call(fn, const volatile, ref, exception)

#define __utils_member_call_cv_ref(fn, exception)                              \
  __utils_member_call_cv(fn, , exception)                                      \
      __utils_member_call_cv(fn, &, exception)                                 \
          __utils_member_call_cv(fn, &&, exception)

#define __utils_member_call_cv_ref_noexcept(fn)                                \
  __utils_member_call_cv_ref(fn, ) __utils_member_call_cv_ref(fn, noexcept)

// Applies the function-like macro `macro` to each of the remaining elements
// e.g. utils_map(func, a, b, c) evaluates to `func(a) func(b) func(c)`
#define utils_map(macro, ...)                                                  \
  __utils_eval(__utils_map2(macro, __VA_ARGS__, ()()(), ()()(), ()()(), 0))

// Applies the function-like macro `macro` to each of the remaining elements and
// separates the result with comma e.g. utils_map_list(func, a, b, c) evaluates
// to `func(a), func(b), func(c)`
#define utils_map_list(macro, ...)                                             \
  __utils_eval(__utils_map_list2(macro, __VA_ARGS__, ()()(), ()()(), ()()(), 0))

// Applies the function-like macro `macro` to each of the remaining elements and
// separates the result with `separator` e.g. utils_map_separated(func, <<, a,
// b, c) evaluates to `func(a) << func(b) << func(c)`
#define utils_map_separated(macro, separator, ...)                             \
  __utils_eval(__utils_map_separated2(macro, separator, __VA_ARGS__, ()()(),   \
                                      ()()(), ()()(), 0))

// Applies the function-like macro `macro` to each of the remaining elements and
// passes `userdata` as second parameter e.g. utils_map_ud(func, x, a, b, c)
// evaluates to `func(a, x) func(b, x) func(c, x)`
#define utils_map_ud(macro, userdata, ...)                                     \
  __utils_eval(__utils_map_ud2(macro, userdata, __VA_ARGS__, ()()(), ()()(),   \
                               ()()(), 0))

// Applies the function-like macro `macro` to each of the remaining elements and
// passes an index starting from 0 and incremented by 1 after each invocation as
// last argument e.g. utils_map_indexed(func, a, b, c) evaluates to `func(a, 0)
// func(b, 1) func(c, 2)`
#define utils_map_indexed(macro, ...)                                          \
  __utils_eval(                                                                \
      __utils_map_indexed2(macro, 0, __VA_ARGS__, ()()(), ()()(), ()()(), 0))

// Applies the function-like macro `macro` to each of the remaining elements,
// separates the result with comma and passes `userdata` as second parameter
// e.g. utils_map_list_ud(func, x, a, b, c) evaluates to `func(a, x), func(b,
// x), func(c, x)`
#define utils_map_list_ud(macro, userdata, ...)                                \
  __utils_eval(__utils_map_list_ud2(macro, userdata, __VA_ARGS__, ()()(),      \
                                    ()()(), ()()(), 0))

// Applies the function-like macro `macro` to each of the remaining elements,
// separates the result with comma and passes an index starting from 0 and
// incremented by 1 after each invocation as last argument e.g.
// utils_map_list_indexed(func, a, b, c) evaluates to `func(a, 0), func(b, 1),
// func(c, 2)`
#define utils_map_list_indexed(macro, ...)                                     \
  __utils_eval(__utils_map_list_indexed2(macro, 0, __VA_ARGS__, ()()(),        \
                                         ()()(), ()()(), 0))

// Applies the function-like macro `macro` to each of the remaining elements,
// separates the result with `separator` and passes `userdata` as second
// parameter e.g. utils_map_separated_ud(func, <<, x, a, b, c) evaluates to
// `func(a, x) << func(b, x) << func(c, x)`
#define utils_map_separated_ud(macro, separator, userdata, ...)                \
  __utils_eval(__utils_map_separated_ud2(                                      \
      macro, separator, userdata, __VA_ARGS__, ()()(), ()()(), ()()(), 0))

// Applies the function-like macro `macro` to each of the remaining elements,
// separates the result with `separator` and passes an index starting from 0 and
// incremented by 1 after each invocation as last argument e.g.
// utils_map_separated_indexed(func, <<, a, b, c) evaluates to `func(a, 0) <<
// func(b, 1) << func(c, 2)`
#define utils_map_separated_indexed(macro, separator, ...)                     \
  __utils_eval(__utils_map_separated_indexed2(                                 \
      macro, separator, 0, __VA_ARGS__, ()()(), ()()(), ()()(), 0))

// Applies the function-like macro `macro` to each of the remaining elements,
// passes `userdata` as second parameter and passes an index starting from 0 and
// incremented by 1 after each invocation as last argument e.g.
// utils_map_ud_indexed(func, x, a, b, c) evaluates to `func(a, x, 0) func(b, x,
// 1) func(c, x, 2)`
#define utils_map_ud_indexed(macro, userdata, ...)                             \
  __utils_eval(__utils_map_ud_indexed2(macro, userdata, 0, __VA_ARGS__,        \
                                       ()()(), ()()(), ()()(), 0))

// Applies the function-like macro `macro` to each of the remaining elements,
// separates the result with comma, passes `userdata` as second parameter and
// passes an index starting from 0 and incremented by 1 after each invocation as
// last argument e.g. utils_map_list_ud_indexed(func, x, a, b, c) evaluates to
// `func(a, x, 0), func(b, x, 1), func(c, x, 2)`
#define utils_map_list_ud_indexed(macro, userdata, ...)                        \
  __utils_eval(__utils_map_list_ud_indexed2(macro, userdata, 0, __VA_ARGS__,   \
                                            ()()(), ()()(), ()()(), 0))

// Applies the function-like macro `macro` to each of the remaining elements,
// separates the result with `separator`, passes `userdata` as second parameter
// and passes an index starting from 0 and incremented by 1 after each
// invocation as last argument e.g. utils_map_separated_ud_indexed(func, <<, x,
// a, b, c) evaluates to `func(a, x, 0) << func(b, x, 1) << func(c, x, 2)`
#define utils_map_separated_ud_indexed(macro, separator, userdata, ...)        \
  __utils_eval(__utils_map_separated_ud_indexed2(                              \
      macro, separator, userdata, 0, __VA_ARGS__, ()()(), ()()(), ()()(), 0))

#define __utils_print_helper(x) ' ' << x

// Print each argument to stdout separated by space
#define utils_print(...)                                                       \
  std::cout << utils_map_separated(__utils_print_helper, <<, __VA_ARGS__)

#define utils_not(x)      __utils_check_expanded(utils_concat(__utils_not_, x))
#define __utils_not_0     ~, true
#define __utils_not_false ~, true
#define __utils_not_1     ~, false
#define __utils_not_true  ~, false

#define utils_bool(x) utils_not(utils_not(x))

#define utils_if(condition)                                                    \
  __utils_call(utils_concat, (__utils_if_, utils_bool(condition)))
#define __utils_if_false(first, ...) __VA_ARGS__
#define __utils_if_true(first, ...)  first

#define utils_and(first_condition, second_condition)                           \
  __utils_check_expanded(utils_concat(                                         \
      utils_concat(utils_concat(__utils_and_, utils_bool(first_condition)),    \
                   _),                                                         \
      utils_bool(second_condition)))
#define __utils_and_true_true ~, true

#define utils_or(first_condition, second_condition)                            \
  __utils_check_expanded(utils_concat(                                         \
      utils_concat(utils_concat(__utils_or_, utils_bool(first_condition)), _), \
      utils_bool(second_condition)))
#define __utils_or_true_false ~, true
#define __utils_or_false_true ~, true
#define __utils_or_true_true  ~, true

#define utils_is_call_operator(x)                                              \
  __utils_check_expanded(__utils_is_call_operator x)
#define __utils_is_call_operator(...) ~, true

#define utils_expand(...) __VA_ARGS__

// source: https://stackoverflow.com/a/36015150/22625698
#if (!defined(_MSVC_TRADITIONAL) || _MSVC_TRADITIONAL) && utils_msvc
  #define utils_sizeof(...)                                                    \
    __utils_expand_varargs(__utils_augment_varargs(__VA_ARGS__))

  #define __utils_augment_varargs(...) unused, __VA_ARGS__
  #define __utils_expand(x)            x
  #define __utils_expand_varargs(...)                                          \
    __utils_expand(__utils_arg_count(                                          \
        __VA_ARGS__, 69, 68, 67, 66, 65, 64, 63, 62, 61, 60, 59, 58, 57, 56,   \
        55, 54, 53, 52, 51, 50, 49, 48, 47, 46, 45, 44, 43, 42, 41, 40, 39,    \
        38, 37, 36, 35, 34, 33, 32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22,    \
        21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3,   \
        2, 1, 0))
  #define __utils_arg_count(                                                   \
      _1_, _2_, _3_, _4_, _5_, _6_, _7_, _8_, _9_, _10_, _11_, _12_, _13_,     \
      _14_, _15_, _16_, _17_, _18_, _19_, _20_, _21_, _22_, _23_, _24_, _25_,  \
      _26_, _27_, _28_, _29_, _30_, _31_, _32_, _33_, _34_, _35_, _36, _37,    \
      _38, _39, _40, _41, _42, _43, _44, _45, _46, _47, _48, _49, _50, _51,    \
      _52, _53, _54, _55, _56, _57, _58, _59, _60, _61, _62, _63, _64, _65,    \
      _66, _67, _68, _69, _70, count, ...)                                     \
    count
#else
  #define utils_sizeof(...)                                                    \
    __utils_arg_count(0, ##__VA_ARGS__, 70, 69, 68, 67, 66, 65, 64, 63, 62,    \
                      61, 60, 59, 58, 57, 56, 55, 54, 53, 52, 51, 50, 49, 48,  \
                      47, 46, 45, 44, 43, 42, 41, 40, 39, 38, 37, 36, 35, 34,  \
                      33, 32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20,  \
                      19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5,   \
                      4, 3, 2, 1, 0)
  #define __utils_arg_count(                                                   \
      _0, _1_, _2_, _3_, _4_, _5_, _6_, _7_, _8_, _9_, _10_, _11_, _12_, _13_, \
      _14_, _15_, _16_, _17_, _18_, _19_, _20_, _21_, _22_, _23_, _24_, _25_,  \
      _26_, _27_, _28_, _29_, _30_, _31_, _32_, _33_, _34_, _35_, _36, _37,    \
      _38, _39, _40, _41, _42, _43, _44, _45, _46, _47, _48, _49, _50, _51,    \
      _52, _53, _54, _55, _56, _57, _58, _59, _60, _61, _62, _63, _64, _65,    \
      _66, _67, _68, _69, _70, count, ...)                                     \
    count
#endif

#define __utils_use_if_n(arg, n, index) utils_if(utils_equal(n, index))(arg, )
#define utils_get(n, ...)               utils_map_ud_indexed(__utils_use_if_n, n, __VA_ARGS__)
#define utils_comma()                   ,

#define __utils_get_attribute_impl(result)                                     \
  utils_if(utils_is_call_operator(result))(utils_expand,                       \
                                           utils_del)(() result utils_del)

#define __utils_get_attribute(x, attrmacro)                                    \
  __utils_get_attribute_impl(utils_concat(utils_concat(attrmacro, _), x))

// Note: `utils_expand` followed by `(~)` is a stupid hack for msvc traditional
// preprocessor to stop complaining about an empty space being passed as an
// argument. Basically if the attribute we are looking for isn't found and
// therefore the stuff in the middle will be replaced with nothing then
// `utils_expand` will leave `~` behind as a result. If found then
// `utils_expand` will be "invoked" with empty parentheses and `(~)` will be
// erased with `utils_del`
#define utils_get_attribute(category, attribute_name, ...)                     \
  utils_expand utils_map_ud(                                                   \
      __utils_get_attribute,                                                   \
      utils_concat(utils_concat(utils_concat(__utils_, category), _),          \
                   attribute_name),                                            \
      __VA_ARGS__)(~)

#define __utils_exception_attribute_extra_extra(...)         (__VA_ARGS__)
#define __utils_exception_attribute_reason_reason(str)       (str)
#define __utils_exception_attribute_base_args_base_args(...) (__VA_ARGS__)
#define __utils_exception_attribute_fields_fields(...)       (__VA_ARGS__)
#define __utils_exception_attribute_stdattr_stdattr(...)     (__VA_ARGS__)

#define __utils_add_exception_attribute_impl(attr)                             \
  utils_if(utils_is_call_operator(attr))(utils_expand,                         \
                                         utils_del)(utils_expand attr)

#define __utils_add_exception_attribute(...)                                   \
  __utils_call2(                                                               \
      __utils_add_exception_attribute_impl,                                    \
      (utils_get_attribute(exception_attribute, stdattr, __VA_ARGS__)))

#define utils_equal_hidden_hidden ~, true

#define __utils_define_field_impl_2(type, name)                                \
private:                                                                       \
  type utils_concat(m_, name);                                                 \
                                                                               \
public:                                                                        \
  type utils_concat(get_, name)() const { return utils_concat(m_, name); }

#define __utils_define_field_impl_3(type, name, attr)                          \
private:                                                                       \
  type utils_concat(m_, name);                                                 \
  utils_if(utils_not(utils_equal(attr, hidden)))(utils_expand, utils_del)(     \
      public                                                                   \
      : type utils_concat(get_, name)()                                        \
          const { return utils_concat(m_, name); })

#define __utils_define_field(tuple)                                            \
  utils_if(utils_equal(utils_sizeof tuple, 3))(                                \
      __utils_define_field_impl_3, __utils_define_field_impl_2) tuple
#define __utils_define_fields_impl2(...)                                       \
  utils_map(__utils_define_field, __VA_ARGS__)
#define __utils_define_fields_impl(attr)                                       \
  utils_if(utils_is_call_operator(attr))(__utils_define_fields_impl2,          \
                                         utils_del)(utils_expand attr)
#define __utils_define_fields(...)                                             \
  __utils_define_fields_impl(                                                  \
      utils_get_attribute(exception_attribute, fields, __VA_ARGS__))

#define __utils_define_argument_impl_3(type, name, attr) type name
#define __utils_define_argument_impl_2(type, name)       type name
#define __utils_define_argument(tuple)                                         \
  utils_if(utils_equal(utils_sizeof tuple, 3))(                                \
      __utils_define_argument_impl_3, __utils_define_argument_impl_2) tuple
#define __utils_define_arguments_impl2(...)                                    \
  utils_map_list(__utils_define_argument, __VA_ARGS__)
#define __utils_define_arguments_impl(attr1, attr2)                            \
  utils_if(utils_is_call_operator(attr1))(__utils_define_arguments_impl2,      \
                                          utils_del)(                          \
      utils_expand attr1)utils_if(utils_is_call_operator(attr2))(utils_expand, \
                                                                 utils_del)(   \
      utils_if(utils_is_call_operator(attr1))(utils_comma, utils_del)()        \
          __utils_call3(__utils_define_arguments_impl2, (utils_expand attr2)))
#define __utils_define_arguments(...)                                          \
  __utils_call2(                                                               \
      __utils_define_arguments_impl,                                           \
      (utils_get_attribute(exception_attribute, base_args, __VA_ARGS__),       \
       utils_get_attribute(exception_attribute, fields, __VA_ARGS__)))

#define __utils_init_field_impl_3(type, name, attr) utils_concat(m_, name)(name)
#define __utils_init_field_impl_2(type, name)       utils_concat(m_, name)(name)
#define __utils_init_field(tuple)                                              \
  utils_if(utils_equal(utils_sizeof tuple, 3))(                                \
      __utils_init_field_impl_3, __utils_init_field_impl_2) tuple
#define __utils_init_fields_impl2(...)                                         \
  , utils_map_list(__utils_init_field, __VA_ARGS__)
#define __utils_init_fields_impl(attr)                                         \
  utils_if(utils_is_call_operator(attr))(__utils_init_fields_impl2,            \
                                         utils_del)(utils_expand attr)
#define __utils_init_fields(...)                                               \
  __utils_call2(                                                               \
      __utils_init_fields_impl,                                                \
      (utils_get_attribute(exception_attribute, fields, __VA_ARGS__)))

#define __utils_pass_argument_impl(type, name) name
#define __utils_pass_argument(pair)            __utils_pass_argument_impl pair
#define __utils_pass_arguments_impl2(...)                                      \
  utils_map_list(__utils_pass_argument, __VA_ARGS__)
#define __utils_pass_arguments_impl(attr)                                      \
  utils_if(utils_is_call_operator(attr))(__utils_pass_arguments_impl2,         \
                                         utils_del)(utils_expand attr)
#define __utils_pass_arguments(...)                                            \
  __utils_call2(                                                               \
      __utils_pass_arguments_impl,                                             \
      (utils_get_attribute(exception_attribute, base_args, __VA_ARGS__)))

#define __utils_define_constructor(exception_name, base, ...)                  \
public:                                                                        \
  exception_name(__utils_define_arguments(__VA_ARGS__))                        \
      : base(__utils_pass_arguments(__VA_ARGS__))                              \
            __utils_init_fields(__VA_ARGS__)                                   \
  {                                                                            \
  }

#define __utils_define_what_impl(attr)                                         \
  utils_if(utils_is_call_operator(attr))(utils_expand, utils_del)(             \
      public                                                                   \
      : const char* what()                                                     \
          const noexcept override { return utils_expand attr; })
#define __utils_define_what(...)                                               \
  __utils_call2(                                                               \
      __utils_define_what_impl,                                                \
      (utils_get_attribute(exception_attribute, reason, __VA_ARGS__)))

#define __utils_add_extra_impl(attr)                                           \
  utils_if(utils_is_call_operator(attr))(utils_expand,                         \
                                         utils_del)(utils_expand attr)
#define __utils_add_extra(...)                                                 \
  __utils_call2(                                                               \
      __utils_add_extra_impl,                                                  \
      (utils_get_attribute(exception_attribute, extra, __VA_ARGS__)))

// clang-format off
/* This generates an exception class using the following properties:
 * `exception_name`:
 * | The name of the exception (it will therefore be the name of the class
 * | generated).
 *
 * `base`:
 * | The base class of the exception (e.g. std::exception). This is not
 * | optional.
 *
 * `__VA_ARGS__`:
 * | A list of 0 or more of the following attributes:
 * | - stdattr(attribute): Puts `attribute` right after the class keyword and
 * |   can therefore be used to trigger implementation defined behavior (e.g.
 * |   stdattr([[gnu::visibility("default")]]))
 * | - fields(...): A list of pairs or 3-element tuples that specify the fields
 * |   of the exception class. They consist of the type of the field, the name
 * |   and optionally a keyword named hidden. This makes sure to define each
 * |   field in private scope as well as generate a constructor that initializes
 * |   those fields with its arguments. If the `hidden` keyword isn't specified
 * |   then a getter will also be generated that accesses the specific field.
 * |   Note that the prefix `m_` is added on the field names to prevent
 * |   shadowing of custom constructor arguments. (e.g. fields((int,
 * |   member1), (float, member2, hidden))).
 * | - base_args(...): A list of pairs that specify the arguments that the base
 * |   class constructor expects. They consist of the type and name of the
 * |   arguments. This will add them at the beginning of the current exception's
 * |   constructor and will make sure to forward them to the base class as
 * |   needed. (e.g. base_args((int, arg1), (float, arg2))).
 * | - reason(str): Generates an overload of the `what()`
 * |   method of the `std::exception` class which returns `str`.
 * | - extra(...): Any extra stuff to be added to the class. They can be method
 * |   declarations/definitions, static members etc. They are put in public
 * |   scope by default and right after any code generated from the attributes
 * |   above. (e.g. extra(void myvfunc() const override;)).
 */
#define utils_generate_exception(exception_name, base, ...)                    \
  class __utils_add_exception_attribute(__VA_ARGS__) exception_name : base     \
  {                                                                            \
    __utils_define_fields(__VA_ARGS__)                                         \
    __utils_define_constructor(exception_name, base, __VA_ARGS__)              \
    __utils_define_what(__VA_ARGS__)                                           \
  public:                                                                      \
    __utils_add_extra(__VA_ARGS__)                                             \
  }

// clang-format on
