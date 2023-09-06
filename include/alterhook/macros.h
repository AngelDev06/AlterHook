/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#if defined(_USRDLL) ||                                                        \
    (defined(ALTERHOOK_SHARED) &&                                              \
     (defined(__WIN32__) || defined(_WIN32) || defined(_MSC_VER)))
  #ifdef ALTERHOOK_EXPORT
    #define ALTERHOOK_API __declspec(dllexport)
  #else
    #define ALTERHOOK_API __declspec(dllimport)
  #endif
#elif defined(__GNUC__) && defined(ALTERHOOK_SHARED)
  #define ALTERHOOK_API __attribute__((visibility("default")))
#else
  #define ALTERHOOK_API
#endif
#ifdef __GNUC__
  #define ALTERHOOK_HIDDEN __attribute__((visibility("hidden")))
#else
  #define ALTERHOOK_HIDDEN
#endif

#define utils_visibility ALTERHOOK_API
#include "utilities/utils_macros.h"

#if utils_cpp20
  #define __alterhook_is_invocable_impl(T, ...) std::invocable<__VA_ARGS__> T
  #define __alterhook_is_invocable(T, ...)      std::invocable<__VA_ARGS__> T

  #define __alterhook_requires(...) requires __VA_ARGS__

  #define __alterhook_is_detour_and_original_impl(T1, T2)                      \
    utils::callable_type T1, utils::function_type T2
  #define __alterhook_is_detour_and_original(T1, T2)                           \
    __alterhook_is_detour_and_original_impl(T1, T2)
  #define __alterhook_is_detour_impl(T) utils::callable_type T
  #define __alterhook_is_detour(T)      utils::callable_type T
  #define __alterhook_is_target_detour_and_original_impl(T1, T2, T3)           \
    utils::callable_type T1, utils::callable_type T2, utils::function_type T3
  #define __alterhook_is_target_detour_and_original(T1, T2, T3)                \
    __alterhook_is_target_detour_and_original_impl(T1, T2, T3)
  #define __alterhook_is_target_and_detour_impl(T1, T2)                        \
    utils::callable_type T1, utils::callable_type T2
  #define __alterhook_is_target_and_detour(T1, T2)                             \
    utils::callable_type T1, utils::callable_type T2
  #define __alterhook_is_target_impl(T)   utils::callable_type T
  #define __alterhook_is_target(T)        utils::callable_type T
  #define __alterhook_is_detour_impl(T)   utils::callable_type T
  #define __alterhook_is_detour(T)        utils::callable_type T
  #define __alterhook_is_original_impl(T) utils::function_type T
  #define __alterhook_is_original(T)      utils::function_type T
  #define __alterhook_are_detour_and_original_pairs_impl(T1, T2, TREST)        \
    utils::callable_type T1, utils::function_type T2, typename... TREST
  #define __alterhook_are_detour_and_original_pairs(T1, T2, TREST)             \
    __alterhook_are_detour_and_original_pairs_impl(T1, T2, TREST)
  #define __alterhook_are_target_detour_and_original_pairs_impl(T1, T2, T3,    \
                                                                TREST)         \
    utils::callable_type T1, utils::callable_type T2, utils::function_type T3, \
        typename... TREST
  #define __alterhook_are_target_detour_and_original_pairs(T1, T2, T3, TREST)  \
    __alterhook_are_target_detour_and_original_pairs_impl(T1, T2, T3, TREST)
  #define __alterhook_are_detour_and_original_stl_pairs_impl(T1, TREST)        \
    utils::detour_and_storage_stl_pairs T1, typename... TREST
  #define __alterhook_are_detour_and_original_stl_pairs(T1, TREST)             \
    __alterhook_are_detour_and_original_stl_pairs_impl(T1, TREST)
  #define __alterhook_are_target_detour_and_original_stl_pairs_impl(T1, T2,    \
                                                                    TREST)     \
    utils::callable_type T1, utils::detour_and_storage_stl_pairs T2,           \
        typename... TREST
  #define __alterhook_are_target_detour_and_original_stl_pairs(T1, T2, TREST)  \
    __alterhook_are_target_detour_and_original_stl_pairs_impl(T1, T2, TREST)
  #define __alterhook_are_key_detour_and_original_triplets_impl(T1, T2, T3,    \
                                                                TREST)         \
    utils::clean_same_as<key> T1, utils::callable_type T2,                     \
        utils::function_type T3, typename... TREST
  #define __alterhook_are_key_detour_and_original_triplets(T1, T2, T3, TREST)  \
    __alterhook_are_key_detour_and_original_triplets_impl(T1, T2, T3, TREST)
  #define __alterhook_are_target_key_detour_and_original_triplets_impl(        \
      T1, T2, T3, T4, TREST)                                                   \
    utils::callable_type T1, utils::clean_same_as<key> T2,                     \
        utils::callable_type T3, utils::function_type T4, typename... TREST
  #define __alterhook_are_target_key_detour_and_original_triplets(T1, T2, T3,  \
                                                                  T4, TREST)   \
    __alterhook_are_target_key_detour_and_original_triplets_impl(T1, T2, T3,   \
                                                                 T4, TREST)
#else
  #define __alterhook_is_invocable_impl(T, ...)                                \
    typename T, std::enable_if_t<std::is_invocable_v<T, __VA_ARGS__>, size_t>
  #define __alterhook_is_invocable(T, ...)                                     \
    __alterhook_is_invocable_impl(T, __VA_ARGS__) = 0

  #define __alterhook_requires(...)

  #define __alterhook_is_detour_and_original_impl(T1, T2)                      \
    typename T1, typename T2,                                                  \
        std::enable_if_t<utils::callable_type<T1> && utils::function_type<T2>, \
                         size_t>
  #define __alterhook_is_detour_and_original(T1, T2)                           \
    __alterhook_is_detour_and_original_impl(T1, T2) = 0
  #define __alterhook_is_detour_impl(T)                                        \
    typename T, std::enable_if_t<utils::callable_type<T>, size_t>
  #define __alterhook_is_detour(T) __alterhook_is_detour_impl(T) = 0
  #define __alterhook_is_target_detour_and_original_impl(T1, T2, T3)           \
    typename T1, typename T2, typename T3,                                     \
        std::enable_if_t<utils::callable_type<T1> &&                           \
                             utils::callable_type<T2> &&                       \
                             utils::function_type<T3>,                         \
                         size_t>
  #define __alterhook_is_target_detour_and_original(T1, T2, T3)                \
    __alterhook_is_target_detour_and_original_impl(T1, T2, T3) = 0
  #define __alterhook_is_target_and_detour_impl(T1, T2)                        \
    typename T1, typename T2,                                                  \
        std::enable_if_t<utils::callable_type<T1> && utils::callable_type<T2>, \
                         size_t>
  #define __alterhook_is_target_and_detour(T1, T2)                             \
    __alterhook_is_target_and_detour_impl(T1, T2) = 0
  #define __alterhook_is_target_impl(T)                                        \
    typename T, std::enable_if_t<utils::callable_type<T>, size_t>
  #define __alterhook_is_target(T) __alterhook_is_target_impl(T) = 0
  #define __alterhook_is_detour_impl(T)                                        \
    typename T, std::enable_if_t<utils::callable_type<T>, size_t>
  #define __alterhook_is_detour(T) __alterhook_is_detour_impl(T) = 0
  #define __alterhook_is_original_impl(T)                                      \
    typename T, std::enable_if_t<utils::function_type<T>, size_t>
  #define __alterhook_is_original(T) __alterhook_is_original_impl(T) = 0
  #define __alterhook_are_detour_and_original_pairs_impl(T1, T2, TREST)        \
    typename T1, typename T2, typename... TREST,                               \
        std::enable_if_t<utils::callable_type<T1> &&                           \
                             utils::function_type<T2> &&                       \
                             utils::detour_and_storage_pairs<TREST...>,        \
                         size_t>
  #define __alterhook_are_detour_and_original_pairs(T1, T2, TREST)             \
    __alterhook_are_detour_and_original_pairs_impl(T1, T2, TREST) = 0
  #define __alterhook_are_target_detour_and_original_pairs_impl(T1, T2, T3,    \
                                                                TREST)         \
    typename T1, typename T2, typename T3, typename... TREST,                  \
        std::enable_if_t<utils::callable_type<T1> &&                           \
                             utils::callable_type<T2> &&                       \
                             utils::function_type<T3> &&                       \
                             utils::detour_and_storage_pairs<TREST...>,        \
                         size_t>
  #define __alterhook_are_target_detour_and_original_pairs(T1, T2, T3, TREST)  \
    __alterhook_are_target_detour_and_original_pairs_impl(T1, T2, T3, TREST) = 0
  #define __alterhook_are_detour_and_original_stl_pairs_impl(T1, TREST)        \
    typename T1, typename... TREST,                                            \
        std::enable_if_t<utils::detour_and_storage_stl_pairs<T1, TREST...>,    \
                         size_t>
  #define __alterhook_are_detour_and_original_stl_pairs(T1, TREST)             \
    __alterhook_are_detour_and_original_stl_pairs_impl(T1, TREST) = 0
  #define __alterhook_are_target_detour_and_original_stl_pairs_impl(T1, T2,    \
                                                                    TREST)     \
    typename T1, typename T2, typename... TREST,                               \
        std::enable_if_t<                                                      \
            utils::callable_type<T1> &&                                        \
                utils::detour_and_storage_stl_pairs<T2, TREST...>,             \
            size_t>
  #define __alterhook_are_target_detour_and_original_stl_pairs(T1, T2, TREST)  \
    __alterhook_are_target_detour_and_original_stl_pairs_impl(T1, T2, TREST) = 0
  #define __alterhook_are_key_detour_and_original_triplets_impl(T1, T2, T3,    \
                                                                TREST)         \
    typename T1, typename T2, typename T3, typename... TREST,                  \
        std::enable_if_t<                                                      \
            std::is_same_v<utils::remove_cvref_t<key>,                         \
                           utils::remove_cvref_t<T1>> &&                       \
                utils::callable_type<T2> && utils::function_type<T3> &&        \
                utils::key_detour_and_storage_triplets<T1, TREST...>,          \
            size_t>
  #define __alterhook_are_key_detour_and_original_triplets(T1, T2, T3, TREST)  \
    __alterhook_are_key_detour_and_original_triplets_impl(T1, T2, T3, TREST) = 0
  #define __alterhook_are_target_key_detour_and_original_triplets_impl(        \
      T1, T2, T3, T4, TREST)                                                   \
    typename T1, typename T2, typename T3, typename T4, typename... TREST,     \
        std::enable_if_t<                                                      \
            utils::callable_type<T1> &&                                        \
                std::is_same_v<utils::remove_cvref_t<key>,                     \
                               utils::remove_cvref_t<T2>> &&                   \
                utils::callable_type<T3> && utils::function_type<T4> &&        \
                utils::key_detour_and_storage_triplets<T2, TREST...>,          \
            size_t>
  #define __alterhook_are_target_key_detour_and_original_triplets(T1, T2, T3,  \
                                                                  T4, TREST)   \
    __alterhook_are_target_key_detour_and_original_triplets_impl(              \
        T1, T2, T3, T4, TREST) = 0
#endif

#if !utils_x64
  #define __alterhook_set_dtr(dtr)         (pdetour = dtr)
  #define __alterhook_get_dtr()            pdetour
  #define __alterhook_get_other_dtr(other) other.pdetour
  #define __alterhook_get_real_dtr()       pdetour
  #define __alterhook_get_other_real_dtr() other.pdetour
  #define __alterhook_copy_dtr(other)      (pdetour = other.pdetour)
  #define __alterhook_exchange_dtr(other)                                      \
    (pdetour = std::exchange(other.pdetour, nullptr))
#else
  #define __alterhook_set_dtr(dtr)                                             \
    (*reinterpret_cast<uint64_t*>(prelay + 6) =                                \
         reinterpret_cast<uintptr_t>(dtr))
  #define __alterhook_get_dtr()                                                \
    reinterpret_cast<std::byte*>(*reinterpret_cast<uint64_t*>(prelay + 6))
  #define __alterhook_get_other_dtr(other)                                     \
    reinterpret_cast<std::byte*>(*reinterpret_cast<uint64_t*>(other.prelay + 6))
  #define __alterhook_get_real_dtr()            prelay
  #define __alterhook_get_other_real_dtr(other) other.prelay
  #define __alterhook_copy_dtr(other)                                          \
    (*reinterpret_cast<uint64_t*>(prelay + 6) =                                \
         *reinterpret_cast<uint64_t*>(other.prelay + 6))
  #define __alterhook_exchange_dtr(other)                                      \
    (*reinterpret_cast<uint64_t*>(prelay + 6) = std::exchange(                 \
         *reinterpret_cast<uint64_t*>(other.prelay + 6), uint64_t{}))
#endif

#if utils_arm
  #define __alterhook_make_backup()                                            \
    do                                                                         \
    {                                                                          \
      const auto target_addr = reinterpret_cast<std::byte*>(                   \
          reinterpret_cast<uintptr_t>(ptarget) & ~1);                          \
      size_t copy_size = reinterpret_cast<uintptr_t>(target_addr) % 4          \
                             ? sizeof(uint64_t) + 2                            \
                             : sizeof(uint64_t);                               \
      if (patch_above)                                                         \
        memcpy(backup.data(), target_addr - __patch_above_target_offset,       \
               __patch_above_backup_size);                                     \
      else                                                                     \
        memcpy(backup.data(), target_addr, copy_size);                         \
    } while (false)
  #define __alterhook_def_thumb_var(address)                                   \
    const bool thumb = reinterpret_cast<uintptr_t>(address) & 1
  #define __alterhook_add_thumb_bit(address)                                   \
    reinterpret_cast<std::byte*>(reinterpret_cast<uintptr_t>(address) | thumb)
#else
  #define __alterhook_make_backup()                                            \
    do                                                                         \
    {                                                                          \
      if (patch_above)                                                         \
        memcpy(backup.data(), ptarget - __patch_above_target_offset,           \
               __patch_above_backup_size);                                     \
      else                                                                     \
        memcpy(backup.data(), ptarget, __backup_size);                         \
    } while (false)
  #define __alterhook_def_thumb_var(address) ((void)0)
  #define __alterhook_add_thumb_bit(address) address
#endif

#define __alterhook_decl_itr_get_0(first, second, ...)    first
#define __alterhook_decl_itr_get_1(first, second, ...)    second
#define __alterhook_decl_itr_get_rest(first, second, ...) __VA_ARGS__
#define __alterhook_decl_itr_func(params)                                      \
  __alterhook_decl_itr_get_0 params utils_concat(                              \
      chain_, __alterhook_decl_itr_get_1 params)()                             \
      __alterhook_decl_itr_get_rest params                                     \
  {                                                                            \
    return base::__alterhook_decl_itr_get_1 params();                          \
  }