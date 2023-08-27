/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#if defined(_USRDLL) || (defined(ALTERHOOK_SHARED) && utils_windows)
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

#if utils_cpp20
  #define __alterhook_must_be_fn_t       utils::function_type
  #define __alterhook_must_be_callable_t utils::callable_type
  #define __alterhook_fn_callable_sfinae_nd_templ
  #define __alterhook_fn_callable_sfinae_templ
  #define __alterhook_callable_sfinae_nd_templ
  #define __alterhook_callable_sfinae_templ
  #define __alterhook_fn_callable2_sfinae_nd_templ
  #define __alterhook_fn_callable2_sfinae_templ
  #define __alterhook_callable2_sfinae_nd_templ
  #define __alterhook_callable2_sfinae_templ
  #define __alterhook_fn_sfinae_nd_templ
  #define __alterhook_fn_sfinae_templ
  #define __alterhook_callable_trg_sfinae_nd_templ
  #define __alterhook_callable_trg_sfinae_templ
  #define __alterhook_fn_callable_pairs_sfinae_nd_templ
  #define __alterhook_fn_callable_pairs_sfinae_templ
  #define __alterhook_fn_callable2_pairs_sfinae_nd_templ
  #define __alterhook_fn_callable2_pairs_sfinae_templ
  #define __alterhook_requires_fn_callable_pairs                               \
    requires utils::detour_and_storage_pairs<types...>
#else
  #define __alterhook_must_be_fn_t       typename
  #define __alterhook_must_be_callable_t typename

  #define __alterhook_fn_callable_sfinae_nd_templ                              \
    , std::enable_if_t<                                                        \
          utils::callable_type<dtr> && utils::function_type<orig>, size_t>
  #define __alterhook_fn_callable_sfinae_templ                                 \
    __alterhook_fn_callable_sfinae_nd_templ = 0

  #define __alterhook_callable_sfinae_nd_templ                                 \
    , std::enable_if_t<utils::callable_type<dtr>, size_t>
  #define __alterhook_callable_sfinae_templ                                    \
    __alterhook_callable_sfinae_nd_templ = 0

  #define __alterhook_fn_callable2_sfinae_nd_templ                             \
    , std::enable_if_t<utils::callable_type<trg> &&                            \
                           utils::callable_type<dtr> &&                        \
                           utils::function_type<orig>,                         \
                       size_t>
  #define __alterhook_fn_callable2_sfinae_templ                                \
    __alterhook_fn_callable2_sfinae_nd_templ = 0

  #define __alterhook_callable2_sfinae_nd_templ                                \
    , std::enable_if_t<utils::callable_type<trg> && utils::callable_type<dtr>, \
                       size_t>
  #define __alterhook_callable2_sfinae_templ                                   \
    __alterhook_callable2_sfinae_nd_templ = 0

  #define __alterhook_fn_sfinae_nd_templ                                       \
    , std::enable_if_t<utils::function_type<orig>, size_t>
  #define __alterhook_fn_sfinae_templ __alterhook_fn_sfinae_nd_templ = 0

  #define __alterhook_callable_trg_sfinae_nd_templ                             \
    , std::enable_if_t<utils::callable_type<trg>, size_t>
  #define __alterhook_callable_trg_sfinae_templ                                \
    __alterhook_callable_trg_sfinae_nd_templ = 0

  #define __alterhook_fn_callable_pairs_sfinae_nd_templ                        \
    , std::enable_if_t<utils::callable_type<dtr> &&                            \
                           utils::function_type<orig> &&                       \
                           utils::detour_and_storage_pairs<types...>,          \
                       size_t>
  #define __alterhook_fn_callable_pairs_sfinae_templ                           \
    __alterhook_fn_callable_pairs_sfinae_nd_templ = 0

  #define __alterhook_fn_callable2_pairs_sfinae_nd_templ                       \
    , std::enable_if_t<utils::callable_type<trg> &&                            \
                           utils::callable_type<dtr> &&                        \
                           utils::function_type<orig> &&                       \
                           utils::detour_and_storage_pairs<types...>,          \
                       size_t>
  #define __alterhook_fn_callable2_pairs_sfinae_templ                          \
    __alterhook_fn_callable2_pairs_sfinae_nd_templ = 0

  #define __alterhook_requires_fn_callable_pairs
#endif

#if !utils_windows64
  #define __alterhook_set_dtr(dtr)      pdetour = dtr
  #define __alterhook_get_dtr()         pdetour
  #define __alterhook_get_real_dtr(arg) arg##pdetour
  #define __alterhook_copy_dtr(other)   pdetour = other.pdetour
  #define __alterhook_exchange_dtr(other)                                      \
    pdetour = std::exchange(other.pdetour, nullptr)
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
#endif
