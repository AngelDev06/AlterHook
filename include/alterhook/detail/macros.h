/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include "../utilities/utils_macros.h"

#if (defined(ALTERHOOK_SHARED) &&                                              \
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

#if !utils_arm && !utils_aarch64 && !utils_x86 && !utils_x64
  #error unsupported architecture
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
        memcpy(backup.data(),                                                  \
               target_addr -                                                   \
                   ::alterhook::detail::constants::patch_above_target_offset,  \
               ::alterhook::detail::constants::patch_above_backup_size);       \
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
        memcpy(backup.data(),                                                  \
               ptarget -                                                       \
                   ::alterhook::detail::constants::patch_above_target_offset,  \
               ::alterhook::detail::constants::patch_above_backup_size);       \
      else                                                                     \
        memcpy(backup.data(), ptarget,                                         \
               ::alterhook::detail::constants::backup_size);                   \
    } while (false)
  #define __alterhook_def_thumb_var(address) ((void)0)
  #define __alterhook_add_thumb_bit(address) address
#endif

#define __alterhook_decl_itr_func2(itr, name)                                  \
  itr         chain_##name() noexcept { return hook_chain::name(); }           \
  const_##itr chain_##name() const noexcept { return hook_chain::name(); }     \
  const_##itr chain_c##name() const noexcept { return hook_chain::name(); }

#define __alterhook_decl_itr_func(params) __alterhook_decl_itr_func2 params