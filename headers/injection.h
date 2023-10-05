/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#if !utils_windows
  #include "linux_thread_handler.h"
#else
  #include "windows_thread_handler.h"
#endif

namespace alterhook
{
  extern std::shared_mutex hook_lock;

#if !utils_windows
  void inject_to_target(std::byte* target, const std::byte* backup_or_detour,
                        bool patch_above, bool enable, int old_protect);
  #if !utils_x64
  void patch_jmp(std::byte* target, const std::byte* detour, bool patch_above,
                 int old_protect);
  #endif

  #define __alterhook_inject_extra_arg              , old_protect
  #define __alterhook_inject_base_node_extra_arg    , pchain->old_protect
  #define __alterhook_inject_other_extra_arg(other) , other.old_protect
#else
  void inject_to_target(std::byte* target, const std::byte* backup_or_detour,
                        bool patch_above, bool enable);
  // note that patch_jmp is not needed for x64 builds
  #if !utils_x64
  void patch_jmp(std::byte* target, const std::byte* detour, bool patch_above);
  #endif

  #define __alterhook_inject_extra_arg
  #define __alterhook_inject_base_node_extra_arg
  #define __alterhook_inject_other_extra_arg(other)
#endif

#if utils_x64
  #define __alterhook_inject(backup_or_detour, enable)                         \
    (enable ? (__alterhook_set_dtr(backup_or_detour),                          \
               inject_to_target(ptarget, prelay, patch_above,                  \
                                true __alterhook_inject_extra_arg))            \
            : inject_to_target(ptarget, backup_or_detour, patch_above,         \
                               false __alterhook_inject_extra_arg))

  #define __alterhook_inject_other(other, backup_or_detour, enable)            \
    (enable                                                                    \
         ? (*reinterpret_cast<uint64_t*>(other.prelay + 6) =                   \
                reinterpret_cast<uintptr_t>(backup_or_detour),                 \
            inject_to_target(other.ptarget, other.prelay, other.patch_above,   \
                             true __alterhook_inject_other_extra_arg(other)))  \
         : inject_to_target(other.ptarget, backup_or_detour,                   \
                            other.patch_above,                                 \
                            false __alterhook_inject_other_extra_arg(other)))

  #define __alterhook_inject_base_node(backup_or_detour, enable)               \
    (enable ? (*reinterpret_cast<uint64_t*>(pchain->prelay + 6) =              \
                   reinterpret_cast<uintptr_t>(backup_or_detour),              \
               inject_to_target(pchain->ptarget, pchain->prelay,               \
                                pchain->patch_above,                           \
                                true __alterhook_inject_base_node_extra_arg))  \
            : inject_to_target(pchain->ptarget, backup_or_detour,              \
                               pchain->patch_above,                            \
                               false __alterhook_inject_base_node_extra_arg))

  #define __alterhook_patch_jmp(detour) __alterhook_set_dtr(detour)

  #define __alterhook_patch_other_jmp(other, detour)                           \
    (*reinterpret_cast<uint64_t*>(other.prelay + 6) =                          \
         reinterpret_cast<uintptr_t>(detour))

  #define __alterhook_patch_base_node_jmp(detour)                              \
    (*reinterpret_cast<uint64_t*>(pchain->prelay + 6) =                        \
         reinterpret_cast<uintptr_t>(detour))
#else
  #define __alterhook_inject(backup_or_detour, enable)                         \
    inject_to_target(ptarget, backup_or_detour, patch_above,                   \
                     enable __alterhook_inject_extra_arg)

  #define __alterhook_inject_other(other, backup_or_detour, enable)            \
    inject_to_target(other.ptarget, backup_or_detour, other.patch_above,       \
                     enable __alterhook_inject_other_extra_arg(other))

  #define __alterhook_inject_base_node(backup_or_detour, enable)               \
    inject_to_target(pchain->ptarget, backup_or_detour, pchain->patch_above,   \
                     enable __alterhook_inject_base_node_extra_arg)

  #define __alterhook_patch_jmp(detour)                                        \
    patch_jmp(ptarget, detour, patch_above __alterhook_inject_extra_arg)

  #define __alterhook_patch_other_jmp(other, detour)                           \
    patch_jmp(other.ptarget, detour,                                           \
              other.patch_above __alterhook_inject_other_extra_arg(other))

  #define __alterhook_patch_base_node_jmp(detour)                              \
    patch_jmp(pchain->ptarget, detour,                                         \
              pchain->patch_above __alterhook_inject_base_node_extra_arg)
#endif
}
