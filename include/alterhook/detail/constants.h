/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include "macros.h"

namespace alterhook::detail::constants
{
#if utils_aarch64
  inline constexpr size_t patch_above_backup_size =
      3 * sizeof(uint32_t) + sizeof(uint64_t);
  inline constexpr size_t patch_above_target_offset = sizeof(uint64_t);
  inline constexpr size_t backup_size = 3 * sizeof(uint32_t) + sizeof(uint64_t);
#elif utils_arm
  inline constexpr size_t patch_above_backup_size =
      3 * sizeof(uint16_t) + sizeof(uint32_t);
  inline constexpr size_t patch_above_target_offset = sizeof(uint32_t);
  inline constexpr size_t backup_size = 3 * sizeof(uint16_t) + sizeof(uint32_t);
#elif utils_x86 || utils_x64
  inline constexpr size_t patch_above_backup_size   = 7;
  inline constexpr size_t patch_above_target_offset = 5;
  #if utils_x64
  inline constexpr size_t backup_size       = 14;
  inline constexpr size_t small_backup_size = 5;
  #else
  inline constexpr size_t backup_size       = 5;
  inline constexpr size_t small_backup_size = backup_size;
  #endif
#endif
} // namespace alterhook::detail::constants