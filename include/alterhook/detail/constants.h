/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include "macros.h"

namespace alterhook::detail::constants
{
#if utils_arm
  inline constexpr size_t patch_above_backup_size   = sizeof(uint64_t);
  inline constexpr size_t patch_above_target_offset = sizeof(uint32_t);
  inline constexpr size_t backup_size               = sizeof(uint64_t);
#else
  inline constexpr size_t patch_above_backup_size   = 7;
  inline constexpr size_t patch_above_target_offset = 5;
  inline constexpr size_t backup_size               = 5;
#endif
}