/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#include <pch.h>
#include "exceptions.h"
#include "tools.h"
#include "x86_instructions.h"
#include "injection.h"

namespace alterhook
{
  ALTERHOOK_HIDDEN void inject_to_target(std::byte*       target,
                                         const std::byte* backup_or_detour,
                                         bool             patch_above,
                                         bool enable      __int_old_protect)
  {
    utils_assert(target, "inject_to_target: no target address specified");
    utils_assert(backup_or_detour,
                 "inject_to_target: no backup or detour specified");
    __define_old_protect();
    const auto [address, size] =
        patch_above
            ? std::pair(target - detail::constants::patch_above_target_offset,
                        detail::constants::patch_above_backup_size)
            : std::pair(target, detail::constants::backup_size);
    const auto [prot_addr, prot_size] = __prot_data(address, size);

    if (!execset(prot_addr, prot_size))
      execthrow(prot_addr, prot_size);

    if (enable)
    {
      new (address) JMP(
          static_cast<uint32_t>(backup_or_detour - (address + sizeof(JMP))));

      if (patch_above)
        new (address + sizeof(JMP)) JMP_SHORT(
            static_cast<uint8_t>(0 - (sizeof(JMP) + sizeof(JMP_SHORT))));
    }
    else
      memcpy(address, backup_or_detour, size);

    execunset(prot_addr, prot_size);
    execflush(address, size);
  }

#if !utils_x64
  ALTERHOOK_HIDDEN void patch_jmp(std::byte* target, const std::byte* detour,
                                  bool patch_above __int_old_protect)
  {
    utils_assert(target, "patch_jmp: no target address specified");
    utils_assert(detour, "patch_jmp: no detour specified");
    __define_old_protect();
    constexpr size_t patch_above_address_offset = sizeof(uint32_t),
                     address_offset             = offsetof(JMP, offset),
                     size                       = sizeof(uint32_t);
    std::byte* const address = patch_above ? target - patch_above_address_offset
                                           : target + address_offset;
    const auto [prot_addr, prot_size] = __prot_data(address, size);

    if (!execset(prot_addr, prot_size))
      execthrow(prot_addr, prot_size);

    *reinterpret_cast<uint32_t*>(address) =
        static_cast<uint32_t>(detour - (target + sizeof(JMP)));

    execunset(prot_addr, prot_size);
    execflush(address, size);
  }
#endif
} // namespace alterhook
