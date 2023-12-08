/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#include <pch.h>
#include "exceptions.h"
#include "tools.h"
#include "arm_instructions.h"
#include "injection.h"

namespace alterhook
{
  ALTERHOOK_HIDDEN void inject_to_target(std::byte*       target,
                                         const std::byte* backup_or_detour,
                                         bool patch_above, bool enable,
                                         int old_protect)
  {
    utils_assert(target, "inject_to_target: no target address specified");
    utils_assert(backup_or_detour,
                 "inject_to_target: no backup or detour specified");
    const bool uses_thumb = reinterpret_cast<uintptr_t>(target) & 1;
    reinterpret_cast<uintptr_t&>(target) &= ~1;
    const auto [address, size] =
        patch_above ? std::pair(target - sizeof(uint32_t),
                                sizeof(arm::custom::FULL_JMP))
                    : std::pair(target, reinterpret_cast<uintptr_t>(target) % 4
                                            ? sizeof(arm::custom::FULL_JMP) + 2
                                            : sizeof(arm::custom::FULL_JMP));
    const auto [prot_addr, prot_size] = __prot_data(address, size);

    if (!execset(prot_addr, prot_size))
      execthrow(prot_addr, prot_size);

    if (enable)
    {
      std::byte buffer[sizeof(arm::custom::FULL_JMP) + 2]{};
      if (uses_thumb)
      {
        if (patch_above)
        {
          thumb2::custom::JMP tjmp{};
          tjmp.set_offset(address -
                          reinterpret_cast<std::byte*>(utils_align(
                              reinterpret_cast<uintptr_t>(target) + 4, 4)));
          new (buffer) auto(backup_or_detour);
          new (&buffer[sizeof(backup_or_detour)]) auto(tjmp);
        }
        else
        {
          if (reinterpret_cast<uintptr_t>(target) % 4)
          {
            thumb2::custom::JMP tjmp{};
            tjmp.set_offset(2);
            new (buffer) auto(tjmp);
            new (&buffer[sizeof(tjmp) + 2]) auto(backup_or_detour);
          }
          else
            new (buffer) thumb2::custom::FULL_JMP(
                reinterpret_cast<uintptr_t>(backup_or_detour));
        }
      }
      else
      {
        if (patch_above)
        {
          arm::custom::JMP jmp{};
          jmp.set_offset(address - (target + 8));
          new (buffer) auto(backup_or_detour);
          new (&buffer[sizeof(backup_or_detour)]) auto(jmp);
        }
        else
          new (buffer) arm::custom::FULL_JMP(
              reinterpret_cast<uintptr_t>(backup_or_detour));
      }
      memcpy(address, buffer, size);
    }
    else
      memcpy(address, backup_or_detour, size);

    execunset(prot_addr, prot_size);
    execflush(address, size);
  }

  ALTERHOOK_HIDDEN void patch_jmp(std::byte* target, const std::byte* detour,
                                  bool patch_above, int old_protect)
  {
    utils_assert(target, "patch_jmp: no target address specified");
    utils_assert(detour, "patch_jmp: no detour specified");
    reinterpret_cast<uintptr_t&>(target) &= ~1;
    constexpr size_t address_offset = offsetof(arm::custom::FULL_JMP, address),
                     size           = sizeof(uint32_t);
    std::byte* const address = patch_above ? target - sizeof(uint32_t)
                               : reinterpret_cast<uintptr_t>(target) % 4
                                   ? target + address_offset + 2
                                   : target + address_offset;
    const auto [prot_addr, prot_size] = __prot_data(address, size);

    if (!execset(prot_addr, prot_size))
      execthrow(prot_addr, prot_size);

    *reinterpret_cast<uint32_t*>(address) = reinterpret_cast<uintptr_t>(detour);

    execunset(prot_addr, prot_size);
    execflush(address, size);
  }
} // namespace alterhook