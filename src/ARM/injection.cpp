/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#include <pch.h>
#include "exceptions.h"
#include "tools.h"
#include "arm_instructions.h"
#include "injection.h"
#pragma GCC visibility push(hidden)

namespace alterhook
{
  void inject_to_target(std::byte* target, const std::byte* backup_or_detour,
                        injector_flags flags)
  {
    utils_assert(target, "inject_to_target: no target address specified");
    utils_assert(backup_or_detour,
                 "inject_to_target: no backup or detour specified");
    __define_old_protect(flags);
    const bool thumb = reinterpret_cast<uintptr_t>(target) & 1;
    reinterpret_cast<uintptr_t&>(target) &= ~1;
    const auto [address, size] =
        flags.patch_above
            ? std::pair(target - sizeof(uint32_t),
                        sizeof(arm::custom::FULL_JMP))
            : std::pair(target, flags.use_small_jmp ? sizeof(arm::B)
                                : reinterpret_cast<uintptr_t>(target) % 4
                                    ? sizeof(arm::custom::FULL_JMP) + 2
                                    : sizeof(arm::custom::FULL_JMP));
    const auto [prot_addr, prot_size] = __prot_data(address, size);

    if (!execset(prot_addr, prot_size))
      execthrow(prot_addr, prot_size);

    if (flags.enable)
    {
      const uint8_t pc_offset = thumb ? 4 : 8;
      if (flags.patch_above)
      {
        const int16_t ldr_relative_address =
            address - utils::align(target + pc_offset, 4u);
        std::byte buffer[sizeof(arm::custom::FULL_JMP)]{};
        new (buffer) auto(backup_or_detour);
        if (thumb)
          new (&buffer[sizeof(uintptr_t)])
              thumb2::custom::JMP(ldr_relative_address);
        else
          new (&buffer[sizeof(uintptr_t)])
              arm::custom::JMP(ldr_relative_address);
        memcpy(address, buffer, size);
      }
      else if (flags.use_small_jmp)
      {
        const intptr_t relative_address =
            backup_or_detour - utils::align(target + pc_offset, 4u);
        if (thumb)
          new (target) thumb2::B(relative_address);
        else
          new (target) arm::B(relative_address);
      }
      else if (thumb)
      {
        if (reinterpret_cast<uintptr_t>(target) % 4)
        {
          std::byte buffer[sizeof(arm::custom::FULL_JMP) + sizeof(arm::NOP)]{};
          new (buffer) thumb2::custom::JMP(2);
          new (&buffer[sizeof(thumb2::custom::JMP)]) thumb::NOP();
          new (&buffer[sizeof(thumb2::custom::JMP) + sizeof(thumb::NOP)]) auto(
              backup_or_detour);
          memcpy(address, buffer, size);
        }
        else
          new (target) thumb2::custom::FULL_JMP(
              reinterpret_cast<uintptr_t>(backup_or_detour));
      }
      else
        new (target) arm::custom::FULL_JMP(
            reinterpret_cast<uintptr_t>(backup_or_detour));
    }
    else
      memcpy(address, backup_or_detour, size);

    execunset(prot_addr, prot_size);
    execflush(address, size);
  }

  void patch_jmp(std::byte* target, const std::byte* detour,
                 patcher_flags flags)
  {
    utils_assert(target, "patch_jmp: no target address specified");
    utils_assert(detour, "patch_jmp: no detour specified");
    __define_old_protect(flags);
    reinterpret_cast<uintptr_t&>(target) &= ~1;
    constexpr size_t address_offset = offsetof(arm::custom::FULL_JMP, address),
                     size           = sizeof(uintptr_t);
    std::byte* const address =
        flags.patch_above ? target - sizeof(uint32_t)
        : reinterpret_cast<uintptr_t>(target) % 4
            ? target + address_offset + sizeof(thumb::NOP)
            : target + address_offset;
    const auto [prot_addr, prot_size] = __prot_data(address, size);

    if (!execset(prot_addr, prot_size))
      execthrow(prot_addr, prot_size);

    *reinterpret_cast<uint32_t*>(address) = reinterpret_cast<uintptr_t>(detour);

    execunset(prot_addr, prot_size);
    execflush(address, size);
  }

  void set_relay(std::byte* prelay, const std::byte* detour)
  {
    constexpr uint8_t address_offset = offsetof(arm::custom::FULL_JMP, address);
    *reinterpret_cast<const std::byte**>(prelay + address_offset) = detour;
  }
} // namespace alterhook

#pragma GCC visibility pop