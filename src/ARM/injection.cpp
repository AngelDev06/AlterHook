/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#include <pch.h>
#include "exceptions.h"
#include "tools.h"
#include "instructions.h"
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
    constexpr size_t far_jump_size        = sizeof(arm::custom::FULL_JMP);
    const auto [address, size] =
        flags.use_small_jmp ? std::pair(target, sizeof(arm::B))
        : flags.patch_above
            ? std::pair(target - sizeof(uintptr_t), far_jump_size)
            : std::pair(target, static_cast<size_t>(
                                    utils::align_up(target + far_jump_size,
                                                    sizeof(uintptr_t)) -
                                    target));
    const auto [prot_addr, prot_size] = __prot_data(address, size);

    if (!execset(prot_addr, prot_size))
      execthrow(prot_addr, prot_size);

    if (flags.enable)
    {
      const auto    detour    = reinterpret_cast<uintptr_t>(backup_or_detour);
      if (flags.patch_above)
      {
        assert(!(reinterpret_cast<uintptr_t>(target) % sizeof(uintptr_t)));
        if (thumb)
          new (address) thumb2::custom::FULL_JMP_FROM_ABOVE(detour);
        else
          new (address) arm::custom::FULL_JMP_FROM_ABOVE(detour);
      }
      else if (flags.use_small_jmp)
      {
        const uint8_t  pc_offset = thumb ? 4 : 8;
        const intptr_t relative_address =
            backup_or_detour - utils::align(target + pc_offset, 4u);
        if (thumb)
          new (address) thumb2::B(relative_address);
        else
          new (address) arm::B(relative_address);
      }
      else if (thumb)
      {
        if (reinterpret_cast<uintptr_t>(target) % sizeof(uintptr_t))
          new (address) thumb2::custom::ALIGNED_FULL_JMP(detour);
        else
          new (address) thumb2::custom::FULL_JMP(detour);
      }
      else
        new (address) arm::custom::FULL_JMP(detour);
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