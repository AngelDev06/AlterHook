/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#include <pch.h>
#include "trampoline.h"
#include "exceptions.h"
#include "injection.h"
#include "instructions.h"
#pragma GCC visibility push(hidden)

namespace alterhook
{
  void inject_to_target(std::byte* target, const std::byte* backup_or_detour,
                        injector_flags flags)
  {
    utils_assert(target, "inject_to_target: no target address specified");
    utils_assert(backup_or_detour,
                 "inject_to_target: no backup or detour specified");
    constexpr size_t far_jump_size = sizeof(aarch64::custom::FULL_JMP);
    __define_old_protect(flags);
    const auto [address, size] =
        flags.use_small_jmp ? std::pair(target, sizeof(aarch64::B))
        : flags.patch_above
            ? std::pair(target - sizeof(uint64_t), far_jump_size)
            : std::pair(target, far_jump_size);
    const auto [prot_addr, prot_size] = __prot_data(address, size);

    if (!execset(prot_addr, prot_size))
      execthrow(prot_addr, prot_size);

    if (flags.enable)
    {
      if (flags.patch_above)
      {
        assert(!(reinterpret_cast<uintptr_t>(address) % 8));
        std::array<std::byte, far_jump_size> buffer{};
        new (buffer.data()) auto(backup_or_detour);
        new (&buffer[sizeof(backup_or_detour)])
            aarch64::custom::JMP(static_cast<int32_t>(address - target));
        memcpy(address, buffer.data(), buffer.size());
      }
      else if (flags.use_small_jmp)
        new (target)
            aarch64::B(static_cast<int32_t>(backup_or_detour - target));
      else if (reinterpret_cast<uintptr_t>(address) % 8)
      {
        constexpr int32_t address_pos = sizeof(aarch64::custom::JMP) + 4;
        std::array<std::byte, far_jump_size + 2> buffer{};
        new (buffer.data()) aarch64::custom::JMP(address_pos);
#ifndef NDEBUG
        new (&buffer[sizeof(aarch64::custom::JMP)]) aarch64::BRK();
#endif
        new (&buffer[address_pos]) auto(backup_or_detour);
        memcpy(address, buffer.data(), buffer.size());
      }
      else
        new (address) aarch64::custom::FULL_JMP(
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
    constexpr auto far_jump_address_offset =
        offsetof(aarch64::custom::FULL_JMP, address);
    constexpr auto aligned_far_jump_address_offset =
        sizeof(aarch64::custom::JMP) + 4;
    __define_old_protect(flags);
    const auto [address, size] =
        flags.use_small_jmp
            ? std::pair(target, sizeof(aarch64::B))
            : std::pair(flags.patch_above ? target - sizeof(uint64_t)
                        : reinterpret_cast<uintptr_t>(target) % 8
                            ? target + aligned_far_jump_address_offset
                            : target + far_jump_address_offset,
                        sizeof(uint64_t));
    const auto [prot_addr, prot_size] = __prot_data(address, size);

    if (!execset(prot_addr, prot_size))
      execthrow(prot_addr, prot_size);

    if (flags.use_small_jmp)
      std::launder(reinterpret_cast<aarch64::B*>(target))
          ->set_offset(detour - target);
    else
      *reinterpret_cast<uint64_t*>(address) =
          reinterpret_cast<uintptr_t>(detour);

    execunset(prot_addr, prot_size);
    execflush(address, size);
  }

  void set_relay(std::byte* prelay, const std::byte* detour)
  {
    std::launder(reinterpret_cast<aarch64::custom::FULL_JMP*>(prelay))
        ->address = reinterpret_cast<uintptr_t>(detour);
  }
} // namespace alterhook

#pragma GCC visibility pop
