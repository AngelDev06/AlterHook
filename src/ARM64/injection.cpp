/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#include <pch.h>
#include "trampoline.h"
#include "exceptions.h"
#include "injection.h"
#include "arm64_instructions.h"

namespace alterhook
{
  ALTERHOOK_HIDDEN void inject_to_target(std::byte*       target,
                                         const std::byte* backup_or_detour,
                                         injector_flags   flags)
  {
    utils_assert(target, "inject_to_target: no target address specified");
    utils_assert(backup_or_detour,
                 "inject_to_target: no backup or detour specified");
    constexpr size_t far_jump_size =
        sizeof(aarch64::LDR) + sizeof(aarch64::BR) + sizeof(uint64_t);
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
      if (flags.use_small_jmp)
        new (target) aarch64::B(backup_or_detour - target);
      else
      {
        std::array<aarch64::INSTRUCTION, far_jump_size> buffer{};
        const auto [instruction_begin, address_begin, ldr_offset] =
            flags.patch_above ? std::tuple(2, 0, -8) : std::tuple(0, 2, 8);

        new (&buffer[instruction_begin]) aarch64::LDR(
            ldr_offset, aarch64::X17, aarch64::register_size::dword);
        new (&buffer[instruction_begin + 1]) aarch64::BR(aarch64::X17);
        new (&buffer[address_begin]) auto(backup_or_detour);

        memcpy(address, buffer.data(), size);
      }
    }
    else
      memcpy(address, backup_or_detour, size);

    execunset(prot_addr, prot_size);
    execflush(address, size);
  }

  ALTERHOOK_HIDDEN void patch_jmp(std::byte* target, const std::byte* detour,
                                  patcher_flags flags)
  {
    utils_assert(target, "patch_jmp: no target address specified");
    utils_assert(detour, "patch_jmp: no detour specified");
    const auto [address, size] =
        flags.use_small_jmp
            ? std::pair(target, sizeof(aarch64::B))
            : std::pair(flags.patch_above ? target - sizeof(uint64_t)
                                          : target + sizeof(aarch64::LDR) +
                                                sizeof(aarch64::BR),
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
} // namespace alterhook