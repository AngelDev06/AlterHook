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
  template <typename T>
  static size_t get_jump_size(T&& flags) noexcept
  {
#if !always_use_relay && utils_x64
    if (flags.use_small_jmp)
      return detail::constants::small_backup_size;
#endif
    return detail::constants::backup_size;
  }

  void inject_to_target(std::byte* target, const std::byte* backup_or_detour,
                        injector_flags flags)
  {
    utils_assert(target, "inject_to_target: no target address specified");
    utils_assert(backup_or_detour,
                 "inject_to_target: no backup or detour specified");
    __define_old_protect(flags);
    const auto [address, size] =
        flags.patch_above
            ? std::pair(target - detail::constants::patch_above_target_offset,
                        detail::constants::patch_above_backup_size)
            : std::pair(target, get_jump_size(flags));
    const auto [prot_addr, prot_size] = __prot_data(address, size);

    if (!execset(prot_addr, prot_size))
      execthrow(prot_addr, prot_size);

    if (flags.enable)
    {
#if !always_use_relay && utils_x64
      if (!flags.use_small_jmp)
        new (address) JMP_ABS(reinterpret_cast<uintptr_t>(backup_or_detour));
      else
#endif
      {
        new (address) JMP(
            static_cast<uint32_t>(backup_or_detour - (address + sizeof(JMP))));

        if (flags.patch_above)
          new (address + sizeof(JMP)) JMP_SHORT(
              static_cast<uint8_t>(0 - (sizeof(JMP) + sizeof(JMP_SHORT))));
      }
    }
    else
      memcpy(address, backup_or_detour, size);

    execunset(prot_addr, prot_size);
    execflush(address, size);
  }

#if utils_x86 || !always_use_relay
  void patch_jmp(std::byte* target, const std::byte* detour,
                 [[maybe_unused]] patcher_flags flags)
  {
    utils_assert(target, "patch_jmp: no target address specified");
    utils_assert(detour, "patch_jmp: no detour specified");
    __define_old_protect(flags);
    constexpr size_t size = detail::constants::backup_size;
  #if utils_x64
    std::byte* const address = target;
  #else
    std::byte* const address =
        flags.patch_above
            ? target - detail::constants::patch_above_target_offset
            : target;
  #endif
    const auto [prot_addr, prot_size] = __prot_data(address, size);

    if (!execset(prot_addr, prot_size))
      execthrow(prot_addr, prot_size);

  #if utils_x64
    std::launder(reinterpret_cast<JMP_ABS*>(address))->address =
        reinterpret_cast<uintptr_t>(detour);
  #else
    std::launder(reinterpret_cast<JMP*>(address))->offset =
        static_cast<uint32_t>(detour - (address + sizeof(JMP)));
  #endif

    execunset(prot_addr, prot_size);
    execflush(address, size);
  }
#endif

#if !utils_x86
  void set_relay(std::byte* prelay, const std::byte* detour)
  {
    std::launder(reinterpret_cast<JMP_ABS*>(prelay))->address =
        reinterpret_cast<uintptr_t>(detour);
  }
#endif
} // namespace alterhook

#pragma GCC visibility pop
