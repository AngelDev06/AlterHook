/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#include <pch.hpp>
#include <type_traits>
#include "injection.hpp"
#include "detail/injectable.hpp"
#include "hook.hpp"
#include "hook_chain.hpp"
#pragma GCC visibility push(hidden)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"

namespace alterhook::detail
{
  template <typename derived>
  injector_flags
      injectable<derived>::make_injector_flags(bool enable) const noexcept
  {
    auto flags   = make_general_flags<injector_flags>();
    flags.enable = enable;
    return flags;
  }

  template <typename derived>
  patcher_flags injectable<derived>::make_patcher_flags() const noexcept
  {
    return make_general_flags<patcher_flags>();
  }

  template <typename derived>
  void injectable<derived>::inject(const std::byte* backup_or_detour,
                                   bool             enable) const
  {
    auto* pself = static_cast<const derived*>(this);
#if !utils_x86
    if (enable && pself->prelay)
    {
      set_relay(pself->prelay, backup_or_detour);
      inject_to_target(pself->ptarget, pself->prelay,
                       make_injector_flags(enable));
      return;
    }
#endif
    inject_to_target(pself->ptarget, backup_or_detour,
                     make_injector_flags(enable));
  }

  template <typename derived>
  void injectable<derived>::patch(const std::byte* detour) const
  {
    auto* pself = static_cast<const derived*>(this);
#if !utils_x86
  #if !always_use_relay
    if (pself->prelay)
  #endif // !always_use_relay
    {
      set_relay(pself->prelay, detour);
      return;
    }
#endif // !utils_x86

#if utils_x86 || !always_use_relay
    patch_jmp(pself->ptarget, detour, make_patcher_flags());
#endif // utils_x86 || !always_use_relay
  }

  template <typename derived>
  template <typename T>
  T injectable<derived>::make_general_flags() const noexcept
  {
    static_assert(std::is_same_v<T, injector_flags> ||
                  std::is_same_v<T, patcher_flags>);
    auto* pself = static_cast<const derived*>(this);
    T     flags{ pself->patch_above };

#if !utils_x86 && !always_use_relay
    flags.use_small_jmp = pself->prelay;
#endif // !utils_x86 && !always_use_relay
#if !utils_windows
    flags.old_protect = pself->old_protect;
#endif // !utils_windows
    return flags;
  }

  template class injectable<hook>;
  template class injectable<hook_chain>;
} // namespace alterhook::detail

#pragma GCC diagnostic pop
#pragma GCC visibility pop
