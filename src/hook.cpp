/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#include <pch.h>
#include "hook.h"
#include "injection.h"

#if utils_msvc
  #pragma warning(push)
  #pragma warning(disable : 4297)
#endif

namespace alterhook
{
  hook::hook(const hook& other)
      : trampoline(other), pdetour(other.pdetour), backup(other.backup),
        original_buffer(other.original_buffer),
        original_wrap(other.original_wrap
                          ? std::launder(reinterpret_cast<helpers::original*>(
                                &original_buffer))
                          : nullptr)
  {
  }

  hook::hook(hook&& other) noexcept
      : trampoline(std::move(other)),
        pdetour(std::exchange(other.pdetour, nullptr)),
        enabled(std::exchange(other.enabled, false)), backup(other.backup),
        original_buffer(other.original_buffer),
        original_wrap(std::exchange(other.original_wrap, nullptr)
                          ? std::launder(reinterpret_cast<helpers::original*>(
                                &original_buffer))
                          : nullptr)
  {
  }

  hook& hook::operator=(const hook& other)
  {
    if (this == &other)
      return *this;

    disable();
    trampoline::operator=(other);
    pdetour = other.pdetour;
    backup  = other.backup;

    if (!other.original_wrap)
      return *this;

    original_buffer = other.original_buffer;
    original_wrap =
        std::launder(reinterpret_cast<helpers::original*>(&original_buffer));
    return *this;
  }

  hook& hook::operator=(hook&& other) noexcept
  {
    if (this == &other)
      return *this;
    if (enabled)
      disable();

    trampoline::operator=(std::move(other));
    pdetour = std::exchange(other.pdetour, nullptr);
    enabled = std::exchange(other.enabled, false);
    backup  = other.backup;

    if (!other.original_wrap)
      return *this;

    original_buffer = other.original_buffer;
    original_wrap =
        std::launder(reinterpret_cast<helpers::original*>(&original_buffer));
    other.original_wrap = nullptr;
    return *this;
  }

  hook& hook::operator=(const trampoline& other)
  {
    if (static_cast<trampoline*>(this) == &other)
      return *this;

    const bool should_enable = enabled;
    disable();
    trampoline::operator=(other);
    helpers::make_backup(ptarget, backup.data(), patch_above);
    if (should_enable)
      enable();
    return *this;
  }

  hook& hook::operator=(trampoline&& other)
  {
    if (static_cast<trampoline*>(this) == &other)
      return *this;

    const bool should_enable = enabled;
    disable();
    trampoline::operator=(std::move(other));
    helpers::make_backup(ptarget, backup.data(), patch_above);
    if (original_wrap)
      *original_wrap = helpers::resolve_original(ptarget, ptrampoline.get());
    if (should_enable)
      enable();
    return *this;
  }

  hook::~hook() noexcept
  {
    disable();
    if (original_wrap)
      *original_wrap = nullptr;
  }

  void hook::enable()
  {
    utils_assert(pdetour, "hook::enable: invalid detour");
    if (!enabled)
    {
      std::unique_lock lock{ hook_lock };
      thread_freezer   freeze{ *this, true };
      inject(pdetour, true);
      enabled = true;
    }
  }

  void hook::disable()
  {
    if (enabled)
    {
      std::unique_lock lock{ hook_lock };
      thread_freezer   freeze{ *this, false };
      inject(backup.data(), false);
      enabled = false;
    }
  }

  hook& hook::set_target(std::byte* target)
  {
    if (target == ptarget)
      return *this;
    const bool should_enable = enabled;
    disable();
    init(target);
    helpers::make_backup(target, backup.data(), patch_above);

    if (should_enable)
      enable();
    return *this;
  }

  void hook::set_detour(std::byte* detour)
  {
    utils_assert(ptarget, "Attempt to set the detour of an uninitialized hook");
    if (detour == pdetour)
      return;

    if (enabled)
    {
      std::unique_lock lock{ hook_lock };
      patch(detour);
    }
    pdetour = detour;
  }

  void hook::set_original(const helpers::orig_buff_t& original)
  {
    thread_freezer freeze{};
    if (enabled)
      freeze.init(nullptr);
    if (!original_wrap)
    {
      original_buffer = original;
      original_wrap =
          std::launder(reinterpret_cast<helpers::original*>(&original_buffer));
      *original_wrap = helpers::resolve_original(ptarget, ptrampoline.get());
      return;
    }
    helpers::orig_buff_t tmp = std::exchange(original_buffer, original);
    *original_wrap = helpers::resolve_original(ptarget, ptrampoline.get());
    *std::launder(reinterpret_cast<helpers::original*>(&tmp)) = nullptr;
  }

  hook& hook::reset_original()
  {
    if (original_wrap)
    {
      thread_freezer freeze{};
      if (enabled)
        freeze.init(nullptr);
      *original_wrap = nullptr;
      original_wrap  = nullptr;
    }
    return *this;
  }

  bool hook::operator==(const hook& other) const noexcept
  {
    return std::tie(ptarget, pdetour, enabled) ==
           std::tie(other.ptarget, other.pdetour, other.enabled);
  }

  bool hook::operator!=(const hook& other) const noexcept
  {
    return std::tie(ptarget, pdetour, enabled) !=
           std::tie(other.ptarget, other.pdetour, other.enabled);
  }
} // namespace alterhook

#if utils_msvc
  #pragma warning(pop)
#endif
