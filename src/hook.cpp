/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#include <pch.hpp>
#include <utility>
#include "hook.hpp"
#include "injection.hpp"
#include "tools.hpp"

#if utils_msvc
  #pragma warning(push)
  #pragma warning(disable : 4297)
#endif

namespace alterhook
{
  hook::hook(const hook& other)
      : trampoline(other), pdetour(other.pdetour), backup(other.backup),
        original_ref(other.original_ref)
  {
  }

  hook::hook(hook&& other) noexcept
      : trampoline(std::move(other)),
        pdetour(std::exchange(other.pdetour, nullptr)),
        enabled(std::exchange(other.enabled, false)), backup(other.backup),
        original_ref(std::move(other.original_ref))
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

    if (!other.original_ref)
      return *this;
    original_ref = other.original_ref;
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

    if (!other.original_ref)
      return *this;

    original_ref = std::move(other.original_ref);
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
    if (original_ref)
      original_ref.bind_original(
          helpers::resolve_original(ptarget, ptrampoline.get()));
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
    if (original_ref)
      original_ref.bind_original(
          helpers::resolve_original(ptarget, ptrampoline.get()));
    if (should_enable)
      enable();
    return *this;
  }

  hook::~hook() noexcept
  {
    disable();
    if (original_ref)
      original_ref.unbind_original();
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

  void hook::set_original(const helpers::original_ref_handler& new_original)
  {
    thread_freezer freeze{};
    if (enabled)
      freeze.init(nullptr);
    if (original_ref)
      original_ref.unbind_original();

    original_ref = new_original;
    original_ref.bind_original(
        helpers::resolve_original(ptarget, ptrampoline.get()));
  }

  hook& hook::reset_original()
  {
    if (!original_ref)
      return *this;
    thread_freezer freeze{};
    if (enabled)
      freeze.init(nullptr);
    original_ref.unbind_original();
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
