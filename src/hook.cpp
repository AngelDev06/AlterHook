/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#include <pch.hpp>
#include <utility>
#include "hook.hpp"
#include "thread_handler.hpp"
#include "tools.hpp"

#if utils_msvc
  #pragma warning(push)
  #pragma warning(disable : 4297)
#endif

namespace alterhook
{
  hook::hook(hook&& other) noexcept
      : trampoline(std::move(other)),
        pdetour(std::exchange(other.pdetour, nullptr)),
        enabled(std::exchange(other.enabled, false)), backup(other.backup),
        original_ref(std::move(other.original_ref))
  {
  }

  hook& hook::operator=(hook&& other) noexcept
  {
    if (this == &other)
      return *this;
    if (enabled)
    {
      try
      {
        disable();
      }
      catch (...)
      {
        release();
      }
    }

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
      original_ref.bind_original(get_original());
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
      original_ref.bind_original(get_original());
    if (should_enable)
      enable();
    return *this;
  }

  hook::~hook() noexcept
  {
    try
    {
      disable();
    }
    catch (...)
    {
      release();
    }
    if (original_ref)
      original_ref.unbind_original();
  }

  void hook::enable()
  {
    utils_assert(pdetour, "hook::enable: invalid detour");
    if (!enabled)
    {
      thread_freezer freeze{ *this, true };
      inject(pdetour, true);
      enabled = true;
    }
  }

  void hook::disable()
  {
    if (enabled)
    {
      thread_freezer freeze{ *this, false };
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
      thread_freezer freeze;
      patch(detour);
    }
    pdetour = detour;
  }

  void hook::set_original(const helpers::original_ref_handler& new_original)
  {
    if (original_ref.same_reference(new_original))
      return;
    thread_freezer freeze{ defer_freeze };
    if (enabled)
      freeze.init();
    if (original_ref)
      original_ref.unbind_original();

    original_ref = new_original;
    original_ref.bind_original(get_original());
  }

  hook& hook::reset_original()
  {
    if (!original_ref)
      return *this;
    thread_freezer freeze{ defer_freeze };
    if (enabled)
      freeze.init();
    original_ref.unbind_original();
    return *this;
  }
} // namespace alterhook

#if utils_msvc
  #pragma warning(pop)
#endif
