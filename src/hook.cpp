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
  hook::hook(const hook& other) : trampoline(other)
  {
    __alterhook_copy_dtr(other);
    memcpy(backup.data(), other.backup.data(), backup.size());
  }

  hook::hook(hook&& other) noexcept
      : trampoline(std::move(other)),
        enabled(std::exchange(other.enabled, false)),
        original_buffer(other.original_buffer)
  {
    __alterhook_exchange_dtr(other);
    memcpy(backup.data(), other.backup.data(), backup.size());
    if (other.original_wrap)
    {
      other.original_wrap = nullptr;
      original_wrap =
          std::launder(reinterpret_cast<helpers::original*>(&original_buffer));
    }
  }

  hook& hook::operator=(const hook& other)
  {
    if (this != &other)
    {
      disable();
      trampoline::operator=(other);
      __alterhook_copy_dtr(other);
      memcpy(backup.data(), other.backup.data(), backup.size());
    }
    return *this;
  }

  hook& hook::operator=(hook&& other) noexcept
  {
    if (this != &other)
    {
      if (enabled)
      {
        try
        {
          disable();
        }
        catch (...)
        {
          // will most likely never happen
          assert(!"hook::operator=: failed to disable a hook in a noexcept "
                  "function");
          std::terminate();
        }
      }
      trampoline::operator=(std::move(other));
      enabled         = std::exchange(other.enabled, false);
      original_buffer = other.original_buffer;
      __alterhook_exchange_dtr(other);
      memcpy(backup.data(), other.backup.data(), backup.size());
      if (other.original_wrap)
      {
        other.original_wrap = nullptr;
        original_wrap       = std::launder(
            reinterpret_cast<helpers::original*>(&original_buffer));
      }
    }
    return *this;
  }

  hook& hook::operator=(const trampoline& other)
  {
    if (static_cast<trampoline*>(this) != &other)
    {
      const bool should_enable = enabled;
      disable();
      static_cast<trampoline&>(*this) = other;
      __alterhook_make_backup();
      if (should_enable)
        enable();
    }
    return *this;
  }

  hook& hook::operator=(trampoline&& other)
  {
    if (static_cast<trampoline*>(this) != &other)
    {
      const bool should_enable = enabled;
      disable();
      static_cast<trampoline&>(*this) = std::move(other);
      __alterhook_make_backup();
      if (should_enable)
        enable();
    }
    return *this;
  }

  hook::~hook() noexcept
  try
  {
    disable();
    if (original_wrap)
      *original_wrap = nullptr;
  }
  catch (...)
  {
    assert(!"hook::~hook: failed to disable a hook in a noexcept function");
    std::terminate();
  }

  void hook::enable()
  {
    utils_assert(__alterhook_get_dtr(), "hook::enable: invalid detour");
    if (!enabled)
    {
      std::unique_lock lock{ hook_lock };
      thread_freezer   freeze{ *this, true };
      __alterhook_inject(__alterhook_get_dtr(), true);
      enabled = true;
    }
  }

  void hook::disable()
  {
    if (enabled)
    {
      std::unique_lock lock{ hook_lock };
      thread_freezer   freeze{ *this, false };
      __alterhook_inject(backup.data(), false);
      enabled = false;
    }
  }

  void hook::set_target(std::byte* target)
  {
    if (target == ptarget)
      return;
    const bool should_enable = enabled;
    disable();
    init(target);
    __alterhook_make_backup();
    if (should_enable)
      enable();
  }

  void hook::set_detour(std::byte* detour)
  {
    if (detour == __alterhook_get_dtr())
      return;
    __alterhook_set_dtr(detour);
#if !utils_x64
    if (enabled)
    {
      std::unique_lock lock{ hook_lock };
      __alterhook_patch_jmp(detour);
    }
#endif
  }

  void hook::set_original(std::nullptr_t)
  {
    if (original_wrap)
    {
      *original_wrap = nullptr;
      original_wrap  = nullptr;
    }
  }
}

#if utils_msvc
  #pragma warning(pop)
#endif