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
      : trampoline(other), original_buffer(other.original_buffer)
  {
    __alterhook_copy_dtr(other);
    memcpy(backup.data(), other.backup.data(), backup.size());
    if (other.original_wrap)
      original_wrap =
          std::launder(reinterpret_cast<helpers::original*>(&original_buffer));
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
      if (other.original_wrap)
      {
        original_buffer = other.original_buffer;
        if (!original_wrap)
          original_wrap = std::launder(
              reinterpret_cast<helpers::original*>(&original_buffer));
      }
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
      trampoline::operator=(other);
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
      trampoline::operator=(std::move(other));
      __alterhook_make_backup();
      __alterhook_def_thumb_var(ptarget);
      if (original_wrap)
        *original_wrap = __alterhook_add_thumb_bit(ptrampoline.get());
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
    const std::byte* const dtr = __alterhook_get_dtr();
    utils_assert(dtr, "hook::enable: invalid detour");
    if (!enabled)
    {
      std::unique_lock lock{ hook_lock };
      thread_freezer   freeze{ *this, true };
      inject(dtr, true);
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

  void hook::set_target(std::byte* target)
  {
    if (target == ptarget)
      return;
#if utils_64bit
    const std::byte* const tmpdtr = __alterhook_get_dtr();
#endif
    const bool should_enable = enabled;
    disable();
    init(target);
    __alterhook_make_backup();

    if (should_enable)
    {
#if utils_64bit
      utils_assert(prelay, "hook::set_target: detour was corrupted");
      __alterhook_set_dtr(tmpdtr);
#endif
      enable();
    }
  }

  void hook::set_detour(std::byte* detour)
  {
    utils_assert(ptarget, "Attempt to set the detour of an uninitialized hook");
    if (detour == __alterhook_get_dtr())
      return;

#if utils_64bit
    __alterhook_set_dtr(detour);
#else
    if (enabled)
    {
      std::unique_lock lock{ hook_lock };
      patch(detour);
    }
    pdetour = detour;
#endif
  }

  void hook::set_original(const helpers::orig_buff_t& original)
  {
    thread_freezer freeze{};
    if (enabled)
      freeze.init(nullptr);
    __alterhook_def_thumb_var(ptarget);
    if (!original_wrap)
    {
      original_buffer = original;
      original_wrap =
          std::launder(reinterpret_cast<helpers::original*>(&original_buffer));
      *original_wrap = __alterhook_add_thumb_bit(ptrampoline.get());
      return;
    }
    helpers::orig_buff_t tmp = std::exchange(original_buffer, original);
    *original_wrap           = __alterhook_add_thumb_bit(ptrampoline.get());
    *std::launder(reinterpret_cast<helpers::original*>(&tmp)) = nullptr;
  }

  void hook::reset_original()
  {
    if (original_wrap)
    {
      thread_freezer freeze{};
      if (enabled)
        freeze.init(nullptr);
      *original_wrap = nullptr;
      original_wrap  = nullptr;
    }
  }

  bool hook::operator==(const hook& other) const noexcept
  {
    return std::forward_as_tuple(ptarget, __alterhook_get_dtr(), enabled) ==
           std::forward_as_tuple(
               other.ptarget, __alterhook_get_other_dtr(other), other.enabled);
  }

  bool hook::operator!=(const hook& other) const noexcept
  {
    return std::forward_as_tuple(ptarget, __alterhook_get_dtr(), enabled) !=
           std::forward_as_tuple(
               other.ptarget, __alterhook_get_other_dtr(other), other.enabled);
  }
} // namespace alterhook

#if utils_msvc
  #pragma warning(pop)
#endif