/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#include <pch.h>
#include "exceptions.h"
#include "addresser.h"
#include "buffer.h"
#include "tools.h"
#if !utils_windows
  #include "linux_thread_handler.h"
#else
  #include "windows_thread_handler.h"
#endif
#include "api.h"

namespace alterhook
{
  extern std::shared_mutex hook_lock;

#if !utils_windows
  void inject_to_target(std::byte* target, const std::byte* backup_or_detour,
                        bool patch_above, bool enable, int old_protect);
  #if !utils_x64
  void patch_jmp(std::byte* target, const std::byte* detour, bool patch_above,
                 int old_protect);
  #endif

  #define __alterhook_inject_extra_arg              , old_protect
  #define __alterhook_inject_base_node_extra_arg    , pchain->old_protect
  #define __alterhook_inject_other_extra_arg(other) , other.old_protect
#else
  void inject_to_target(std::byte* target, const std::byte* backup_or_detour,
                        bool patch_above, bool enable);
  // note that patch_jmp is not needed for x64 builds
  #if !utils_x64
  void patch_jmp(std::byte* target, const std::byte* detour, bool patch_above);
  #endif

  #define __alterhook_inject_extra_arg
  #define __alterhook_inject_base_node_extra_arg
  #define __alterhook_inject_other_extra_arg(other)
#endif

#if utils_x64
  #define __alterhook_inject(backup_or_detour, enable)                         \
    (enable ? (__alterhook_set_dtr(backup_or_detour),                          \
               inject_to_target(ptarget, prelay, patch_above,                  \
                                true __alterhook_inject_extra_arg))            \
            : inject_to_target(ptarget, backup_or_detour, patch_above,         \
                               false __alterhook_inject_extra_arg))

  #define __alterhook_inject_other(other, backup_or_detour, enable)            \
    (enable                                                                    \
         ? (*reinterpret_cast<uint64_t*>(other.prelay + 6) =                   \
                reinterpret_cast<uintptr_t>(backup_or_detour),                 \
            inject_to_target(other.ptarget, other.prelay, other.patch_above,   \
                             true __alterhook_inject_other_extra_arg(other)))  \
         : inject_to_target(other.ptarget, backup_or_detour,                   \
                            other.patch_above,                                 \
                            false __alterhook_inject_other_extra_arg(other)))

  #define __alterhook_inject_base_node(backup_or_detour, enable)               \
    (enable ? (*reinterpret_cast<uint64_t*>(pchain->prelay + 6) =              \
                   reinterpret_cast<uintptr_t>(backup_or_detour),              \
               inject_to_target(pchain->ptarget, pchain->prelay,               \
                                pchain->patch_above,                           \
                                true __alterhook_inject_base_node_extra_arg))  \
            : inject_to_target(pchain->ptarget, backup_or_detour,              \
                               pchain->patch_above,                            \
                               false __alterhook_inject_base_node_extra_arg))

  #define __alterhook_patch_jmp(detour) __alterhook_set_dtr(detour)

  #define __alterhook_patch_other_jmp(other, detour)                           \
    (*reinterpret_cast<uint64_t*>(other.prelay + 6) =                          \
         reinterpret_cast<uintptr_t>(detour))

  #define __alterhook_patch_base_node_jmp(detour)                              \
    (*reinterpret_cast<uint64_t*>(pchain->prelay + 6) =                        \
         reinterpret_cast<uintptr_t>(detour))
#else
  #define __alterhook_inject(backup_or_detour, enable)                         \
    inject_to_target(ptarget, backup_or_detour, patch_above,                   \
                     enable __alterhook_inject_extra_arg)

  #define __alterhook_inject_other(other, backup_or_detour, enable)            \
    inject_to_target(other.ptarget, backup_or_detour, other.patch_above,       \
                     enable __alterhook_inject_other_extra_arg(other))

  #define __alterhook_inject_base_node(backup_or_detour, enable)               \
    inject_to_target(pchain->ptarget, backup_or_detour, pchain->patch_above,   \
                     enable __alterhook_inject_base_node_extra_arg)

  #define __alterhook_patch_jmp(detour)                                        \
    patch_jmp(ptarget, detour, patch_above __alterhook_inject_extra_arg)

  #define __alterhook_patch_other_jmp(other, detour)                           \
    patch_jmp(other.ptarget, detour,                                           \
              other.patch_above __alterhook_inject_other_extra_arg(other))

  #define __alterhook_patch_base_node_jmp(detour)                              \
    patch_jmp(pchain->ptarget, detour,                                         \
              pchain->patch_above __alterhook_inject_base_node_extra_arg)
#endif

  void trampoline::deleter::operator()(std::byte* ptrampoline) const noexcept
  {
    trampoline_buffer::deallocate(ptrampoline);
  }

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

#if utils_msvc
  #pragma warning(push)
  #pragma warning(disable : 4297)
#endif

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

  /*
   * HOOK CHAIN
   */

  hook_chain::hook_chain(alterhook::hook&& other) : trampoline(std::move(other))
  {
    utils_assert(other.original_wrap,
                 "hook_chain::hook_chain: can't initialize hook chain with a "
                 "hook that doesn't hold a reference to the original");
    memcpy(backup.data(), other.backup.data(), backup.size());
    __alterhook_def_thumb_var(ptarget);

    auto [itr, should_enable] =
        other.enabled
            ? std::pair((enabled.emplace_back(), enabled.begin()), true)
            : std::pair((disabled.emplace_back(), disabled.begin()), false);

    itr->init(*this, itr, __alterhook_get_other_dtr(other),
              other.original_buffer);
    itr->enabled   = should_enable;
    itr->poriginal = __alterhook_add_thumb_bit(ptrampoline.get());
    starts_enabled = should_enable;
  }

  hook_chain::hook_chain(const hook_chain& other) : trampoline(other)
  {
    memcpy(backup.data(), other.backup.data(), backup.size());
    for (const hook& h : other)
    {
      list_iterator itr = disabled.emplace(disabled.end());
      itr->init(*this, itr, h.pdetour, h.origbuff);
    }
  }

  hook_chain::hook_chain(hook_chain&& other) noexcept
      : trampoline(std::move(other)), disabled(std::move(other.disabled)),
        enabled(std::move(other.enabled)), starts_enabled(other.starts_enabled)
  {
    memcpy(backup.data(), other.backup.data(), backup.size());
    for (hook& h : *this)
      h.pchain = this;
  }

  hook_chain::~hook_chain() noexcept
  try
  {
    clear();
  }
  catch (...)
  {
    assert(!"hook_chain::~hook_chain: failed to disable the hooks in a "
            "noexcept function");
    std::terminate();
  }

#if utils_msvc
  #pragma warning(pop)
#endif

  void hook_chain::init_chain()
  {
    std::unique_lock lock{ hook_lock };
    thread_freezer   freeze{ *this, true };
    __alterhook_inject(enabled.back().pdetour, true);
  }

  hook_chain& hook_chain::operator=(const hook_chain& other)
  {
    if (this != &other)
    {
      disable_all();
      trampoline::operator=(other);
      memcpy(backup.data(), other.backup.data(), backup.size());

      if (size() >= other.size())
      {
        auto thisitr = disabled.begin();
        for (auto otheritr = other.begin(), otherend = other.end();
             otheritr != otherend; ++otheritr, ++thisitr)
        {
          thisitr->pdetour  = otheritr->pdetour;
          thisitr->origbuff = otheritr->origbuff;
        }
        disabled.erase(thisitr, disabled.end());
      }
      else
      {
        auto otheritr = other.begin();
        for (auto thisitr = disabled.begin(), thisend = disabled.end();
             thisitr != thisend; ++thisitr, ++otheritr)
        {
          thisitr->pdetour  = otheritr->pdetour;
          thisitr->origbuff = otheritr->origbuff;
        }
        for (auto otherend = other.end(); otheritr != otherend; ++otheritr)
        {
          auto itr = disabled.emplace(disabled.end());
          itr->init(*this, itr, otheritr->pdetour, otheritr->origbuff);
        }
      }
    }
    return *this;
  }

  hook_chain& hook_chain::operator=(hook_chain&& other) noexcept
  {
    if (this != &other)
    {
      if (!enabled.empty())
        try
        {
          std::unique_lock lock{ hook_lock };
          thread_freezer   freeze{ *this, false };
          __alterhook_inject(backup.data(), false);
        }
        catch (...)
        {
          assert(!"hook_chain::operator=: failed to disable a hook in a "
                  "noexcept function");
          std::terminate();
        }
      trampoline::operator=(std::move(other));
      disabled       = std::move(other.disabled);
      enabled        = std::move(other.enabled);
      starts_enabled = other.starts_enabled;

      for (hook& h : *this)
        h.pchain = this;
    }
    return *this;
  }

  hook_chain& hook_chain::operator=(const trampoline& other)
  {
    if (static_cast<trampoline*>(this) != &other)
    {
      if (!enabled.empty())
      {
        std::unique_lock lock{ hook_lock };
        thread_freezer   freeze{ *this, false };
        __alterhook_inject(backup.data(), false);
      }

      try
      {
        trampoline::operator=(other);
        __alterhook_make_backup();
        if (!enabled.empty())
        {
          std::unique_lock lock{ hook_lock };
          thread_freezer   freeze{ *this, true };
          __alterhook_inject(enabled.back().pdetour, true);
        }
      }
      catch (...)
      {
        if (!disabled.empty())
          disabled.back().has_other = false;
        list_iterator previtr = disabled.end();
        do
        {
          list_iterator curritr = std::prev(enabled.end());
          list_iterator trgitr  = previtr;
          hook&         curr    = *curritr;

          if (curr.has_other)
          {
            if (curr.other != disabled.begin())
              std::prev(curr.other)->has_other = false;
            trgitr         = curr.other;
            curr.has_other = false;
          }

          curr.enabled = false;
          disabled.splice(trgitr, enabled, curritr);
          previtr = curritr;
        } while (!enabled.empty());

        starts_enabled = false;
        throw;
      }
    }
    return *this;
  }

  hook_chain& hook_chain::operator=(trampoline&& other)
  {
    if (static_cast<trampoline*>(this) != &other)
    {
      if (!enabled.empty())
      {
        std::unique_lock lock{ hook_lock };
        thread_freezer   freeze{ *this, false };
        __alterhook_inject(backup.data(), false);
      }

      trampoline::operator=(std::move(other));
      __alterhook_make_backup();

      if (!enabled.empty())
      {
        try
        {
          std::unique_lock lock{ hook_lock };
          thread_freezer   freeze{ *this, false };
          __alterhook_inject(enabled.back().pdetour, true);
        }
        catch (...)
        {
          if (!disabled.empty())
            disabled.back().has_other = false;
          list_iterator previtr = disabled.end();
          do
          {
            list_iterator curritr = std::prev(enabled.end());
            list_iterator trgitr  = previtr;
            hook&         curr    = *curritr;

            if (curr.has_other)
            {
              if (curr.other != disabled.begin())
                std::prev(curr.other)->has_other = false;
              trgitr         = curr.other;
              curr.has_other = false;
            }

            curr.enabled = false;
            disabled.splice(trgitr, enabled, curritr);
            previtr = curritr;
          } while (!enabled.empty());

          starts_enabled = false;
          throw;
        }
      }
    }
    return *this;
  }

  void hook_chain::clear(include trg)
  {
    if (empty())
      return;
    const auto uninject = [&]
    {
      std::unique_lock lock{ hook_lock };
      thread_freezer   freeze{ *this, false };
      __alterhook_inject(backup.data(), false);
    };

    switch (trg)
    {
    case include::disabled:
      if (disabled.empty())
        return;
      disabled.clear();

      for (hook& h : enabled)
        h.has_other = false;
      starts_enabled = true;
      break;
    case include::enabled:
      if (enabled.empty())
        return;
      uninject();
      enabled.clear();

      for (hook& h : disabled)
        h.has_other = false;
      starts_enabled = false;
      break;
    case include::both:
      if (!enabled.empty())
        uninject();
      enabled.clear();
      disabled.clear();
      break;
    }
  }

  void hook_chain::enable_all()
  {
    if (disabled.empty())
      return;
    starts_enabled = true;
    if (enabled.empty())
    {
      reverse_list_iterator rbegin = disabled.rbegin();
      __alterhook_def_thumb_var(ptarget);
      rbegin->poriginal = __alterhook_add_thumb_bit(ptrampoline.get());
      *rbegin->origwrap = rbegin->poriginal;
      thread_freezer freeze{ *this, true };
      {
        std::unique_lock lock{ hook_lock };
        __alterhook_inject(rbegin->pdetour, true);
      }
      rbegin->enabled = true;

      for (auto prev = rbegin, itr = std::next(rbegin),
                enditr = disabled.rend();
           itr != enditr; ++itr, ++prev)
      {
        itr->enabled    = true;
        itr->poriginal  = prev->poriginal;
        *itr->origwrap  = prev->poriginal;
        prev->poriginal = itr->pdetour;
        *prev->origwrap = itr->pdetour;
      }
      enabled.splice(enabled.begin(), disabled);
    }
    else
    {
      list_iterator  previtr = std::prev(disabled.end());
      hook&          dlast   = *previtr;
      thread_freezer freeze{ nullptr };
      // if disabled doesn't have other then we got to touch the target
      if (!dlast.has_other)
      {
        hook& elast     = enabled.back();
        dlast.poriginal = elast.pdetour;
        *dlast.origwrap = elast.pdetour;
        dlast.enabled   = true;
        elast.has_other = false;

        {
          std::unique_lock lock{ hook_lock };
          __alterhook_patch_jmp(dlast.pdetour);
        }

        enabled.splice(enabled.end(), disabled, previtr);
      }
      toggle_status_all(include::disabled);
    }
  }

  void hook_chain::disable_all()
  {
    if (enabled.empty())
      return;

    uninject_all();
    toggle_status_all(include::enabled);
  }

  void hook_chain::pop_back(include trg)
  {
    utils_assert(!empty(), "hook_chain::pop_back: popping from empty chain");
    list_iterator    itr{};
    std::list<hook>* to       = nullptr;
    std::list<hook>* other    = nullptr;
    const auto       uninject = [&]
    {
      std::unique_lock lock{ hook_lock };
      thread_freezer   freeze{ *this, false };
      __alterhook_inject(backup.data(), false);
    };

    switch (trg)
    {
    case include::disabled:
      itr   = std::prev(disabled.end());
      to    = &disabled;
      other = &enabled;
      break;
    case include::enabled:
      itr   = std::prev(enabled.end());
      to    = &enabled;
      other = &disabled;

      if (enabled.size() == 1)
        uninject();
      else
      {
        std::unique_lock lock{ hook_lock };
        __alterhook_patch_jmp(itr->poriginal);
      }
      break;
    case include::both:
      itr = std::prev(disabled.empty() || disabled.back().has_other
                          ? enabled.end()
                          : disabled.end());
      to  = itr->enabled ? &enabled : &disabled;

      if (itr->enabled)
      {
        if (enabled.size() == 1)
          uninject();
        else
        {
          std::unique_lock lock{ hook_lock };
          __alterhook_patch_jmp(itr->poriginal);
        }

        if (!disabled.empty())
        {
          hook& disback = disabled.back();
          if (disback.has_other && disback.other == itr)
            disback.has_other = false;
        }
      }
      else if (!enabled.empty())
      {
        hook& enback = enabled.back();
        if (enback.has_other && enback.other == itr)
          enback.has_other = false;
      }
      to->pop_back();
      return;
    }

    if (itr == to->begin())
    {
      if (itr->enabled != starts_enabled)
      {
        hook& oback     = other->back();
        oback.has_other = false;
      }
      else if (itr->has_other)
        starts_enabled = !starts_enabled;
    }
    else
    {
      list_iterator itrprev = std::prev(itr);
      if (itrprev->has_other)
      {
        hook& oback     = other->back();
        oback.has_other = false;
      }
      else if (itr->has_other)
      {
        itrprev->has_other = true;
        itrprev->other     = itr->other;
      }
    }

    to->pop_back();
  }

  void hook_chain::pop_front(include trg)
  {
    utils_assert(!empty(), "hook_chain::pop_front: popping from empty chain");
    list_iterator    itr{};
    list_iterator    itrnext{};
    std::list<hook>* to       = nullptr;
    std::list<hook>* other    = nullptr;
    const auto       uninject = [&]
    {
      std::unique_lock lock{ hook_lock };
      thread_freezer   freeze{ *this, false };
      __alterhook_inject(backup.data(), false);
    };
    const auto uninject_one = [&]
    {
      thread_freezer freeze{ nullptr };
      itrnext->poriginal = itr->poriginal;
      *itrnext->origwrap = itr->poriginal;
    };

    switch (trg)
    {
    case include::disabled:
      utils_assert(!disabled.empty(),
                   "hook_chain::pop_front: popping from empty disabled chain");
      itr     = disabled.begin();
      itrnext = std::next(itr);
      to      = &disabled;
      other   = &enabled;
      break;
    case include::enabled:
      utils_assert(!enabled.empty(),
                   "hook_chain::pop_front: popping from empty enabled chain");
      itr     = enabled.begin();
      itrnext = std::next(itr);

      if (itr->enabled)
      {
        if (itrnext == enabled.end())
          uninject();
        else
          uninject_one();
      }
      to    = &enabled;
      other = &disabled;
      break;
    case include::both:
      itr     = starts_enabled ? enabled.begin() : disabled.begin();
      itrnext = std::next(itr);

      if (itr->enabled)
      {
        if (itrnext == enabled.end())
          uninject();
        else
          uninject_one();
      }

      if (itr->has_other)
        starts_enabled = !starts_enabled;
      to = itr->enabled ? &enabled : &disabled;
      to->pop_front();
      return;
    }

    if (itr->enabled != starts_enabled)
    {
      list_iterator i = other->begin();
      while (!i->has_other)
        ++i;

      if (itr->has_other || to->size() == 1)
        i->has_other = false;
      else
        i->other = itrnext;
    }
    else if (itr->has_other)
      starts_enabled = !starts_enabled;

    to->pop_front();
  }

  hook_chain::list_iterator hook_chain::erase(list_iterator position)
  {
    if (position->enabled)
      uninject(position);

    unbind(position);

    std::list<hook>& trg = position->enabled ? enabled : disabled;
    return trg.erase(position);
  }

  hook_chain::list_iterator hook_chain::erase(list_iterator first,
                                              list_iterator last)
  {
    if (first == last)
      return last;
    std::list<hook>& trg = first->enabled ? enabled : disabled;

    if (first->enabled)
      uninject_range(first, last);

    unbind_range(first, last, [&](list_iterator itr, bool) { trg.erase(itr); });
    return last;
  }

  void hook_chain::swap(list_iterator left, hook_chain& other,
                        list_iterator right)
  {
    if (&other == this && left->enabled == right->enabled && left == right)
      return;
    std::list<hook>& lefttrg  = left->enabled ? enabled : disabled;
    std::list<hook>& righttrg = right->enabled ? other.enabled : other.disabled;
    list_iterator    leftnext = std::next(left);
    list_iterator    rightnext = std::next(right);
    const auto       do_swap   = [&]
    {
      std::swap(left->pchain, right->pchain);
      std::swap(left->other, right->other);
      std::swap(left->has_other, right->has_other);
      std::swap(left->poriginal, right->poriginal);
      std::swap(left->enabled, right->enabled);
      lefttrg.splice(leftnext, righttrg, right);
      righttrg.splice(rightnext, lefttrg, left);
      std::swap(left, right);
      *left->origwrap  = left->poriginal;
      *right->origwrap = right->poriginal;
    };

    if (left->enabled || right->enabled)
    {
      bool             injected_first = false;
      std::unique_lock lock{ hook_lock };
      thread_freezer   freeze{ nullptr };
      do_swap();

      try
      {
        if (left->enabled)
        {
          if (leftnext == enabled.end())
            __alterhook_patch_jmp(left->pdetour);
          else
          {
            leftnext->poriginal = left->pdetour;
            *leftnext->origwrap = left->pdetour;
          }
          injected_first = true;
        }

        if (right->enabled)
        {
          if (rightnext == other.enabled.end())
            __alterhook_patch_other_jmp(other, right->pdetour);
          else
          {
            rightnext->poriginal = right->pdetour;
            *rightnext->origwrap = right->pdetour;
          }
        }
      }
      catch (...)
      {
        do_swap();

        if (injected_first)
        {
          if (leftnext == other.enabled.end())
          {
            // if that throws, no guarantee is provided
            __alterhook_patch_jmp(left->pdetour);
          }
          else
          {
            leftnext->poriginal = left->pdetour;
            *leftnext->origwrap = left->pdetour;
          }
        }
        throw;
      }
    }

    bind(left, left, left->enabled);
    other.bind(right, right, right->enabled);
  }

  void hook_chain::swap(hook_chain& other)
  {
    enabled.swap(other.enabled);
    disabled.swap(other.disabled);
    std::swap(starts_enabled, other.starts_enabled);

    for (hook& h : *this)
      h.pchain = this;
    for (hook& h : other)
      h.pchain = &other;
  }

#if utils_clang
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wswitch"
#endif

  void hook_chain::splice(list_iterator newpos, hook_chain& other, transfer to,
                          transfer from)
  {
    utils_assert(&other != this, "hook_chain::splice: other needs to be a "
                                 "different hook_chain instance");
    utils_assert(to != transfer::both,
                 "hook_chain::splice: to can't be the both flag");
    if (other.empty())
      return;
    bool             to_enabled = to == transfer::enabled;
    std::list<hook>& trg        = to_enabled ? enabled : disabled;

    if (from != transfer::disabled)
      other.uninject_range(other.enabled.begin(), other.enabled.end());

    if (to_enabled)
    {
      if (from == transfer::disabled)
        inject_range(newpos, other.enabled.begin(), other.enabled.end());
      else
      {
        try
        {
          inject_range(newpos, other.enabled.begin(), other.enabled.end());
        }
        catch (...)
        {
          try
          {
            other.inject_back(other.enabled.begin(), other.enabled.end());
          }
          catch (...)
          {
            other.toggle_status_all(include::enabled);
            throw;
          }
          throw;
        }
      }
    }

    if (from == transfer::both && !empty())
    {
      hook& lastprev = other.back();

      if (lastprev.enabled != to_enabled && newpos != trg.end())
      {
        lastprev.has_other = true;
        lastprev.other     = newpos;
      }
    }

    switch (from)
    {
    case transfer::disabled:
      bind(newpos, other.disabled.begin(), to_enabled);
      break;
    case transfer::enabled:
      bind(newpos, other.enabled.end(), to_enabled);
      break;
    case transfer::both: bind(newpos, other.begin(), to_enabled); break;
    }

    if (from == transfer::both)
    {
      if (empty())
        starts_enabled = other.starts_enabled;

      list_iterator disablednewpos = newpos;
      list_iterator enablednewpos  = newpos;

      if (newpos == trg.end())
      {
        disablednewpos = disabled.end();
        enablednewpos  = enabled.end();
      }
      else
      {
        list_iterator& othernewpos =
            to_enabled ? disablednewpos : enablednewpos;
        list_iterator i = newpos;

        while (i != trg.end() && !i->has_other)
          ++i;
        if (i == trg.end())
          othernewpos = to_enabled ? disabled.end() : enabled.end();
        else
          othernewpos = i->other;
      }

      for (auto i = other.begin(), otherend = other.end(), next = iterator();
           i != otherend; i = next)
      {
        next      = std::next(i);
        i->pchain = this;
        if (i->enabled)
          enabled.splice(enablednewpos, other.enabled, i);
        else
          disabled.splice(disablednewpos, other.disabled, i);
      }
    }
    else
    {
      if (empty())
        starts_enabled = to_enabled;

      auto [from_current, from_other] =
          from == transfer::enabled
              ? std::pair(&other.enabled, &other.disabled)
              : std::pair(&other.disabled, &other.enabled);

      for (hook& h : *from_current)
      {
        h.has_other = false;
        h.pchain    = this;
        h.enabled   = to_enabled;
      }
      for (hook& h : *from_other)
        h.has_other = false;
      trg.splice(newpos, *from_current);
    }
  }

  void hook_chain::splice(list_iterator newpos, hook_chain& other,
                          list_iterator oldpos, transfer to)
  {
    utils_assert(to != transfer::both,
                 "hook_chain::splice: to can't be the both flag");
    const bool to_enabled = to == transfer::enabled;
    auto       oldnext    = std::next(oldpos);
    if (&other == this && oldpos->enabled == to_enabled &&
        (newpos == oldpos || newpos == oldnext))
      return;

    if (oldpos->enabled)
      other.uninject(oldpos);

    if (to_enabled)
    {
      if (!oldpos->enabled)
        inject_range(newpos, oldpos, oldnext);
      else
      {
        try
        {
          inject_range(newpos, oldpos, oldnext);
        }
        catch (...)
        {
          try
          {
            other.inject_back(oldpos, oldnext);
          }
          catch (...)
          {
            other.toggle_status(oldpos);
            throw;
          }
          throw;
        }
      }
    }

    other.unbind(oldpos);
    bind(newpos, oldpos, to_enabled);

    std::list<hook>& trg = to_enabled ? enabled : disabled;
    std::list<hook>& src = oldpos->enabled ? other.enabled : other.disabled;
    oldpos->has_other    = false;
    oldpos->enabled      = to_enabled;
    oldpos->pchain       = this;

    trg.splice(newpos, src, oldpos);
  }

  void hook_chain::splice(list_iterator newpos, hook_chain& other,
                          list_iterator first, list_iterator last, transfer to)
  {
    if (first == last)
      return;
    if (std::next(first) == last)
      return splice(newpos, other, first, to);
    const bool       to_enabled = to == transfer::enabled;
    std::list<hook>& trg        = to_enabled ? enabled : disabled;
    std::list<hook>& src = first->enabled ? other.enabled : other.disabled;

    if (&trg == &src && newpos == last)
      return;
    // on transfer from disabled to enabled we make sure the pieces are bound
    // together
    if (to_enabled && !first->enabled)
    {
      for (auto prev = first, current = std::next(first); current != last;
           ++prev, ++current)
      {
        current->poriginal = prev->pdetour;
        *current->origwrap = prev->pdetour;
      }
    }

    if (first->enabled)
      other.uninject_range(first, last);

    // covers transfer to enabled
    if (to_enabled)
    {
      try
      {
        inject_range(newpos, first, last);
      }
      catch (...)
      {
        if (first->enabled)
        {
          try
          {
            other.inject_back(first, last);
          }
          catch (...)
          {
            other.toggle_status(first, last);
            throw;
          }
        }
        throw;
      }
    }

    list_iterator current_newpos = newpos;

    bind(newpos, first, to_enabled);
    other.unbind_range(first, last,
                       [&](list_iterator itr, bool forward)
                       {
                         itr->has_other = false;
                         itr->enabled   = to_enabled;
                         itr->pchain    = this;
                         trg.splice(current_newpos, src, itr);
                         if (!forward)
                           current_newpos = itr;
                       });
  }

  void hook_chain::splice(list_iterator newpos, hook_chain& other,
                          iterator first, iterator last, transfer to)
  {
    utils_assert(to != transfer::both,
                 "hook_chain::splice: to can't be the both flag");
    if (first == last)
      return;
    if (std::next(first) == last)
      return splice(newpos, other, first, to);

    const bool to_enabled = to == transfer::enabled;
    const bool is_empty   = empty();

    auto [to_current, to_other] = to_enabled ? std::pair(&enabled, &disabled)
                                             : std::pair(&disabled, &enabled);

    list_iterator disablednewpos    = newpos;
    list_iterator enablednewpos     = newpos;
    list_iterator disabledoldtrgpos = last;
    list_iterator enabledoldtrgpos  = last;

    if (&other == this && last.enabled == to_enabled && newpos == last)
      return;

    // gets disablednewpos & enablednewpos
    if (newpos == to_current->end())
    {
      disablednewpos = disabled.end();
      enablednewpos  = enabled.end();
    }
    else
    {
      list_iterator& othernewpos = to_enabled ? disablednewpos : enablednewpos;
      list_iterator  i           = newpos;

      while (!i->has_other && i != to_current->end())
        ++i;
      othernewpos = i != to_current->end() ? i->other : to_other->end();
    }

    list_iterator range_begin   = first;
    list_iterator range_end     = last;
    list_iterator first_enabled = range_begin;
    list_iterator last_enabled  = range_end;
    list_iterator lastprev      = range_end;
    bool          has_enabled   = false;
    // when an exception is thrown, this is used to transfer all elements back
    // to their old position
    const auto    transfer_back = [&]
    {
      const list_iterator range_last         = std::next(lastprev);
      const bool          lastprev_has_other = lastprev->has_other;
      lastprev->has_other                    = false;

      for (auto itr    = iterator(first, first, first.enabled),
                itrend = iterator(range_last, range_last, lastprev->enabled);
           itr != itrend;)
      {
        itr->pchain = &other;
        auto [trgpos, trglist, othertrglist] =
            itr.enabled ? std::tie(enabledoldtrgpos, other.enabled, enabled)
                        : std::tie(disabledoldtrgpos, other.disabled, disabled);

        trglist.splice(trgpos, othertrglist,
                       std::exchange(itr, std::next(itr)));
      }

      lastprev->has_other = lastprev_has_other;
    };

    // search for first enabled
    if (!first.enabled)
    {
      // if neither first nor last refer to an enabled hook we can't be sure
      // that an enabled hook is within the range so we got to do safety checks.
      // otherwise we simply iterate till one is found
      if (!last.enabled)
      {
        while (range_begin != range_end && !range_begin->has_other)
        {
          range_begin->pchain = this;
          disabled.splice(disablednewpos, other.disabled,
                          std::exchange(range_begin, std::next(range_begin)));
        }

        if (range_begin != range_end)
        {
          disabledoldtrgpos   = std::next(range_begin);
          range_begin->pchain = this;
          disabled.splice(disablednewpos, other.disabled, range_begin);
          first_enabled = range_begin->other;
          has_enabled   = true;
        }
      }
      else
      {
        while (!range_begin->has_other)
        {
          range_begin->pchain = this;
          disabled.splice(disablednewpos, other.disabled,
                          std::exchange(range_begin, std::next(range_begin)));
        }

        disabledoldtrgpos   = std::next(range_begin);
        range_begin->pchain = this;
        disabled.splice(disablednewpos, other.disabled, range_begin);
        first_enabled = range_begin->other;
        if (first_enabled != range_end)
          has_enabled = true;
      }
    }
    else
      has_enabled = true;

    if (has_enabled)
    {
      // transfer everything (and keep track of last_enabled)
      for (auto itr = iterator(list_iterator(), first_enabled, true);
           itr != last;)
      {
        itr->pchain = this;
        lastprev    = itr;
        if (itr.enabled)
          last_enabled = lastprev;

        auto [oldtrgpos, trgpos, trglist, othertrglist] =
            itr.enabled ? std::tie(enabledoldtrgpos, enablednewpos, enabled,
                                   other.enabled)
                        : std::tie(disabledoldtrgpos, disablednewpos, disabled,
                                   other.disabled);

        oldtrgpos = std::next(static_cast<list_iterator>(itr));
        trglist.splice(trgpos, othertrglist,
                       std::exchange(itr, std::next(itr)));
      }

      try
      {
        if (enabledoldtrgpos == other.enabled.end())
        {
          std::unique_lock lock{ hook_lock };
          if (other.enabled.empty())
          {
            thread_freezer freeze{ other, false };
            __alterhook_inject_other(other, other.backup.data(), false);
          }
          else
            __alterhook_patch_other_jmp(other, first_enabled->pdetour);
        }
        else
        {
          thread_freezer freeze{ nullptr };
          enabledoldtrgpos->poriginal = first_enabled->poriginal;
          *enabledoldtrgpos->origwrap = first_enabled->poriginal;
        }
      }
      catch (...)
      {
        transfer_back();
        throw;
      }

      hook& otherfront = *first_enabled;
      hook& otherback  = *last_enabled;
      if (first_enabled == enabled.begin())
      {
        __alterhook_def_thumb_var(ptarget);
        otherfront.poriginal = __alterhook_add_thumb_bit(ptrampoline.get());
        *otherfront.origwrap = otherfront.poriginal;
      }
      else
      {
        list_iterator enabledprev = std::prev(first_enabled);
        otherfront.poriginal      = enabledprev->pdetour;
        *otherfront.origwrap      = enabledprev->pdetour;
      }

      try
      {
        if (enablednewpos == enabled.end())
        {
          std::unique_lock lock{ hook_lock };
          if (first_enabled == enabled.begin())
          {
            thread_freezer freeze{ *this, true };
            __alterhook_inject(otherback.pdetour, true);
          }
          else
            __alterhook_patch_jmp(otherback.pdetour);
        }
        else
        {
          thread_freezer freeze{ nullptr };
          enablednewpos->poriginal = otherback.pdetour;
          *enablednewpos->origwrap = otherback.pdetour;
        }
      }
      catch (...)
      {
        transfer_back();

        try
        {
          other.inject_back(first_enabled, std::next(last_enabled));
        }
        catch (...)
        {
          other.toggle_status(first_enabled, std::next(last_enabled));
          throw;
        }
        throw;
      }
    }
    else
    {
      for (list_iterator itr = first; itr != disabledoldtrgpos;)
      {
        itr->pchain = this;
        disabled.splice(disablednewpos, other.disabled,
                        std::exchange(itr, std::next(itr)));
      }
    }

    if (!is_empty)
    {
      const list_iterator newfirst = first;
      bool                search   = false;
      const list_iterator last_current =
          lastprev->enabled ? enabled.end() : disabled.end();
      list_iterator search_begin{};
      auto [first_current, first_other] = first.enabled
                                              ? std::pair(&enabled, &disabled)
                                              : std::pair(&disabled, &enabled);

      if (newfirst == first_current->begin())
      {
        if (starts_enabled != first.enabled)
        {
          search       = true;
          search_begin = to_other->begin();
        }
      }
      else
      {
        list_iterator newfirstprev = std::prev(newfirst);
        if (newfirstprev->has_other)
        {
          search       = true;
          search_begin = newfirstprev->other;
        }
      }

      if (search)
      {
        while (!search_begin->has_other)
          ++search_begin;
        search_begin->other = newfirst;
      }
    }
    else
      starts_enabled = first->enabled;

    if (!other.empty())
    {
      // rebind previous old position
      list_iterator oldother{};
      bool          has_old_other = true;
      if (disabledoldtrgpos == other.disabled.begin() &&
          enabledoldtrgpos == other.enabled.begin())
      {
        other.starts_enabled = last.enabled;
        has_old_other        = false;
      }
      else if (disabledoldtrgpos == other.disabled.begin())
        oldother = std::prev(enabledoldtrgpos);
      else if (enabledoldtrgpos == other.enabled.begin())
        oldother = std::prev(disabledoldtrgpos);
      else if (first.enabled)
      {
        oldother = std::prev(enabledoldtrgpos);
        if (oldother->has_other)
          oldother = std::prev(disabledoldtrgpos);
      }
      else
      {
        oldother = std::prev(disabledoldtrgpos);
        if (oldother->has_other)
          oldother = std::prev(enabledoldtrgpos);
      }

      if (has_old_other)
      {
        if (last == iterator(other.disabled.end(), other.enabled.end(),
                             last.enabled) ||
            last.enabled == oldother->enabled)
          oldother->has_other = false;
        else
        {
          oldother->has_other = true;
          oldother->other     = last;
        }
      }
    }

    // bind last to new position
    lastprev->has_other = false;
    if (to_enabled != lastprev->enabled && newpos != to_current->end())
    {
      lastprev->has_other = true;
      lastprev->other     = newpos;
    }
  }

  void hook_chain::set_target(std::byte* target)
  {
    if (ptarget == target)
      return;
    if (!enabled.empty())
    {
      std::unique_lock lock{ hook_lock };
      thread_freezer   freeze{ *this, false };
      __alterhook_inject(backup.data(), false);
    }

    init(target);
    __alterhook_make_backup();

    if (!enabled.empty())
    {
      std::unique_lock lock{ hook_lock };
      thread_freezer   freeze{ *this, true };
      __alterhook_inject(enabled.back().pdetour, true);
    }
  }

#if utils_clang
  #pragma clang diagnostic pop
#endif

  // hook_chain utilities

  // needed for stupid msvc
  typedef typename hook_chain::list_iterator hook_chain_list_iterator;

  template <__alterhook_is_invocable_impl(callable, hook_chain_list_iterator,
                                          bool)>
  void hook_chain::unbind_range(list_iterator first, list_iterator last,
                                callable&& func)
  {
    list_iterator range_begin = first, range_end = std::prev(last);
    list_iterator other_range_begin{}, other_range_end{};
    bool          has_last_link = false, has_first_link = false;
    const bool    lastprev_has_other = range_end->has_other;
    const bool    are_enabled        = first->enabled;

    // search backwards for last link from other to this range
    while (!range_end->has_other && range_end != range_begin)
      func(std::exchange(range_end, std::prev(range_end)), false);

    if (range_end->has_other)
    {
      has_last_link   = true;
      other_range_end = range_end->other;
      while (!other_range_end->has_other)
        ++other_range_end;
    }

    if ((first->enabled && first == enabled.begin()) ||
        (!first->enabled && first == disabled.begin()))
    {
      if (first->enabled != starts_enabled)
      {
        other_range_begin = first->enabled ? disabled.begin() : enabled.begin();
        has_first_link    = true;
      }
      else if (has_last_link)
        starts_enabled = !starts_enabled;
    }
    else
    {
      list_iterator firstprev = std::prev(first);
      if (firstprev->has_other)
      {
        has_first_link    = true;
        other_range_begin = firstprev->other;
      }
      else if (has_last_link)
      {
        while (!range_begin->has_other)
          func(std::exchange(range_begin, std::next(range_begin)), true);

        other_range_begin    = range_begin->other;
        has_first_link       = true;
        firstprev->has_other = true;
        firstprev->other     = other_range_begin;
      }
    }

    if (has_last_link)
    {
      if (!has_first_link)
      {
        while (!range_begin->has_other)
          func(std::exchange(range_begin, std::next(range_begin)), true);

        other_range_begin = range_begin->other;
      }

      for (; other_range_begin != other_range_end; ++other_range_begin)
        other_range_begin->has_other = false;

      if (lastprev_has_other || (are_enabled && last == enabled.end()) ||
          (!are_enabled && last == disabled.end()))
        other_range_begin->has_other = false;
      else
        other_range_begin->other = last;
    }
    else if (has_first_link)
    {
      while (!other_range_begin->has_other)
        ++other_range_begin;
      other_range_begin->other = last;
    }

    while (range_begin != last)
      func(std::exchange(range_begin, std::next(range_begin)), true);
  }

  void hook_chain::unbind(list_iterator position)
  {
    const list_iterator posnext = std::next(position);
    list_iterator       itr{};
    bool                search = false;
    auto [current, other] = position->enabled ? std::pair(&enabled, &disabled)
                                              : std::pair(&disabled, &enabled);

    if (position == current->begin())
    {
      if (position->enabled != starts_enabled)
      {
        if (posnext == current->end() && !position->has_other)
          other->back().has_other = false;
        else
        {
          search = true;
          itr    = other->begin();
        }
      }
      else if (position->has_other)
        starts_enabled = !starts_enabled;
    }
    else
    {
      list_iterator posprev = std::prev(position);
      if (posprev->has_other)
      {
        search = true;
        itr    = posprev->other;
      }
      else if (position->has_other)
      {
        posprev->has_other = true;
        posprev->other     = position->other;
      }
    }

    if (search)
    {
      while (!itr->has_other)
        ++itr;

      if (position->has_other || posnext == current->end())
        itr->has_other = false;
      else
        itr->other = posnext;
    }
  }

  void hook_chain::uninject_all()
  {
    if (enabled.empty())
      return;
    std::unique_lock lock{ hook_lock };
    thread_freezer   freeze{ *this, false };
    __alterhook_inject(backup.data(), false);
  }

  void hook_chain::uninject_range(list_iterator first, list_iterator last)
  {
    if (last == enabled.end())
    {
      std::unique_lock lock{ hook_lock };
      if (first == enabled.begin())
      {
        thread_freezer freeze{ *this, false };
        __alterhook_inject(backup.data(), false);
      }
      else
        __alterhook_patch_jmp(first->poriginal);
    }
    else
    {
      thread_freezer freeze{ nullptr };
      last->poriginal = first->poriginal;
      *last->origwrap = first->poriginal;
    }
  }

  void hook_chain::uninject(list_iterator position)
  {
    uninject_range(position, std::next(position));
  }

  // this also works for ranges
  void hook_chain::bind(list_iterator pos, list_iterator oldpos,
                        bool to_enabled)
  {
    if (empty())
    {
      starts_enabled = to_enabled;
      return;
    }

    auto [current, other] = to_enabled ? std::pair(&enabled, &disabled)
                                       : std::pair(&disabled, &enabled);

    bool          search = false;
    list_iterator search_itr{};

    if (pos == current->begin())
    {
      if (to_enabled != starts_enabled)
      {
        if (pos == current->end())
        {
          hook& trglast     = other->back();
          trglast.has_other = true;
          trglast.other     = oldpos;
        }
        else
        {
          search     = true;
          search_itr = other->begin();
        }
      }
    }
    else
    {
      list_iterator posprev = std::prev(pos);
      if (posprev->has_other)
      {
        if (pos == current->end())
        {
          hook& trglast     = other->back();
          trglast.has_other = true;
          trglast.other     = oldpos;
        }
        else
        {
          search     = true;
          search_itr = posprev->other;
        }
      }
    }

    if (search)
    {
      while (!search_itr->has_other)
        ++search_itr;
      search_itr->other = oldpos;
    }
  }

  void hook_chain::inject_range(list_iterator pos, list_iterator first,
                                list_iterator last)
  {
    const list_iterator lastprev = std::prev(last);

    if (pos == enabled.end())
    {
      std::unique_lock lock{ hook_lock };
      if (enabled.empty())
      {
        __alterhook_def_thumb_var(ptarget);
        first->poriginal = __alterhook_add_thumb_bit(ptrampoline.get());
        *first->origwrap = first->poriginal;
        thread_freezer freeze{ *this, true };
        __alterhook_inject(lastprev->pdetour, true);
      }
      else
      {
        hook& elast      = enabled.back();
        first->poriginal = elast.pdetour;
        *first->origwrap = elast.pdetour;
        __alterhook_patch_jmp(lastprev->pdetour);
      }
    }
    else
    {
      thread_freezer freeze{ nullptr };
      first->poriginal = pos->poriginal;
      *first->origwrap = pos->poriginal;
      pos->poriginal   = lastprev->pdetour;
      *pos->origwrap   = lastprev->pdetour;
    }
  }

  void hook_chain::inject_back(list_iterator first, list_iterator last)
  {
    const list_iterator lastprev = std::prev(last);

    if (first == enabled.begin())
    {
      __alterhook_def_thumb_var(ptarget);
      first->poriginal = __alterhook_add_thumb_bit(ptrampoline.get());
      *first->origwrap = first->poriginal;
    }
    else
    {
      const list_iterator firstprev = std::prev(first);
      first->poriginal              = firstprev->pdetour;
      *first->origwrap              = firstprev->pdetour;
    }

    if (last == enabled.end())
    {
      std::unique_lock lock{ hook_lock };
      if (first == enabled.begin())
      {
        thread_freezer freeze{ *this, true };
        __alterhook_inject(lastprev->pdetour, true);
      }
      else
        __alterhook_patch_jmp(lastprev->pdetour);
    }
    else
    {
      thread_freezer freeze{ nullptr };
      last->poriginal = lastprev->pdetour;
      *last->origwrap = lastprev->pdetour;
    }
  }

  void hook_chain::toggle_status(list_iterator first, list_iterator last)
  {
    auto [current, other] = first->enabled ? std::pair(&enabled, &disabled)
                                           : std::pair(&disabled, &enabled);

    if (first != current->begin())
    {
      list_iterator firstprev = std::prev(first);
      if (!firstprev->has_other)
      {
        firstprev->has_other = true;
        firstprev->other     = first;
      }
    }
    else if (starts_enabled == first->enabled)
      starts_enabled = !starts_enabled;

    list_iterator       firstbind{};
    list_iterator       lastbind{};
    const list_iterator lastprev           = std::prev(last);
    list_iterator       pos                = lastprev;
    list_iterator       previtr            = other->end();
    bool                has_bind           = false;
    const bool          lastprev_has_other = pos->has_other;
    const bool          first_enabled      = first->enabled;

    while (pos != current->end() && !pos->has_other)
      ++pos;
    if (pos != current->end())
      previtr = pos->other;

    do
    {
      list_iterator current_itr = std::prev(last);
      list_iterator target_itr  = previtr;

      if (current_itr->has_other)
      {
        if (current_itr->other != other->begin())
        {
          lastbind            = std::prev(current_itr->other);
          lastbind->has_other = false;
        }
        if (!has_bind)
        {
          has_bind  = true;
          firstbind = current_itr->other;
        }

        target_itr             = current_itr->other;
        current_itr->has_other = false;
      }

      current_itr->enabled = !current_itr->enabled;
      other->splice(target_itr, *current, current_itr);
      previtr = current_itr;
    } while (first->enabled == first_enabled);

    if (!lastprev_has_other)
    {
      if (has_bind)
      {
        while (!firstbind->has_other)
          ++firstbind;
        firstbind->has_other = false;
      }

      if (last != current->end())
      {
        lastprev->has_other = true;
        lastprev->other     = last;
      }
    }

    // if lastbind other points to a not spliced element then we set it back
    // to true
    if (has_bind)
      lastbind->has_other = lastbind->other->enabled != lastbind->enabled;
    else if (first != other->begin())
    {
      // if no bind was found and the previous element of first's current
      // position points to first then we disable has other
      const list_iterator newfirstprev = std::prev(first);
      if (newfirstprev->has_other &&
          newfirstprev->other->enabled == first->enabled)
        newfirstprev->has_other = false;
    }
  }

  void hook_chain::toggle_status(list_iterator position)
  {
    auto [current, other] = position->enabled ? std::pair(&enabled, &disabled)
                                              : std::pair(&disabled, &enabled);

    if (position != current->begin())
    {
      list_iterator posprev = std::prev(position);
      if (!posprev->has_other)
      {
        posprev->has_other = true;
        posprev->other     = position;
      }
    }
    else if (starts_enabled == position->enabled)
      starts_enabled = !starts_enabled;

    const list_iterator posnext    = std::next(position);
    list_iterator       target_itr = position;

    while (target_itr != current->end() && !target_itr->has_other)
      ++target_itr;

    target_itr =
        target_itr != current->end() ? target_itr->other : other->end();

    if (target_itr != other->begin())
    {
      const list_iterator targetprev = std::prev(target_itr);
      if (targetprev->has_other && targetprev->other == position)
        targetprev->has_other = false;
    }

    if (!position->has_other && posnext != current->end())
    {
      position->has_other = true;
      position->other     = posnext;
    }
    else
      position->has_other = false;

    position->enabled = !position->enabled;
    other->splice(target_itr, *current, position);
  }

  void hook_chain::toggle_status_all(include src)
  {
    utils_assert(src != include::both,
                 "hook_chain::toggle_status_all: trg can't be the 'both' flag");

    auto [current, other] = src == include::enabled
                                ? std::pair(&enabled, &disabled)
                                : std::pair(&disabled, &enabled);

    if (!other->empty())
      other->back().has_other = false;

    list_iterator previtr = other->end();
    do
    {
      const list_iterator current_itr = std::prev(current->end());
      list_iterator       target_itr  = previtr;

      if (current_itr->has_other)
      {
        if (current_itr->other != other->begin())
          std::prev(current_itr->other)->has_other = false;

        target_itr             = current_itr->other;
        current_itr->has_other = false;
      }

      current_itr->enabled = !current_itr->enabled;
      if (src == include::disabled)
      {
        current_itr->poriginal = target_itr->poriginal;
        *current_itr->origwrap = target_itr->poriginal;
        target_itr->poriginal  = current_itr->pdetour;
        *target_itr->origwrap  = current_itr->pdetour;
      }
      other->splice(target_itr, *current, current_itr);
      previtr = current_itr;
    } while (!current->empty());

    // switch to true only if moving disabled to enabled, otherwise false
    starts_enabled = src == include::disabled;
  }

  void hook_chain::join_last()
  {
    list_iterator itr = std::prev(enabled.end());
    try
    {
      std::unique_lock lock{ hook_lock };
      if (itr == enabled.begin())
      {
        thread_freezer freeze{ *this, true };
        __alterhook_inject(itr->pdetour, true);
      }
      else
        __alterhook_patch_jmp(itr->pdetour);
    }
    catch (...)
    {
      enabled.pop_back();
      throw;
    }
  }

  void hook_chain::join_first()
  {
    list_iterator itr = enabled.begin();

    try
    {
      if (enabled.size() == 1)
      {
        std::unique_lock lock{ hook_lock };
        thread_freezer   freeze{ *this, true };
        __alterhook_inject(itr->pdetour, true);
      }
      else
      {
        list_iterator  next = std::next(itr);
        thread_freezer freeze{ nullptr };
        next->poriginal = itr->pdetour;
        *next->origwrap = itr->pdetour;
      }
    }
    catch (...)
    {
      enabled.pop_front();
      throw;
    }
  }

  void hook_chain::join(list_iterator itr)
  {
    list_iterator itrnext = std::next(itr);
    try
    {
      if (itrnext == enabled.end())
      {
        std::unique_lock lock{ hook_lock };
        if (enabled.size() == 1)
        {
          thread_freezer freeze{ *this, true };
          __alterhook_inject(itr->pdetour, true);
        }
        else
          __alterhook_patch_jmp(itr->pdetour);
      }
      else
      {
        thread_freezer freeze{ nullptr };
        itrnext->poriginal = itr->pdetour;
        *itrnext->origwrap = itr->pdetour;
      }
    }
    catch (...)
    {
      enabled.erase(itr);
      throw;
    }
  }

  void hook_chain::hook::enable()
  {
    utils_assert(
        pchain->ptarget != pdetour,
        "hook_chain::hook::enable: target & detour have the same address");
    if (enabled)
      return;
    list_iterator newpos = pchain->enabled.end();
    if (!pchain->enabled.empty())
    {
      list_iterator i = current;
      while (!i->has_other && i != pchain->disabled.end())
        ++i;

      if (i != pchain->disabled.end())
        newpos = i->other;
    }

    pchain->inject_range(newpos, current, std::next(current));
    pchain->toggle_status(current);
  }

  void hook_chain::hook::disable()
  {
    if (!enabled)
      return;
    pchain->uninject(current);
    pchain->toggle_status(current);
  }
} // namespace alterhook