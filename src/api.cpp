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

  #define __alterhook_inject_extra_arg , old_protect
  #define __alterhook_inject_base_node_extra_arg , pchain->old_protect
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

  hook_chain::hook_chain(alterhook::hook&& other) : trampoline(std::move(other))
  {
    memcpy(backup.data(), other.backup.data(), backup.size());
    __alterhook_def_thumb_var(ptarget);
    list_iterator itr = disabled.emplace(disabled.end());
    itr->init(*this, itr, __alterhook_get_other_dtr(other),
              __alterhook_add_thumb_bit(ptrampoline.get()),
              other.original_buffer);
  }

  hook_chain::hook_chain(const hook_chain& other) : trampoline(other)
  {
    memcpy(backup.data(), other.backup.data(), backup.size());
    for (const hook& h : other)
    {
      list_iterator itr = disabled.emplace(disabled.end());
      itr->init(*this, itr, h.pdetour, h.poriginal, h.origbuff);
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
      starts_enabled = false;
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
      list_iterator previtr = std::prev(disabled.end());
      hook&         dlast   = *previtr;
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

      thread_freezer freeze{ nullptr };
      while (!disabled.empty())
      {
        list_iterator curritr = std::prev(disabled.end());
        list_iterator trgitr  = previtr;
        hook&         curr    = *curritr;

        if (curr.has_other)
        {
          if (curr.other != enabled.begin())
            std::prev(curr.other)->has_other = false;
          trgitr         = curr.other;
          curr.has_other = false;
        }

        hook& trg      = *trgitr;
        curr.poriginal = trg.poriginal;
        *curr.origwrap = trg.poriginal;
        trg.poriginal  = curr.pdetour;
        *trg.origwrap  = curr.pdetour;
        curr.enabled   = true;
        enabled.splice(trgitr, disabled, curritr);
        previtr = curritr;
      }
    }
  }

  void hook_chain::disable_all()
  {
    if (enabled.empty())
      return;

    {
      std::unique_lock lock{ hook_lock };
      thread_freezer   freeze{ *this, false };
      __alterhook_inject(backup.data(), false);
    }

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
  }

  void hook_chain::pop_back(base trg)
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
    case base::disabled:
      itr   = std::prev(disabled.end());
      to    = &disabled;
      other = &enabled;
      break;
    case base::enabled:
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
    case base::both:
      itr = std::prev(std::array{
          disabled.end(),
          enabled.end() }[disabled.empty() || disabled.back().has_other]);
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

  void hook_chain::pop_front(base trg)
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
    case base::disabled:
      utils_assert(!disabled.empty(),
                   "hook_chain::pop_front: popping from empty disabled chain");
      itr     = disabled.begin();
      itrnext = std::next(itr);
      to      = &disabled;
      other   = &enabled;
      break;
    case base::enabled:
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
    case base::both:
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

  void hook_chain::erase(list_iterator position)
  {
    list_iterator posnext = std::next(position);

    if (position->enabled)
    {
      std::unique_lock lock{ hook_lock };
      if (enabled.size() == 1)
      {
        thread_freezer freeze{ *this, false };
        __alterhook_inject(backup.data(), false);
      }
      else if (posnext == enabled.end())
        __alterhook_patch_jmp(position->poriginal);
      else
      {
        thread_freezer freeze{ nullptr };
        posnext->poriginal = position->poriginal;
        *posnext->origwrap = position->poriginal;
      }
    }

    // unbind
    if ((position->enabled && position == enabled.begin()) ||
        (!position->enabled && position == disabled.begin()))
    {
      if (starts_enabled != position->enabled)
      {
        list_iterator i =
            position->enabled ? disabled.begin() : enabled.begin();
        while (!i->has_other)
          ++i;
        if (position->has_other ||
            (position->enabled && posnext == enabled.end()) ||
            (!position->enabled && posnext == disabled.end()))
          i->has_other = false;
        else
          i->other = posnext;
      }
      else if (position->has_other)
        starts_enabled = !starts_enabled;
    }
    else
    {
      list_iterator i = std::prev(position);
      if (i->has_other)
      {
        i = i->other;
        while (!i->has_other)
          ++i;
        if (position->has_other ||
            (position->enabled && posnext == enabled.end()) ||
            (!position->enabled && posnext == disabled.end()))
          i->has_other = false;
        else
          i->other = posnext;
      }
      else if (position->has_other)
      {
        i->has_other = true;
        i->other     = position->other;
      }
    }

    std::list<hook>& trg = position->enabled ? enabled : disabled;
    trg.erase(position);
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
      lefttrg.splice(leftnext, righttrg, right);
      righttrg.splice(rightnext, lefttrg, left);
      std::swap(left, right);
      *left->origwrap  = left->poriginal;
      *right->origwrap = right->poriginal;
    };
    const auto bind = [&](list_iterator itr, hook_chain& src)
    {
      bool search = false;

      if (itr->enabled)
      {
        if (itr == src.enabled.begin())
        {
          if (!src.starts_enabled)
          {
            list_iterator i = src.disabled.begin();
            while (!i->has_other)
              ++i;
            i->other = itr;
          }
        }
        else
          search = true;
      }
      else
      {
        if (itr == src.disabled.begin())
        {
          if (src.starts_enabled)
          {
            list_iterator i = src.enabled.begin();
            while (!i->has_other)
              ++i;
            i->other = itr;
          }
        }
        else
          search = true;
      }

      if (search)
      {
        list_iterator i = std::prev(itr);
        if (i->has_other)
        {
          i = i->other;
          while (!i->has_other)
            ++i;
          i->other = itr;
        }
      }
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

    bind(left, *this);
    bind(right, other);
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
    list_iterator    disablednewpos{};
    list_iterator    enablednewpos{};
    const auto       handle_enabled = [&]
    {
      hook& otherfront = other.enabled.front();
      hook& otherback  = other.enabled.back();
      if (enablednewpos == enabled.begin())
      {
        __alterhook_def_thumb_var(ptarget);
        otherfront.poriginal = __alterhook_add_thumb_bit(ptrampoline.get());
        *otherfront.origwrap = otherfront.poriginal;
      }
      else
      {
        list_iterator enabledprev = std::prev(enablednewpos);
        otherfront.poriginal      = enabledprev->pdetour;
        *otherfront.origwrap      = enabledprev->pdetour;
      }

      try
      {
        if (enablednewpos == enabled.end())
        {
          std::unique_lock lock{ hook_lock };
          if (enabled.empty())
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
        if (from != transfer::disabled)
        {
          __alterhook_def_thumb_var(other.ptarget);
          otherfront.poriginal =
              __alterhook_add_thumb_bit(other.ptrampoline.get());
          *otherfront.origwrap = otherfront.poriginal;

          try
          {
            std::unique_lock lock{ hook_lock };
            thread_freezer   freeze{ other, true };
            __alterhook_inject_other(other, otherback.pdetour, true);
          }
          catch (...)
          {
            if (!other.disabled.empty())
              other.disabled.back().has_other = false;
            list_iterator previtr = other.disabled.end();
            do
            {
              list_iterator curritr = std::prev(other.enabled.end());
              list_iterator trgitr  = previtr;
              hook&         curr    = *curritr;

              if (curr.has_other)
              {
                if (curr.other != other.disabled.begin())
                  std::prev(curr.other)->has_other = false;
                trgitr         = curr.other;
                curr.has_other = false;
              }

              curr.enabled = false;
              other.disabled.splice(trgitr, other.enabled, curritr);
              previtr = curritr;
            } while (!other.enabled.empty());
            throw;
          }
        }
        throw;
      }
    };

    switch (from)
    {
    case transfer::disabled:
    {
      if (other.disabled.empty())
        return;
      std::list<hook>& src                 = other.disabled;
      bool             should_search       = false;
      bool             get_prev_and_search = false;
      list_iterator    searchbegin{};

      if (to_enabled)
      {
        enablednewpos = newpos;
        handle_enabled();

        if (newpos == enabled.begin())
        {
          if (!starts_enabled)
          {
            should_search = true;
            searchbegin   = disabled.begin();
          }
        }
        else
          get_prev_and_search = true;
      }
      else
      {
        if (newpos == disabled.begin())
        {
          if (starts_enabled)
          {
            should_search = true;
            searchbegin   = enabled.begin();
          }
        }
        else
          get_prev_and_search = true;
      }

      if (get_prev_and_search)
      {
        list_iterator newprev = std::prev(newpos);
        if (newprev->has_other)
        {
          should_search = true;
          searchbegin   = newprev->other;
        }
      }

      if (should_search)
      {
        while (!searchbegin->has_other)
          ++searchbegin;
        searchbegin->other = other.disabled.begin();
      }

      for (hook& h : other.disabled)
      {
        h.has_other = false;
        h.enabled   = to_enabled;
        h.pchain    = this;
      }
      for (hook& h : other.enabled)
        h.has_other = false;

      if (empty())
        starts_enabled = false;
      trg.splice(newpos, src);
      break;
    }
    case transfer::enabled:
    {
      if (other.enabled.empty())
        return;

      {
        std::unique_lock lock{ hook_lock };
        thread_freezer   freeze{ other, false };
        __alterhook_inject_other(other, other.backup.data(), false);
      }

      std::list<hook>& src                 = other.enabled;
      bool             get_prev_and_search = false;
      bool             should_search       = false;
      list_iterator    searchbegin{};

      if (to_enabled)
      {
        enablednewpos = newpos;
        handle_enabled();

        if (newpos == enabled.begin())
        {
          if (!starts_enabled)
          {
            should_search = true;
            searchbegin   = disabled.begin();
          }
        }
        else
          get_prev_and_search = true;
      }
      else
      {
        if (newpos == disabled.begin())
        {
          if (starts_enabled)
          {
            should_search = true;
            searchbegin   = enabled.begin();
          }
        }
        else
          get_prev_and_search = true;
      }

      if (get_prev_and_search)
      {
        list_iterator newprev = std::prev(newpos);
        if (newprev->has_other)
        {
          should_search = true;
          searchbegin   = newprev->other;
        }
      }

      if (should_search)
      {
        while (!searchbegin->has_other)
          ++searchbegin;
        searchbegin->other = other.enabled.begin();
      }

      for (hook& h : other.enabled)
      {
        h.has_other = false;
        h.enabled   = to_enabled;
        h.pchain    = this;
      }
      for (hook& h : other.disabled)
        h.has_other = false;
      if (empty())
        starts_enabled = true;
      trg.splice(newpos, src);
    }
    case transfer::both:
    {
      if ((to_enabled && newpos == enabled.end()) ||
          (!to_enabled && newpos == disabled.end()))
      {
        disablednewpos = disabled.end();
        enablednewpos  = enabled.end();
      }
      else if (to_enabled)
      {
        enablednewpos   = newpos;
        list_iterator i = newpos;

        while (!i->has_other && i != enabled.end())
          ++i;
        if (i == enabled.end())
          disablednewpos = disabled.end();
        else
          disablednewpos = i->other;
      }
      else
      {
        disablednewpos  = newpos;
        list_iterator i = newpos;

        while (!i->has_other && i != disabled.end())
          ++i;
        if (i == disabled.end())
          enablednewpos = enabled.end();
        else
          enablednewpos = i->other;
      }

      if (!other.enabled.empty())
      {
        {
          std::unique_lock lock{ hook_lock };
          thread_freezer   freeze{ other, false };
          __alterhook_inject_other(other, other.backup.data(), false);
        }
        handle_enabled();
      }

      if (!empty())
      {
        iterator first = other.begin();
        hook&    last  = other.back();
        if (!to_enabled && newpos == disabled.begin())
        {
          if (starts_enabled && !first->enabled)
          {
            list_iterator i = enabled.begin();
            while (!i->has_other)
              ++i;
            i->other = first;
          }
          if (last.enabled && newpos != disabled.end())
          {
            last.has_other = true;
            last.other     = newpos;
          }
        }
        else if (to_enabled && newpos == enabled.begin())
        {
          if (!starts_enabled && first->enabled)
          {
            list_iterator i = disabled.begin();
            while (!i->has_other)
              ++i;
            i->other = first;
          }
          if (!last.enabled && newpos != enabled.end())
          {
            last.has_other = true;
            last.other     = newpos;
          }
        }
        else
        {
          list_iterator newprev = std::prev(newpos);
          if (newprev->has_other && first->enabled == newprev->enabled)
          {
            list_iterator i = newprev->other;
            while (!i->has_other)
              ++i;
            i->other = first;
          }

          if (last.enabled != newprev->enabled &&
              (!to_enabled || newpos != enabled.end()) &&
              (to_enabled || newpos != disabled.end()))
          {
            last.has_other = true;
            last.other     = newpos;
          }
        }
      }
      else
        starts_enabled = other.starts_enabled;

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
      break;
    }
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

    // covers transfer from enabled
    if (oldpos->enabled)
    {
      // covers transfer from enabled end
      if (oldnext == other.enabled.end())
      {
        std::unique_lock lock{ hook_lock };
        if (other.enabled.size() == 1)
        {
          thread_freezer freeze{ other, false };
          __alterhook_inject_other(other, other.backup.data(), false);
        }
        else
          __alterhook_patch_other_jmp(other, oldpos->poriginal);
      }
      else
      {
        thread_freezer freeze{ nullptr };
        oldnext->poriginal = oldpos->poriginal;
        *oldnext->origwrap = oldpos->poriginal;
      }
    }

    // transfer to enabled
    if (to_enabled)
    {
      try
      {
        // transfer to enabled end
        if (newpos == enabled.end())
        {
          std::unique_lock lock{ hook_lock };
          if (enabled.empty())
          {
            __alterhook_def_thumb_var(ptarget);
            oldpos->poriginal = __alterhook_add_thumb_bit(ptrampoline.get());
            *oldpos->origwrap = oldpos->poriginal;
            thread_freezer freeze{ *this, true };
            __alterhook_inject(oldpos->pdetour, true);
          }
          else
          {
            hook& elast       = enabled.back();
            oldpos->poriginal = elast.pdetour;
            *oldpos->origwrap = elast.pdetour;
            __alterhook_patch_jmp(oldpos->pdetour);
          }
        }
        else
        {
          thread_freezer freeze{ nullptr };
          oldpos->poriginal  = oldnext->poriginal;
          *oldpos->origwrap  = oldnext->poriginal;
          oldnext->poriginal = oldpos->pdetour;
          *oldnext->origwrap = oldpos->pdetour;
        }
      }
      catch (...)
      {
        // provide strong guarantee
        // so we attempt to rebind the old node back to where it was before
        // exiting
        if (oldpos->enabled)
        {
          try
          {
            if (oldnext == other.enabled.end())
            {
              std::unique_lock lock{ hook_lock };
              if (other.enabled.size() == 1)
              {
                __alterhook_def_thumb_var(other.ptarget);
                oldpos->poriginal =
                    __alterhook_add_thumb_bit(other.ptrampoline.get());
                *oldpos->origwrap = oldpos->poriginal;
                thread_freezer freeze{ other, true };
                __alterhook_inject_other(other, oldpos->pdetour, true);
              }
              else
              {
                hook& elast       = other.enabled.back();
                oldpos->poriginal = elast.pdetour;
                *oldpos->origwrap = elast.pdetour;
                __alterhook_patch_other_jmp(other, oldpos->pdetour);
              }
            }
            else
            {
              thread_freezer freeze{ nullptr };
              oldpos->poriginal  = oldnext->poriginal;
              *oldpos->origwrap  = oldnext->poriginal;
              oldnext->poriginal = oldpos->pdetour;
              *oldnext->origwrap = oldpos->pdetour;
            }
          }
          catch (...)
          {
            if (oldpos != other.enabled.begin())
            {
              auto oldprev = std::prev(oldpos);
              if (!oldprev->has_other)
              {
                oldprev->has_other = true;
                oldprev->other     = oldpos;
              }
              else if (oldnext != other.enabled.end())
              {
                oldprev = oldprev->other;
                while (!oldprev->has_other)
                  ++oldprev;
                oldprev->has_other = false;
              }
              else
              {
                hook& dlast = other.disabled.back();
                if (dlast.has_other && dlast.other == oldpos)
                  dlast.has_other = false;
              }
            }
            else
              other.starts_enabled = false;

            list_iterator target = other.disabled.end();
            if (oldpos->has_other)
            {
              oldpos->has_other = false;
              target            = oldpos->other;
            }

            oldpos->enabled = false;
            other.disabled.splice(target, other.enabled, oldpos);
            throw;
          }
        }
        throw;
      }
    }

    bool          should_search = false;
    bool          extra_check   = false;
    list_iterator oldsearchitr{};

    if (oldpos->enabled && oldpos == other.enabled.begin())
    {
      if (!other.starts_enabled)
      {
        oldsearchitr  = other.disabled.begin();
        should_search = true;
        extra_check   = oldpos->has_other || oldnext == other.enabled.end();
      }
      else if (oldpos->has_other)
        other.starts_enabled = false;
    }
    else if (!oldpos->enabled && oldpos == other.disabled.begin())
    {
      if (other.starts_enabled)
      {
        oldsearchitr  = other.enabled.begin();
        should_search = true;
        extra_check   = oldpos->has_other || oldnext == other.disabled.end();
      }
      else if (oldpos->has_other)
        other.starts_enabled = true;
    }
    else
    {
      auto oldprev = std::prev(oldpos);
      if (oldprev->has_other)
      {
        oldsearchitr  = oldprev->other;
        should_search = true;
        extra_check   = oldpos->has_other ||
                      (oldpos->enabled && oldnext == other.enabled.end()) ||
                      (!oldpos->enabled && oldnext == other.disabled.end());
      }
      else if (oldpos->has_other)
      {
        oldprev->has_other = true;
        oldprev->other     = oldpos->other;
      }
    }

    if (should_search)
    {
      while (!oldsearchitr->has_other)
        ++oldsearchitr;

      if (extra_check)
        oldsearchitr->has_other = false;
      else
        oldsearchitr->other = oldnext;
    }

    list_iterator newsearchitr{};

    enum
    {
      SEARCH,
      HANDLE_ENABLED_END,
      HANDLE_DISABLED_END,
      DO_NOTHING
    } newpos_strategy = DO_NOTHING;

    if (!empty())
    {
      if (to_enabled && newpos == enabled.begin())
      {
        if (!starts_enabled)
        {
          if (newpos == enabled.end())
            newpos_strategy = HANDLE_ENABLED_END;
          else
          {
            newsearchitr    = disabled.begin();
            newpos_strategy = SEARCH;
          }
        }
      }
      else if (!to_enabled && newpos == disabled.begin())
      {
        if (starts_enabled)
        {
          if (newpos == disabled.end())
            newpos_strategy = HANDLE_DISABLED_END;
          else
          {
            newsearchitr    = enabled.begin();
            newpos_strategy = SEARCH;
          }
        }
      }
      else
      {
        auto newprev = std::prev(newpos);
        if (newprev->has_other)
        {
          if (to_enabled && newpos == enabled.end())
            newpos_strategy = HANDLE_ENABLED_END;
          else if (!to_enabled && newpos == disabled.end())
            newpos_strategy = HANDLE_DISABLED_END;
          else
          {
            newsearchitr    = newprev->other;
            newpos_strategy = SEARCH;
          }
        }
      }

      switch (newpos_strategy)
      {
      case SEARCH:
        while (!newsearchitr->has_other)
          ++newsearchitr;
        newsearchitr->other = oldpos;
        break;
      case HANDLE_ENABLED_END:
      {
        hook& dlast     = disabled.back();
        dlast.has_other = true;
        dlast.other     = oldpos;
        break;
      }
      case HANDLE_DISABLED_END:
      {
        hook& elast     = enabled.back();
        elast.has_other = true;
        elast.other     = oldpos;
        break;
      }
      }
    }
    else
      starts_enabled = oldpos->enabled;

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

    // covers transfer from enabled
    if (first->enabled)
    {
      // covers transfer from enabled end
      if (last == other.enabled.end())
      {
        std::unique_lock lock{ hook_lock };
        if (first == other.enabled.begin())
        {
          thread_freezer freeze{ other, false };
          __alterhook_inject_other(other, other.backup.data(), false);
        }
        else
          __alterhook_patch_other_jmp(other, first->poriginal);
      }
      else
      {
        thread_freezer freeze{ nullptr };
        last->poriginal = first->poriginal;
        *last->origwrap = first->poriginal;
      }
    }

    auto lastprev = std::prev(last);

    // covers transfer to enabled
    if (to_enabled)
    {
      try
      {
        // covers transfer to enabled end
        if (newpos == enabled.end())
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
          first->poriginal  = newpos->poriginal;
          *first->origwrap  = newpos->poriginal;
          newpos->poriginal = lastprev->pdetour;
          *newpos->origwrap = lastprev->pdetour;
        }
      }
      catch (...)
      {
        if (first->enabled)
        {
          try
          {
            if (last == other.enabled.end())
            {
              std::unique_lock lock{ hook_lock };
              if (first == other.enabled.begin())
              {
                __alterhook_def_thumb_var(other.ptarget);
                first->poriginal =
                    __alterhook_add_thumb_bit(other.ptrampoline.get());
                *first->origwrap = first->poriginal;
                thread_freezer freeze{ other, true };
                __alterhook_inject_other(other, lastprev->pdetour, true);
              }
              else
              {
                hook& elast      = other.enabled.back();
                first->poriginal = elast.pdetour;
                *first->origwrap = elast.pdetour;
                __alterhook_patch_other_jmp(other, lastprev->pdetour);
              }
            }
            else
            {
              thread_freezer freeze{ nullptr };
              first->poriginal = last->poriginal;
              *first->origwrap = last->poriginal;
              last->poriginal  = lastprev->pdetour;
              *last->origwrap  = lastprev->pdetour;
            }
          }
          catch (...)
          {
            if (first != other.enabled.begin())
            {
              auto firstprev = std::prev(first);
              if (!firstprev->has_other)
              {
                firstprev->has_other = true;
                firstprev->other     = first;
              }
            }
            else
              other.starts_enabled = false;
            list_iterator trg     = lastprev;
            list_iterator previtr = other.disabled.end();
            list_iterator firstbind{};
            bool          has_first_bind     = false;
            bool          lastprev_has_other = lastprev->has_other;

            while (!trg->has_other && trg != other.enabled.end())
              ++trg;
            if (trg != other.enabled.end())
              previtr = trg->other;
            if (!other.disabled.empty())
              other.disabled.back().has_other = false;

            do
            {
              list_iterator curritr = std::prev(last);
              list_iterator trgitr  = previtr;
              hook&         curr    = *curritr;

              if (curr.has_other)
              {
                if (curr.other != other.disabled.begin())
                  std::prev(curr.other)->has_other = false;
                if (!has_first_bind)
                {
                  has_first_bind = true;
                  firstbind      = curr.other;
                }
                trgitr         = curr.other;
                curr.has_other = false;
              }

              curr.enabled = false;
              other.disabled.splice(trgitr, other.enabled, curritr);
              previtr = curritr;
            } while (first->enabled);

            if (has_first_bind && !lastprev_has_other)
            {
              while (!firstbind->has_other)
                ++firstbind;
              firstbind->has_other = false;
            }
            throw;
          }
        }
        throw;
      }
    }

    if (!empty())
    {
      list_iterator newsearchitr{};

      enum
      {
        SEARCH,
        HANDLE_ENABLED_END,
        HANDLE_DISABLED_END,
        DO_NOTHING
      } newpos_strategy = DO_NOTHING;

      if (!to_enabled && newpos == disabled.begin())
      {
        if (starts_enabled)
        {
          if (newpos == disabled.end())
            newpos_strategy = HANDLE_DISABLED_END;
          else
          {
            newsearchitr    = enabled.begin();
            newpos_strategy = SEARCH;
          }
        }
      }
      else if (to_enabled && newpos == enabled.begin())
      {
        if (!starts_enabled)
        {
          if (newpos == enabled.end())
            newpos_strategy = HANDLE_ENABLED_END;
          else
          {
            newsearchitr    = disabled.begin();
            newpos_strategy = SEARCH;
          }
        }
      }
      else
      {
        auto newprev = std::prev(newpos);
        if (newprev->has_other)
        {
          if (!to_enabled && newpos == disabled.end())
            newpos_strategy = HANDLE_DISABLED_END;
          else if (to_enabled && newpos == enabled.end())
            newpos_strategy = HANDLE_ENABLED_END;
          else
          {
            newsearchitr    = newprev->other;
            newpos_strategy = SEARCH;
          }
        }
      }

      switch (newpos_strategy)
      {
      case SEARCH:
        while (!newsearchitr->has_other)
          ++newsearchitr;
        newsearchitr->other = first;
        break;
      case HANDLE_DISABLED_END:
      {
        hook& elast     = enabled.back();
        elast.has_other = true;
        elast.other     = first;
        break;
      }
      case HANDLE_ENABLED_END:
      {
        hook& dlast     = disabled.back();
        dlast.has_other = true;
        dlast.other     = first;
        break;
      }
      }
    }
    else
      starts_enabled = to_enabled;

    list_iterator searchbegin        = first;
    list_iterator searchend          = std::prev(last);
    list_iterator begin_uncovered    = first;
    list_iterator currnewpos         = newpos;
    bool          has_search_end     = false;
    bool          has_search_begin   = false;
    const bool    lastprev_has_other = lastprev->has_other;
    const bool    from_enabled       = first->enabled;

    // backwards search for last link
    while (!searchend->has_other && searchend != searchbegin)
    {
      searchend->enabled = to_enabled;
      searchend->pchain  = this;
      trg.splice(currnewpos, src, searchend);
      currnewpos = searchend;
      searchend  = std::prev(last);
    }

    if (searchend->has_other)
    {
      has_search_end = true;
      searchend      = searchend->other;
      while (!searchend->has_other)
        ++searchend;
    }

    if (!first->enabled && first == other.disabled.begin())
    {
      if (starts_enabled)
      {
        searchbegin      = other.enabled.begin();
        has_search_begin = true;
      }
      else if (has_search_end)
        other.starts_enabled = true;
    }
    else if (first->enabled && first == other.enabled.begin())
    {
      if (!starts_enabled)
      {
        searchbegin      = other.disabled.begin();
        has_search_begin = true;
      }
      else if (has_search_end)
        other.starts_enabled = false;
    }
    else
    {
      auto firstprev = std::prev(first);
      if (firstprev->has_other)
      {
        searchbegin      = firstprev->other;
        has_search_begin = true;
      }
      else if (has_search_end)
      {
        while (!searchbegin->has_other)
        {
          list_iterator next   = std::next(searchbegin);
          searchbegin->enabled = to_enabled;
          searchbegin->pchain  = this;
          trg.splice(currnewpos, src, searchbegin);
          searchbegin = next;
        }

        begin_uncovered      = searchbegin;
        searchbegin          = searchbegin->other;
        has_search_begin     = true;
        firstprev->has_other = true;
        firstprev->other     = searchbegin;
      }
    }

    if (has_search_end)
    {
      if (!has_search_begin)
      {
        while (!searchbegin->has_other)
        {
          list_iterator next   = std::next(searchbegin);
          searchbegin->enabled = to_enabled;
          searchbegin->pchain  = this;
          trg.splice(currnewpos, src, searchbegin);
          searchbegin = next;
        }
        begin_uncovered = searchbegin;
        searchbegin     = searchbegin->other;
      }

      while (searchbegin != searchend)
      {
        searchbegin->has_other = false;
        ++searchbegin;
      }

      if (lastprev_has_other || (from_enabled && last == other.enabled.end()) ||
          (!from_enabled && last == other.disabled.end()))
        searchbegin->has_other = false;
      else
        searchbegin->other = last;
    }
    else if (has_search_begin)
    {
      while (!searchbegin->has_other)
        ++searchbegin;
      searchbegin->other = last;
    }

    while (begin_uncovered != last)
    {
      list_iterator next       = std::next(begin_uncovered);
      begin_uncovered->enabled = to_enabled;
      begin_uncovered->pchain  = this;
      trg.splice(currnewpos, src, begin_uncovered);
      begin_uncovered = next;
    }
  }

  void hook_chain::splice(list_iterator newpos, hook_chain& other,
                          iterator first, iterator last, transfer to)
  {
    if (first == last)
      return;
    if (std::next(first) == last)
      return splice(newpos, other, first, to);
    const bool    to_enabled = to == transfer::enabled;
    const bool    is_empty   = empty();
    list_iterator disablednewpos{};
    list_iterator enablednewpos{};

    list_iterator disabledoldtrgpos{};
    list_iterator enabledoldtrgpos{};

    if (&other == this && last.enabled == to_enabled && newpos == last)
      return;
    if ((to_enabled && newpos == enabled.end()) ||
        (!to_enabled && newpos == disabled.end()))
    {
      disablednewpos = disabled.end();
      enablednewpos  = enabled.end();
    }
    else if (to_enabled)
    {
      enablednewpos   = newpos;
      list_iterator i = newpos;

      while (!i->has_other && i != enabled.end())
        ++i;
      if (i == enabled.end())
        disablednewpos = disabled.end();
      else
        disablednewpos = i->other;
    }
    else
    {
      disablednewpos  = newpos;
      list_iterator i = newpos;

      while (!i->has_other && i != disabled.end())
        ++i;
      if (i == disabled.end())
        enablednewpos = enabled.end();
      else
        enablednewpos = i->other;
    }

    list_iterator first_enabled = first;
    list_iterator last_enabled  = last;
    list_iterator lastprev{};
    bool          has_enabled = false;

    // search for first enabled
    if (!first.enabled)
    {
      if (!last.enabled)
      {
        disabledoldtrgpos = last;
        for (auto next = list_iterator();
             !first_enabled->has_other && first_enabled != last_enabled;
             first_enabled = next)
        {
          next                  = std::next(first_enabled);
          first_enabled->pchain = this;
          disabled.splice(disablednewpos, other.disabled, first_enabled);
        }

        if (first_enabled != last_enabled)
        {
          disabledoldtrgpos     = std::next(first_enabled);
          first_enabled->pchain = this;
          disabled.splice(disablednewpos, other.disabled, first_enabled);
          first_enabled = first_enabled->other;
          has_enabled   = true;
        }
      }
      else
      {
        for (auto next     = list_iterator(); !first_enabled->has_other;
             first_enabled = next)
        {
          next                  = std::next(first_enabled);
          first_enabled->pchain = this;
          disabled.splice(disablednewpos, other.disabled, first_enabled);
        }

        disabledoldtrgpos     = std::next(first_enabled);
        first_enabled->pchain = this;
        disabled.splice(disablednewpos, other.disabled, first_enabled);
        first_enabled = first_enabled->other;
        if (first_enabled != last)
          has_enabled = true;
      }
    }
    else
      has_enabled = true;

    if (has_enabled)
    {
      // transfer everything (and keep track of last_enabled)
      for (auto i       = iterator(list_iterator(), first_enabled, true),
                next    = iterator();
           i != last; i = next)
      {
        next      = std::next(i);
        i->pchain = this;
        lastprev  = i;
        if (i.enabled)
        {
          enabledoldtrgpos = std::next(static_cast<list_iterator>(i));
          enabled.splice(enablednewpos, other.enabled, i);
          last_enabled = lastprev;
        }
        else
        {
          disabledoldtrgpos = std::next(static_cast<list_iterator>(i));
          disabled.splice(disablednewpos, other.disabled, i);
        }
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
        for (auto itr    = iterator(first, first, first.enabled),
                  itrend = iterator(lastprev, lastprev, lastprev->enabled),
                  next   = iterator();
             itr != itrend; itr = next)
        {
          next        = std::next(itr);
          itr->pchain = &other;
          if (itr.enabled)
            other.enabled.splice(enabledoldtrgpos, enabled, itr);
          else
            other.disabled.splice(disabledoldtrgpos, disabled, itr);
        }
        lastprev->pchain = &other;
        if (lastprev->enabled)
          other.enabled.splice(enabledoldtrgpos, enabled, lastprev);
        else
          other.disabled.splice(disabledoldtrgpos, disabled, lastprev);
        throw;
      }

      hook&            otherfront   = *first_enabled;
      hook&            otherback    = *last_enabled;
      // backup in case of failure
      const std::byte* oldporiginal = otherfront.poriginal;
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
          if (enabled.empty())
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
        otherfront.poriginal = oldporiginal;
        *otherfront.origwrap = oldporiginal;

        for (auto itr    = iterator(first, first, first.enabled),
                  itrend = iterator(lastprev, lastprev, lastprev->enabled),
                  next   = iterator();
             itr != itrend; itr = next)
        {
          next        = std::next(itr);
          itr->pchain = &other;
          if (itr.enabled)
            other.enabled.splice(enabledoldtrgpos, enabled, itr);
          else
            other.disabled.splice(disabledoldtrgpos, disabled, itr);
        }
        lastprev->pchain = &other;
        if (lastprev->enabled)
          other.enabled.splice(enabledoldtrgpos, enabled, lastprev);
        else
          other.disabled.splice(disabledoldtrgpos, disabled, lastprev);

        try
        {
          if (enabledoldtrgpos == other.enabled.end())
          {
            std::unique_lock lock{ hook_lock };
            if (other.enabled.empty())
            {
              thread_freezer freeze{ other, true };
              __alterhook_inject_other(other, last_enabled->pdetour, true);
            }
            else
              __alterhook_patch_other_jmp(other, last_enabled->pdetour);
          }
          else
          {
            thread_freezer freeze{ nullptr };
            enabledoldtrgpos->poriginal = last_enabled->pdetour;
            *enabledoldtrgpos->origwrap = last_enabled->pdetour;
          }
        }
        catch (...)
        {
          if (first.enabled)
          {
            if (static_cast<list_iterator>(first) != other.enabled.begin())
            {
              auto firstprev = std::prev(first_enabled);
              if (!firstprev->has_other)
              {
                firstprev->has_other = true;
                firstprev->other     = first_enabled;
              }
            }
            else
              other.starts_enabled = false;
          }

          list_iterator trg               = last_enabled;
          list_iterator previtr           = other.disabled.end();
          list_iterator last_enabled_next = std::next(last_enabled);
          list_iterator firstbind{};
          bool          has_first_bind         = false;
          bool          last_enabled_has_other = last_enabled->has_other;

          while (!trg->has_other && trg != other.enabled.end())
            ++trg;
          if (trg != other.enabled.end())
            previtr = trg->other;

          do
          {
            auto  curritr = std::prev(last_enabled_next);
            auto  trgitr  = previtr;
            hook& curr    = *curritr;

            if (curr.has_other)
            {
              if (curr.other != other.disabled.begin())
                std::prev(curr.other)->has_other = false;
              if (!has_first_bind)
              {
                has_first_bind = true;
                firstbind      = curr.other;
              }
              trgitr         = curr.other;
              curr.has_other = false;
            }

            curr.enabled = false;
            other.disabled.splice(trgitr, other.enabled, curritr);
            previtr = curritr;
          } while (first_enabled->enabled);

          if (has_first_bind && !last_enabled_has_other)
          {
            while (!firstbind->has_other)
              ++firstbind;
            firstbind->has_other = false;
          }
          throw;
        }
        throw;
      }
    }
    else
    {
      for (list_iterator itr = first, next = list_iterator();
           itr != disabledoldtrgpos; itr = next)
      {
        next        = std::next(itr);
        itr->pchain = this;
        disabled.splice(disablednewpos, other.disabled, itr);
      }
    }

    if (!is_empty)
    {
      // bind first to new position
      if (!to_enabled && newpos == disabled.begin())
      {
        if (starts_enabled && !first.enabled)
        {
          list_iterator i = enabled.begin();
          while (!i->has_other)
            ++i;
          i->other = first;
        }
      }
      else if (to_enabled && newpos == enabled.begin())
      {
        if (!starts_enabled && first->enabled)
        {
          list_iterator i = disabled.begin();
          while (!i->has_other)
            ++i;
          i->other = first;
        }
      }
      else
      {
        list_iterator newprev = std::prev(newpos);
        if (newprev->has_other && first->enabled == newprev->enabled)
        {
          list_iterator i = newprev->other;
          while (!i->has_other)
            ++i;
          i->other = first;
        }
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
    if (to_enabled != lastprev->enabled &&
        (!to_enabled || newpos != enabled.end()) &&
        (to_enabled || newpos != disabled.end()))
    {
      lastprev->has_other = true;
      lastprev->other     = newpos;
    }
  }

#if utils_clang
  #pragma clang diagnostic pop
#endif

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
    list_iterator target{};
    // re-setup if empty
    if (pchain->enabled.empty())
    {
      {
        __alterhook_def_thumb_var(pchain->ptarget);
        poriginal = __alterhook_add_thumb_bit(pchain->ptrampoline.get());
        *origwrap = poriginal;
        std::unique_lock lock{ hook_lock };
        thread_freezer   freeze{ *pchain, true };

        __alterhook_inject_base_node(pdetour, true);
      }
      other     = std::next(current);
      has_other = other != pchain->disabled.end();
      target    = pchain->enabled.end();
    }
    else
    {
      list_iterator new_other{};
      bool          new_has_other = false;
      // put next as other to current and search for other to splice to
      // otherwise remove other
      if (!has_other)
      {
        list_iterator result = std::next(current);
        new_other            = result;
        new_has_other        = result != pchain->disabled.end();
        while (result != pchain->disabled.end() && !result->has_other)
          ++result;
        target = result == pchain->disabled.end() ? pchain->enabled.end()
                                                  : result->other;
      }
      else
        target = other;

      if (target == pchain->enabled.end())
      {
        poriginal = pchain->enabled.back().pdetour;
        *origwrap = poriginal;
        std::unique_lock lock{ hook_lock };
        __alterhook_patch_base_node_jmp(pdetour);
      }
      else
      {
        thread_freezer freeze{ nullptr };
        poriginal         = target->poriginal;
        *origwrap         = target->poriginal;
        target->poriginal = pdetour;
        *target->origwrap = pdetour;
      }
      other     = new_other;
      has_other = new_has_other;
    }

    // put current as other on prev if needed
    if (current != pchain->disabled.begin())
    {
      list_iterator prev = std::prev(current);
      if (!prev->has_other)
      {
        prev->has_other = true;
        prev->other     = current;
      }
    }
    else
      pchain->starts_enabled = true;

    // remove other on new prev if needed
    if (target != pchain->enabled.begin())
    {
      list_iterator prev = std::prev(target);
      if (prev->has_other && prev->other == current)
        prev->has_other = false;
    }
    enabled = true;
    pchain->enabled.splice(target, pchain->disabled, current);
  }

  void hook_chain::hook::disable()
  {
    if (!enabled)
      return;
    list_iterator target{};
    list_iterator new_other{};
    bool          new_has_other = false;
    if (pchain->disabled.empty())
    {
      new_other     = std::next(current);
      new_has_other = new_other != pchain->enabled.end();
      target        = pchain->disabled.end();
    }
    else if (!has_other)
    {
      list_iterator result = std::next(current);
      new_other            = result;
      new_has_other        = new_other != pchain->enabled.end();
      while (result != pchain->enabled.end() && !result->has_other)
        ++result;
      target = result == pchain->enabled.end() ? pchain->disabled.end()
                                               : result->other;
    }
    else
      target = other;

    // if enabled list is going to be left empty, we are disabling setup
    if (pchain->enabled.size() == 1)
    {
      std::unique_lock lock{ hook_lock };
      thread_freezer   freeze{ *pchain, false };
      __alterhook_inject_base_node(pchain->backup.data(), false);
    }
    else
    {
      list_iterator next = std::next(current);
      if (next == pchain->enabled.end())
      {
        std::unique_lock lock{ hook_lock };
        __alterhook_patch_base_node_jmp(poriginal);
      }
      else
      {
        thread_freezer freeze{ nullptr };
        next->poriginal = poriginal;
        *next->origwrap = poriginal;
      }
    }

    if (current != pchain->enabled.begin())
    {
      list_iterator prev = std::prev(current);
      if (!prev->has_other)
      {
        prev->has_other = true;
        prev->other     = current;
      }
    }
    else
      pchain->starts_enabled = false;

    if (target != pchain->disabled.begin())
    {
      list_iterator prev = std::prev(target);
      if (prev->has_other && prev->other == current)
        prev->has_other = false;
    }
    other     = new_other;
    has_other = new_has_other;
    enabled   = false;
    pchain->disabled.splice(target, pchain->enabled, current);
  }
} // namespace alterhook