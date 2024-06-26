/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#include <pch.h>
#include "hook_chain.h"
#include "injection.h"
#include "exceptions.h"
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnon-virtual-dtor"
#pragma clang diagnostic ignored "-Wshadow"
#pragma clang diagnostic ignored "-Wstring-conversion"
#pragma clang diagnostic ignored "-Wcomma"

namespace alterhook
{
  hook_chain::hook_chain(alterhook::hook&& other) : trampoline(std::move(other))
  {
    utils_assert(other.original_wrap,
                 "hook_chain::hook_chain: can't initialize hook chain with a "
                 "hook that doesn't hold a reference to the original");
    memcpy(backup.data(), other.backup.data(), backup.size());
    hook_list& target_list = other.enabled ? enabled : disabled;

    target_list.emplace_back(
        *this, other.pdetour, other.original_buffer,
        helpers::resolve_original(ptarget, ptrampoline.get()), other.enabled);
    target_list.begin()->current = target_list.begin();
    starts_enabled               = other.enabled;
  }

  hook_chain::hook_chain(const hook_chain& other) : trampoline(other)
  {
    memcpy(backup.data(), other.backup.data(), backup.size());
    for (const hook& h : other)
    {
      list_iterator itr =
          disabled.emplace(disabled.end(), *this, h.pdetour, h.origbuff);
      itr->current = itr;
    }
  }

  hook_chain::hook_chain(hook_chain&& other) noexcept
      : trampoline(std::move(other)), disabled(std::move(other.disabled)),
        enabled(std::move(other.enabled)), starts_enabled(other.starts_enabled)
  {
    memcpy(backup.data(), other.backup.data(), backup.size());
    for (hook& h : *this)
      h.chain = *this;
  }

#if utils_msvc
  #pragma warning(push)
  #pragma warning(disable : 4297)
#endif

  hook_chain::~hook_chain() noexcept { clear(); }

#if utils_msvc
  #pragma warning(pop)
#endif

  hook_chain& hook_chain::operator=(const hook_chain& other)
  {
    if (this == &other)
      return *this;
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
        auto itr = disabled.emplace(disabled.end(), *this, otheritr->pdetour,
                                    otheritr->origbuff);
        itr->current = itr;
      }
    }
    return *this;
  }

  hook_chain& hook_chain::operator=(hook_chain&& other) noexcept
  {
    if (this == &other)
      return *this;
    if (!enabled.empty())
    {
      std::unique_lock lock{ hook_lock };
      thread_freezer   freeze{ *this, false };
      inject(backup.data(), false);
    }
    trampoline::operator=(std::move(other));
    disabled       = std::move(other.disabled);
    enabled        = std::move(other.enabled);
    starts_enabled = other.starts_enabled;

    for (hook& h : *this)
      h.chain = *this;
    return *this;
  }

  hook_chain& hook_chain::operator=(const trampoline& other)
  {
    if (this != &other)
      return *this;
    uninject_all();

    try
    {
      trampoline::operator=(other);
      inject_back(enabled.begin(), enabled.end());
      helpers::make_backup(ptarget, backup.data(), patch_above);
      if (!enabled.empty())
      {
        std::unique_lock lock{ hook_lock };
        thread_freezer   freeze{ *this, true };
        inject(enabled.back().pdetour, true);
      }
    }
    catch (...)
    {
      toggle_status_all(include::enabled);
      throw;
    }
    return *this;
  }

  hook_chain& hook_chain::operator=(trampoline&& other)
  {
    if (this == &other)
      return *this;
    if (!enabled.empty())
    {
      std::unique_lock lock{ hook_lock };
      thread_freezer   freeze{ *this, false };
      inject(backup.data(), false);
    }

    trampoline::operator=(std::move(other));
    helpers::make_backup(ptarget, backup.data(), patch_above);

    if (enabled.empty())
      return *this;
    try
    {
      std::unique_lock lock{ hook_lock };
      thread_freezer   freeze{ *this, false };
      inject(enabled.back().pdetour, true);
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
      inject(backup.data(), false);
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
      rbegin->redirect_originalref(
          helpers::resolve_original(ptarget, ptrampoline.get()));
      thread_freezer freeze{ *this, true };
      {
        std::unique_lock lock{ hook_lock };
        inject(rbegin->pdetour, true);
      }
      rbegin->enabled = true;

      for (auto prev = rbegin, itr = std::next(rbegin),
                enditr = disabled.rend();
           itr != enditr; ++itr, ++prev)
      {
        itr->enabled = true;
        itr->redirect_originalref(prev->poriginal);
        prev->redirect_originalref(itr->pdetour);
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
        dlast.enabled   = true;
        elast.has_other = false;
        dlast.redirect_originalref(elast.pdetour);

        {
          std::unique_lock lock{ hook_lock };
          patch(dlast.pdetour);
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
    list_iterator itr{};
    hook_list*    to       = nullptr;
    hook_list*    other    = nullptr;
    const auto    uninject = [&]
    {
      std::unique_lock lock{ hook_lock };
      thread_freezer   freeze{ *this, false };
      inject(backup.data(), false);
    };

    switch (trg)
    {
    case include::disabled:
      utils_assert(!disabled.empty(),
                   "hook_chain::pop_back: popping from an empty disabled list");
      itr   = std::prev(disabled.end());
      to    = &disabled;
      other = &enabled;
      break;
    case include::enabled:
      utils_assert(!enabled.empty(),
                   "hook_chain::pop_back: popping from an empty enabled list");
      itr   = std::prev(enabled.end());
      to    = &enabled;
      other = &disabled;

      if (enabled.size() == 1)
        uninject();
      else
      {
        std::unique_lock lock{ hook_lock };
        patch(itr->poriginal);
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
          patch(itr->poriginal);
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
    list_iterator itr{};
    list_iterator itrnext{};
    hook_list*    to                     = nullptr;
    hook_list*    other                  = nullptr;
    auto          uninject_first_enabled = [&]
    {
      if (itrnext == enabled.end())
      {
        std::unique_lock lock{ hook_lock };
        thread_freezer   freeze{ *this, false };
        inject(backup.data(), false);
      }
      else
      {
        thread_freezer freeze{ nullptr };
        itrnext->redirect_originalref(itr->poriginal);
      }
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
      to      = &enabled;
      other   = &disabled;
      uninject_first_enabled();
      break;
    case include::both:
      itr     = starts_enabled ? enabled.begin() : disabled.begin();
      itrnext = std::next(itr);
      if (itr->enabled)
        uninject_first_enabled();
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

    hook_list& trg = position->enabled ? enabled : disabled;
    return trg.erase(position);
  }

  hook_chain::list_iterator hook_chain::erase(list_iterator first,
                                              list_iterator last)
  {
    if (first == last)
      return last;
    hook_list& trg = first->enabled ? enabled : disabled;

    if (first->enabled)
      uninject_range(first, last);

    struct erase_callback : unbind_range_callback
    {
      hook_list& trg;

      erase_callback(hook_list& trg) : trg(trg) {}

      void operator()(list_iterator itr, bool) override { trg.erase(itr); }
    } callback{ trg };

    unbind_range(first, last, callback);
    return last;
  }

  hook_chain::iterator hook_chain::erase(iterator first, iterator last)
  {
    list_iterator       firstprev{};
    list_iterator       search_itr{};
    list_iterator       range_begin   = first;
    const list_iterator range_end     = last;
    list_iterator       first_enabled = range_begin;
    list_iterator       last_enabled  = range_end;
    bool                has_enabled   = false;
    bool                has_firstprev = false;
    bool                search        = false;

    auto [first_current, first_other] = first.enabled
                                            ? std::tie(enabled, disabled)
                                            : std::tie(disabled, enabled);
    hook_list& last_current           = last.enabled ? enabled : disabled;

    // find firstprev
    if (range_begin == first_current.begin())
    {
      if (first.enabled != starts_enabled)
      {
        search     = true;
        search_itr = first_other.begin();
      }
    }
    else
    {
      has_firstprev = true;
      firstprev     = std::prev(range_begin);
      if (firstprev->has_other)
      {
        search     = true;
        search_itr = firstprev->other;
      }
    }

    if (search)
    {
      has_firstprev = true;
      while (!search_itr->has_other)
        ++search_itr;
      firstprev = search_itr;
    }

    // find first_enabled
    if (!first.enabled)
    {
      if (!last.enabled)
      {
        while (range_begin != range_end && !range_begin->has_other)
          range_begin = disabled.erase(range_begin);

        if (range_begin != range_end)
        {
          has_enabled   = true;
          first_enabled = range_begin->other;
          disabled.erase(range_begin);
        }
      }
      else
      {
        while (!range_begin->has_other)
          range_begin = disabled.erase(range_begin);

        first_enabled = range_begin->other;
        disabled.erase(first_enabled);
        if (first_enabled != range_end)
          has_enabled = true;
      }
    }
    else
      has_enabled = true;

    if (has_enabled)
    {
      // erase all except enabled ones for safety reasons
      for (auto itr = iterator(list_iterator(), first_enabled, true);
           itr != last;)
      {
        if (itr.enabled)
          last_enabled = itr++;
        else
        {
          iterator next = std::next(itr);
          disabled.erase(itr);
          itr = next;
        }
      }

      const list_iterator end_enabled = std::next(last_enabled);

      // only after uninjecting successfully it is safe to erase the enabled
      // hooks
      try
      {
        uninject_range(first_enabled, end_enabled);
      }
      catch (...)
      {
        for (list_iterator itr = first_enabled; itr != end_enabled; ++itr)
          itr->has_other = false;

        if (has_firstprev)
        {
          firstprev->has_other = false;
          if (!firstprev->enabled)
          {
            firstprev->has_other = true;
            firstprev->other     = first_enabled;
          }
        }
        else
          starts_enabled = true;

        if (range_end != last_current.end() && !range_end->enabled)
        {
          last_enabled->has_other = true;
          last_enabled->other     = range_end;
        }
        throw;
      }

      enabled.erase(first_enabled, end_enabled);
    }
    else
    {
      if (last.enabled)
      {
        list_iterator itr = first;
        while (!itr->has_other)
          itr = disabled.erase(itr);
      }
      else
        disabled.erase(first, last);
    }

    if (has_firstprev)
    {
      firstprev->has_other = false;
      if (range_end != last_current.end() &&
          range_end->enabled != firstprev->enabled)
      {
        firstprev->has_other = true;
        firstprev->other     = range_end;
      }
    }
    else
      starts_enabled = last.enabled;

    return last;
  }

  void hook_chain::swap(list_iterator left, hook_chain& other,
                        list_iterator right)
  {
    utils_assert(&left->chain.get() == this,
                 "hook_chain::swap: the left iterator passed is outside the "
                 "range of `this` object");
    utils_assert(&right->chain.get() == &other,
                 "hook_chain::swap: the right iterator passed is outside the "
                 "range of `other` object");
    if (&other == this && left->enabled == right->enabled && left == right)
      return;
    hook_list&    lefttrg   = left->enabled ? enabled : disabled;
    hook_list&    righttrg  = right->enabled ? other.enabled : other.disabled;
    list_iterator leftnext  = std::next(left);
    list_iterator rightnext = std::next(right);

    if (left->enabled || right->enabled)
    {
#if !utils_64bit
      bool injected_first = false;
#endif
      std::unique_lock lock{ hook_lock };
      thread_freezer   freeze{ nullptr };
      right->swap(*left);
      lefttrg.splice(leftnext, righttrg, right);
      righttrg.splice(rightnext, lefttrg, left);
      std::swap(left, right);

#if !utils_64bit
      try
#endif
      {
        if (left->enabled)
        {
          if (leftnext == enabled.end())
            patch(left->pdetour);
          else if (leftnext != left)
            leftnext->redirect_originalref(left->pdetour);
#if !utils_64bit
          injected_first = true;
#endif
        }

        if (right->enabled)
        {
          if (rightnext == other.enabled.end())
            patch(other, right->pdetour);
          else if (rightnext != right)
            rightnext->redirect_originalref(right->pdetour);
        }
      }
#if !utils_64bit
      catch (...)
      {
        right->swap(*left);
        lefttrg.splice(leftnext, righttrg, right);
        righttrg.splice(rightnext, lefttrg, left);
        std::swap(left, right);

        if (injected_first)
        {
          // if that throws, no guarantee is provided
          if (leftnext == other.enabled.end())
            patch(left->pdetour);
          else
            leftnext->redirect_originalref(left->pdetour);
        }
        throw;
      }
#endif
    }

    bind(left, left, left->enabled);
    other.bind(right, right, right->enabled);
  }

  void hook_chain::swap(hook_chain& other)
  {
    if (this == &other)
      return;
    utils_assert(
        other.ptarget != ptarget,
        "hook_chain::swap: other can't share the same target as *this");

    {
#if !utils_64bit
      bool injected_first_range = false;
#endif

      std::unique_lock lock{ hook_lock };
      thread_freezer   freeze{ nullptr };
      if (!other.enabled.empty())
      {
        patch(other.enabled.back().pdetour);
        hook& hfront = other.enabled.front();
        hfront.redirect_originalref(
            helpers::resolve_original(ptarget, ptrampoline.get()));
#if !utils_64bit
        injected_first_range = true;
#endif
      }

      if (!enabled.empty())
      {
        // patch is noexcept on x64 so no need to try-catch
#if !utils_64bit
        if (injected_first_range)
        {
          try
          {
            patch(other, enabled.back().pdetour);
            hook& hfront = enabled.front();
            hfront.redirect_originalref(helpers::resolve_original(
                other.ptarget, other.ptrampoline.get()));
          }
          catch (...)
          {
            // if that throws no guarantee is provided
            patch(enabled.back().pdetour);
            throw;
          }
        }
        else
#endif
        {
          patch(other, enabled.back().pdetour);
          hook& hfront = enabled.front();
          hfront.redirect_originalref(helpers::resolve_original(
              other.ptarget, other.ptrampoline.get()));
        }
      }
    }

    enabled.swap(other.enabled);
    disabled.swap(other.disabled);
    std::swap(starts_enabled, other.starts_enabled);

    for (hook& h : *this)
      h.chain = *this;
    for (hook& h : other)
      h.chain = other;
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
                 "hook_chain::splice: `to` must not be `transfer::both`");
    if (other.empty())
      return;
    bool       to_enabled = to == transfer::enabled;
    hook_list& trg        = to_enabled ? enabled : disabled;

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
        next     = std::next(i);
        i->chain = *this;
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
        h.chain     = *this;
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
                 "hook_chain::splice: `to` must not be `transfer::both`");
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

    hook_list& trg    = to_enabled ? enabled : disabled;
    hook_list& src    = oldpos->enabled ? other.enabled : other.disabled;
    oldpos->has_other = false;
    oldpos->enabled   = to_enabled;
    oldpos->chain     = *this;

    trg.splice(newpos, src, oldpos);
  }

  void hook_chain::splice(list_iterator newpos, hook_chain& other,
                          list_iterator first, list_iterator last, transfer to)
  {
    utils_assert(to != transfer::both,
                 "hook_chain::splice: `to` must not be `transfer::both`");
    if (first == last)
      return;
    if (std::next(first) == last)
      return splice(newpos, other, first, to);
    const bool to_enabled = to == transfer::enabled;
    hook_list& trg        = to_enabled ? enabled : disabled;
    hook_list& src        = first->enabled ? other.enabled : other.disabled;

    if (&trg == &src && newpos == last)
      return;
    // on transfer from disabled to enabled we make sure the pieces are bound
    // together
    if (to_enabled && !first->enabled)
    {
      for (auto prev = first, current = std::next(first); current != last;
           ++prev, ++current)
        current->redirect_originalref(prev->pdetour);
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

    struct splice_callback : unbind_range_callback
    {
      hook_chain*   current;
      const bool    to_enabled;
      hook_list&    trg;
      hook_list&    src;
      list_iterator newpos;

      splice_callback(hook_chain* current, bool to_enabled, hook_list& trg,
                      hook_list& src, list_iterator newpos)
          : current(current), to_enabled(to_enabled), trg(trg), src(src),
            newpos(newpos)
      {
      }

      void operator()(list_iterator itr, bool forward) override
      {
        set_has_other(itr, false);
        set_enabled(itr, to_enabled);
        set_pchain(itr, current);
        trg.splice(newpos, src, itr);
        if (!forward)
          newpos = itr;
      }
    } callback{ this, to_enabled, trg, src, newpos };

    bind(newpos, first, to_enabled);
    other.unbind_range(first, last, callback);
  }

  void hook_chain::splice(list_iterator newpos, hook_chain& other,
                          iterator first, iterator last, transfer to)
  {
    utils_assert(to != transfer::both,
                 "hook_chain::splice: to can't be the both flag");
    if (first == last)
      return;

    const bool to_enabled = to == transfer::enabled;
    const bool is_empty   = empty();

    list_iterator disablednewpos    = newpos;
    list_iterator enablednewpos     = newpos;
    list_iterator disabledoldtrgpos = last;
    list_iterator enabledoldtrgpos  = last;

    auto [to_current, to_other] =
        to_enabled ? std::tie(enabled, disabled) : std::tie(disabled, enabled);
    auto [first_current, first_other, first_newpos_current,
          first_newpos_other] =
        first.enabled
            ? std::tie(enabled, disabled, enablednewpos, disablednewpos)
            : std::tie(disabled, enabled, disablednewpos, enablednewpos);
    auto [last_current_src, last_current_src_other] =
        last.enabled ? std::tie(other.enabled, other.disabled)
                     : std::tie(other.disabled, other.enabled);

    if (&other == this && last.enabled == to_enabled && newpos == last)
      return;

    // gets disablednewpos & enablednewpos
    if (newpos == to_current.end())
    {
      disablednewpos = disabled.end();
      enablednewpos  = enabled.end();
    }
    else
    {
      list_iterator& othernewpos = to_enabled ? disablednewpos : enablednewpos;
      list_iterator  i           = newpos;

      while (i != to_current.end() && !i->has_other)
        ++i;
      othernewpos = i != to_current.end() ? i->other : to_other.end();
    }

    list_iterator bind_pos{};
    list_iterator lastprev{};
    list_iterator range_begin   = first;
    list_iterator range_end     = last;
    list_iterator first_enabled = range_begin;
    list_iterator last_enabled  = range_end;
    bool          has_enabled   = false;
    bool          should_bind   = false;
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
        itr->chain = other;
        auto [trgpos, trglist, othertrglist] =
            itr.enabled ? std::tie(enabledoldtrgpos, other.enabled, enabled)
                        : std::tie(disabledoldtrgpos, other.disabled, disabled);

        trglist.splice(trgpos, othertrglist,
                       std::exchange(itr, std::next(itr)));
      }

      lastprev->has_other = lastprev_has_other;
    };

    if (!is_empty)
    {
      if (first_newpos_current == first_current.begin())
      {
        if (starts_enabled != first.enabled)
        {
          should_bind = true;
          bind_pos    = std::prev(first_newpos_other);
        }
      }
      else
      {
        list_iterator newfirstprev = std::prev(first_newpos_current);
        if (newfirstprev->has_other)
        {
          should_bind = true;
          bind_pos    = std::prev(first_newpos_other);
        }
      }
    }

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
          range_begin->chain = *this;
          lastprev           = range_begin;
          disabled.splice(disablednewpos, other.disabled,
                          std::exchange(range_begin, std::next(range_begin)));
        }

        if (range_begin != range_end)
        {
          disabledoldtrgpos  = std::next(range_begin);
          range_begin->chain = *this;
          lastprev           = range_begin;
          disabled.splice(disablednewpos, other.disabled, range_begin);
          first_enabled = range_begin->other;
          has_enabled   = true;
        }
      }
      else
      {
        while (!range_begin->has_other)
        {
          range_begin->chain = *this;
          lastprev           = range_begin;
          disabled.splice(disablednewpos, other.disabled,
                          std::exchange(range_begin, std::next(range_begin)));
        }

        disabledoldtrgpos  = std::next(range_begin);
        range_begin->chain = *this;
        lastprev           = range_begin;
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
      const bool in_list_splice         = &other == this;
      bool       stop_splicing_enabled  = false;
      bool       stop_splicing_disabled = false;

      // transfer everything (and keep track of last_enabled)
      for (auto itr = iterator(list_iterator(), first_enabled, true);
           itr != last;)
      {
        itr->chain = *this;
        lastprev   = itr;
        if (itr.enabled)
          last_enabled = lastprev;

        auto [oldtrgpos, trgpos, trglist, othertrglist, stop_splicing] =
            itr.enabled ? std::tie(enabledoldtrgpos, enablednewpos, enabled,
                                   other.enabled, stop_splicing_enabled)
                        : std::tie(disabledoldtrgpos, disablednewpos, disabled,
                                   other.disabled, stop_splicing_disabled);

        oldtrgpos = std::next(static_cast<list_iterator>(itr));

        if (in_list_splice &&
            (stop_splicing || (stop_splicing = itr == trgpos)))
        {
          ++itr;
          continue;
        }

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
            inject(other, other.backup.data(), false);
          }
          else
            patch(other, first_enabled->poriginal);
        }
        else
        {
          thread_freezer freeze{ nullptr };
          enabledoldtrgpos->redirect_originalref(first_enabled->poriginal);
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
        otherfront.redirect_originalref(
            helpers::resolve_original(ptarget, ptrampoline.get()));
      else
      {
        list_iterator enabledprev = std::prev(first_enabled);
        otherfront.redirect_originalref(enabledprev->pdetour);
      }

      try
      {
        if (enablednewpos == enabled.end())
        {
          std::unique_lock lock{ hook_lock };
          if (first_enabled == enabled.begin())
          {
            thread_freezer freeze{ *this, true };
            inject(otherback.pdetour, true);
          }
          else
            patch(otherback.pdetour);
        }
        else
        {
          thread_freezer freeze{ nullptr };
          enablednewpos->redirect_originalref(otherback.pdetour);
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

    if (is_empty)
      starts_enabled = first.enabled;
    else if (should_bind)
    {
      bind_pos->has_other = true;
      bind_pos->other     = first;
    }

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
        if (last == last_current_src.end() || last.enabled == oldother->enabled)
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
    if (to_enabled != lastprev->enabled && newpos != to_current.end())
    {
      lastprev->has_other = true;
      lastprev->other     = newpos;
    }
  }

  void hook_chain::set_target(std::byte* target)
  {
    if (ptarget == target)
      return;
    uninject_all();
    auto try_inject_back = [this]
    {
      if (enabled.empty())
        return;
      try
      {
        std::unique_lock lock{ hook_lock };
        thread_freezer   freeze{ *this, true };
        inject(enabled.back().pdetour, true);
      }
      catch (...)
      {
        toggle_status_all(include::enabled);
        throw;
      }
    };

    try
    {
      init(target);
    }
    catch (const exceptions::page_allocation_fail&)
    {
      try_inject_back();
      throw;
    }
    catch (const exceptions::invalid_address&)
    {
      try_inject_back();
      throw;
    }
    catch (...)
    {
      // for any other exception the trampoline is reset and therefore the chain
      // is left uninitialized, so we move all enabled hooks to the disabled
      // list.
      toggle_status_all(include::enabled);
      throw;
    }

    helpers::make_backup(ptarget, backup.data(), patch_above);
    try_inject_back();
  }

  bool hook_chain::operator==(const hook_chain& other) const noexcept
  {
    return std::forward_as_tuple(ptarget, enabled.size(), disabled.size()) ==
               std::forward_as_tuple(other.ptarget, other.enabled.size(),
                                     other.disabled.size()) &&
           std::equal(begin(), end(), other.begin(),
                      [](const hook& left, const hook& right)
                      {
                        return std::tie(left.pdetour, left.enabled) ==
                               std::tie(right.pdetour, right.enabled);
                      });
  }

  bool hook_chain::operator!=(const hook_chain& other) const noexcept
  {
    return !(*this == other);
  }

#if utils_clang
  #pragma clang diagnostic pop
#endif

  // hook_chain utilities

  void hook_chain::unbind_range(list_iterator first, list_iterator last,
                                unbind_range_callback& callback)
  {
    list_iterator range_begin = first, range_end = std::prev(last);
    list_iterator other_range_begin{}, other_range_end{};
    auto [current, other]    = first->enabled ? std::tie(enabled, disabled)
                                              : std::tie(disabled, enabled);
    bool       has_last_link = false, has_first_link = false;
    const bool lastprev_has_other = range_end->has_other;

    // search backwards for last link from other to this range
    while (!range_end->has_other && range_end != range_begin)
      callback(std::exchange(range_end, std::prev(range_end)), false);

    if (range_end->has_other)
    {
      has_last_link   = true;
      other_range_end = range_end->other;
      if (last != current.end() || !lastprev_has_other)
      {
        while (!other_range_end->has_other)
          ++other_range_end;
      }
      else
        other_range_end = std::prev(other.end());
    }

    if (first == current.begin())
    {
      if (first->enabled != starts_enabled)
      {
        other_range_begin = other.begin();
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
          callback(std::exchange(range_begin, std::next(range_begin)));

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
          callback(std::exchange(range_begin, std::next(range_begin)));

        other_range_begin = range_begin->other;
      }

      for (; other_range_begin != other_range_end; ++other_range_begin)
        other_range_begin->has_other = false;

      if (lastprev_has_other || last == current.end())
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
      callback(std::exchange(range_begin, std::next(range_begin)));
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
    inject(backup.data(), false);
  }

  void hook_chain::uninject_range(list_iterator first, list_iterator last)
  {
    if (last != enabled.end())
    {
      thread_freezer freeze{ nullptr };
      last->redirect_originalref(first->poriginal);
      return;
    }

    std::unique_lock lock{ hook_lock };
    if (first == enabled.begin())
    {
      thread_freezer freeze{ *this, false };
      inject(backup.data(), false);
    }
    else
      patch(first->poriginal);
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

    auto [current, other] =
        to_enabled ? std::tie(enabled, disabled) : std::tie(disabled, enabled);

    bool          search = false;
    list_iterator search_itr{};

    if (pos == current.begin())
    {
      if (to_enabled != starts_enabled)
      {
        if (pos == current.end())
        {
          hook& trglast     = other.back();
          trglast.has_other = true;
          trglast.other     = oldpos;
        }
        else
        {
          search     = true;
          search_itr = other.begin();
        }
      }
    }
    else if (list_iterator posprev = std::prev(pos); posprev->has_other)
    {
      if (pos == current.end())
      {
        hook& trglast     = other.back();
        trglast.has_other = true;
        trglast.other     = oldpos;
      }
      else
      {
        search     = true;
        search_itr = posprev->other;
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
    if (pos != enabled.end())
    {
      thread_freezer freeze{ nullptr };
      first->redirect_originalref(pos->poriginal);
      pos->redirect_originalref(lastprev->pdetour);
      return;
    }

    std::unique_lock lock{ hook_lock };
    if (enabled.empty())
    {
      first->redirect_originalref(
          helpers::resolve_original(ptarget, ptrampoline.get()));
      thread_freezer freeze{ *this, true };
      inject(lastprev->pdetour, true);
    }
    else
    {
      hook& elast = enabled.back();
      first->redirect_originalref(elast.pdetour);
      patch(lastprev->pdetour);
    }
  }

  void hook_chain::inject_back(list_iterator first, list_iterator last)
  {
    const list_iterator lastprev = std::prev(last);

    if (first == enabled.begin())
      first->redirect_originalref(
          helpers::resolve_original(ptarget, ptrampoline.get()));
    else
    {
      const list_iterator firstprev = std::prev(first);
      first->redirect_originalref(firstprev->pdetour);
    }

    if (last != enabled.end())
    {
      thread_freezer freeze{ nullptr };
      last->redirect_originalref(lastprev->pdetour);
      return;
    }

    std::unique_lock lock{ hook_lock };
    if (first == enabled.begin())
    {
      thread_freezer freeze{ *this, true };
      inject(lastprev->pdetour, true);
    }
    else
      patch(lastprev->pdetour);
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
        current_itr->redirect_originalref(target_itr->poriginal);
        target_itr->redirect_originalref(current_itr->pdetour);
      }
      other->splice(target_itr, *current, current_itr);
      previtr = current_itr;
    } while (!current->empty());

    // switch to true only if moving disabled to enabled, otherwise false
    starts_enabled = src == include::disabled;
  }

  void hook_chain::init_with_list(hook_init_range range)
  {
    helpers::make_backup(ptarget, backup.data(), patch_above);
    const std::byte* original =
        helpers::resolve_original(ptarget, ptrampoline.get());

    for (auto itr = range.first; itr != range.second; ++itr)
    {
      auto& [detour, buffer] = *itr;
      const list_iterator trg_itr =
          enabled.emplace(enabled.end(), *this, detour, buffer, original, true);
      trg_itr->current = trg_itr;
      original         = detour;
    }

    starts_enabled = true;
    std::unique_lock lock{ hook_lock };
    thread_freezer   freeze{ *this, true };
    inject(enabled.back().pdetour, true);
  }

  typename hook_chain::hook&
      hook_chain::push_back_impl(const std::byte*     detour,
                                 helpers::orig_buff_t buffer, bool enable_hook)
  {
    auto [to, other] =
        enable_hook ? std::tie(enabled, disabled) : std::tie(disabled, enabled);
    const std::byte* const original =
        enabled.empty() ? helpers::resolve_original(ptarget, ptrampoline.get())
                        : enabled.back().pdetour;
    to.emplace_back(*this, detour, buffer, original, enable_hook);
    const list_iterator itr = std::prev(to.end());
    itr->current            = itr;
    if (enable_hook)
      join_last();

    bool touch_back = false;
    if (itr == to.begin())
    {
      if (other.empty())
        starts_enabled = enable_hook;
      else
        touch_back = true;
    }
    else if (std::prev(itr)->has_other)
      touch_back = true;

    if (!touch_back)
      return *itr;
    hook& otherback     = other.back();
    otherback.has_other = true;
    otherback.other     = itr;
    return *itr;
  }

  typename hook_chain::hook&
      hook_chain::push_front_impl(const std::byte*     detour,
                                  helpers::orig_buff_t buffer, bool enable_hook)
  {
    auto [to, other] =
        enable_hook ? std::tie(enabled, disabled) : std::tie(disabled, enabled);
    to.emplace_front(*this, detour, buffer,
                     helpers::resolve_original(ptarget, ptrampoline.get()),
                     enable_hook);
    const list_iterator itr = to.begin();
    itr->current            = itr;

    if (enable_hook)
      join_first();

    if (starts_enabled != enable_hook && !other.empty())
    {
      itr->has_other = true;
      itr->other     = other.begin();
    }
    starts_enabled = enable_hook;
    return *itr;
  }

  typename hook_chain::hook&
      hook_chain::insert_impl(list_iterator pos, const std::byte* detour,
                              helpers::orig_buff_t buffer, include trg)
  {
    auto [to, other] = trg == include::enabled ? std::tie(enabled, disabled)
                                               : std::tie(disabled, enabled);
    const bool             enable_hook = trg == include::enabled;
    const std::byte* const original =
        enable_hook
            ? pos == enabled.begin()
                  ? helpers::resolve_original(ptarget, ptrampoline.get())
                  : std::prev(pos)->pdetour
            : nullptr;
    list_iterator itr =
        to.emplace(pos, *this, detour, buffer, original, enable_hook);
    itr->current = itr;
    if (enable_hook)
      join(itr);

    if (itr == to.begin())
    {
      if (starts_enabled != itr->enabled)
      {
        list_iterator i = other.begin();
        while (!i->has_other)
          ++i;
        i->other = itr;
      }
    }
    else
    {
      list_iterator itrprev = std::prev(itr);
      if (itrprev->has_other)
      {
        list_iterator i = itrprev->other;
        while (!i->has_other)
          ++i;
        i->other = itr;
      }
    }
    return *itr;
  }

  typename hook_chain::list_range hook_chain::append_list(transfer        to,
                                                          hook_init_range range)
  {
    const size_t args_count = range.second - range.first;
    utils_assert(args_count, "hook_chain::append: empty arg list unexpected");
    utils_assert(to != transfer::both,
                 "hook_chain::append: transfer::both is not a valid value");
    const bool enable_hooks = to == transfer::enabled;
    auto [trg, other]       = enable_hooks ? std::tie(enabled, disabled)
                                           : std::tie(disabled, enabled);
    const std::byte* original =
        enabled.empty() ? helpers::resolve_original(ptarget, ptrampoline.get())
                        : enabled.back().pdetour;
    const list_iterator prevlast =
        !trg.empty() ? std::prev(trg.end()) : trg.end();

    try
    {
      for (auto itr = range.first; itr != range.second; ++itr)
      {
        auto& [detour, buffer]      = *itr;
        const list_iterator trg_itr = trg.emplace(
            trg.end(), *this, detour, buffer, original, enable_hooks);
        trg_itr->current = trg_itr;
        original         = detour;
      }

      if (enable_hooks)
        join_last_unchecked(args_count);
    }
    catch (...)
    {
      trg.erase(std::next(prevlast), trg.end());
      throw;
    }

    bool touch_back = false;

    if (args_count == trg.size())
    {
      if (other.empty())
      {
        starts_enabled = enable_hooks;
        return { trg.begin(), trg.end() };
      }
      touch_back = true;
    }
    else if (prevlast->has_other)
      touch_back = true;

    if (!touch_back)
      return { std::next(prevlast), trg.end() };
    hook& otherback     = other.back();
    otherback.has_other = true;
    otherback.other     = std::next(prevlast);
    return { std::next(prevlast), trg.end() };
  }

  void hook_chain::join_last_unchecked(size_t enabled_count)
  {
    std::unique_lock lock{ hook_lock };
    list_iterator    itr = std::prev(enabled.end());
    if (enabled_count == enabled.size())
    {
      thread_freezer freeze{ *this, true };
      inject(itr->pdetour, true);
    }
    else
      patch(itr->pdetour);
  }

  void hook_chain::join_last()
  {
    try
    {
      join_last_unchecked();
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
        inject(itr->pdetour, true);
      }
      else
      {
        list_iterator  next = std::next(itr);
        thread_freezer freeze{ nullptr };
        next->redirect_originalref(itr->pdetour);
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
          inject(itr->pdetour, true);
        }
        else
          patch(itr->pdetour);
      }
      else
      {
        thread_freezer freeze{ nullptr };
        itrnext->redirect_originalref(itr->pdetour);
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
        chain.get().ptarget != pdetour,
        "hook_chain::hook::enable: target & detour have the same address");
    if (enabled)
      return;
    list_iterator newpos = chain.get().enabled.end();
    if (!chain.get().enabled.empty())
    {
      list_iterator i = current;
      while (!i->has_other && i != chain.get().disabled.end())
        ++i;

      if (i != chain.get().disabled.end())
        newpos = i->other;
    }

    chain.get().inject_range(newpos, current, std::next(current));
    chain.get().toggle_status(current);
  }

  void hook_chain::hook::disable()
  {
    if (!enabled)
      return;
    chain.get().uninject(current);
    chain.get().toggle_status(current);
  }

  void hook_chain::hook::set_detour(std::byte* detour)
  {
    if (pdetour == detour)
      return;
    if (!enabled)
    {
      pdetour = detour;
      return;
    }

    std::unique_lock    lock{ hook_lock };
    const list_iterator next = std::next(current);
    if (next == chain.get().enabled.end())
      patch(chain.get(), detour);
    else
    {
      thread_freezer freeze{ nullptr };
      next->redirect_originalref(detour);
    }

    pdetour = detour;
  }

  void hook_chain::hook::set_original(helpers::orig_buff_t original)
  {
    thread_freezer freeze{};
    if (enabled)
      freeze.init(nullptr);

    *std::launder(reinterpret_cast<helpers::original*>(&original)) = poriginal;
    originalref()                                                  = nullptr;
    origbuff                                                       = original;
  }

  void hook_chain::hook::swap(hook& right)
  {
    if (enabled && right.enabled &&
        (poriginal == right.pdetour || right.poriginal == pdetour))
    {
      auto [newprev, newnext] = poriginal == right.pdetour
                                    ? std::tie(*this, right)
                                    : std::tie(right, *this);
      newprev.redirect_originalref(newnext.poriginal);
      newnext.redirect_originalref(newprev.pdetour);
    }
    else
    {
      std::swap(poriginal, right.poriginal);
      originalref()       = poriginal;
      right.originalref() = right.poriginal;
    }

    std::swap(chain, right.chain);
    std::swap(other, right.other);
    std::swap(has_other, right.has_other);
    std::swap(enabled, right.enabled);
  }

  bool hook_chain::hook::operator==(const hook& other) const noexcept
  {
    return std::tie(chain.get().ptarget, pdetour, enabled) ==
           std::tie(other.chain.get().ptarget, other.pdetour, other.enabled);
  }

  bool hook_chain::hook::operator!=(const hook& other) const noexcept
  {
    return std::tie(chain.get().ptarget, pdetour, enabled) !=
           std::tie(other.chain.get().ptarget, other.pdetour, other.enabled);
  }

  std::reference_wrapper<typename hook_chain::hook> hook_chain::empty_ref_wrap()
  {
    static std::aligned_storage_t<sizeof(hook), alignof(hook)> buffer{};
    return std::ref(*std::launder(reinterpret_cast<hook*>(&buffer)));
  }
} // namespace alterhook

#pragma clang diagnostic pop
