/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#include <algorithm>
#include <cstddef>
#include <cstdlib>
#include <iterator>
#include <pch.hpp>
#include <tuple>
#include <utility>
#include <vector>
#include "hook_chain.hpp"
#include "thread_handler.hpp"
#include "tools.hpp"
#include "utilities/macros.hpp"
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnon-virtual-dtor"
#pragma clang diagnostic ignored "-Wshadow"
#pragma clang diagnostic ignored "-Wstring-conversion"
#pragma clang diagnostic ignored "-Wcomma"

namespace alterhook
{
  struct hook_chain::intra_swap_info
  {
    bool rearranged;
    bool left_is_first;
  };

  struct hook_chain::splicer_rollback_info
  {
    iterator itr{};
    bool     was_matched   = false;
    bool     changed_state = false;
  };

  // only domain specific properties are swapped
  void hook_chain::hook::swap(hook& right)
  {
    // std::swap(poriginal, right.poriginal);
    // original_ref.bind_original(poriginal);
    // right.original_ref.bind_original(right.poriginal);
    std::swap(chain, right.chain);
  }

  void hook_chain::inject_back_all()
  {
    if (!enabled_count)
      return;
    thread_freezer freeze{ *this, true };
    inject(enabled_hooks().back().pdetour, true);
  }

  void hook_chain::uninject_all()
  {
    if (!enabled_count)
      return;
    thread_freezer freeze{ *this, false };
    inject(backup.data(), false);
  }

  void hook_chain::safe_uninject_all() noexcept
  {
    try
    {
      uninject_all();
    }
    catch (...)
    {
      release();
    }
  }

  size_t
      hook_chain::set_status_range(iterator first, iterator last,
                                   bool                              new_state,
                                   predicate_view<bool(const hook&)> predicate)
  {
    if (first == last)
      return 0;

    // --- PHASE 1: TRANSACTION SETUP & BOOKKEEPING ---
    // Track strictly the hooks that change state to allow easy rollback.
    std::vector<iterator> updated_hooks;

    const std::byte* prev_poriginal    = nullptr;
    const std::byte* current_poriginal = nullptr;
    ptrdiff_t        enabled_diff      = 0;
    bool             tip_changed       = false;
    thread_freezer   freeze{ defer_freeze };

    // --- PHASE 2: SINGLE-PASS STATE & POINTER UPDATE ---
    for (iterator itr = first; itr != last; ++itr)
    {
      bool state_changed = false;

      if (!current_poriginal && itr->enabled)
        prev_poriginal = current_poriginal = itr->poriginal;

      // 1. Update logical state and track for potential rollback
      if (itr->enabled != new_state && (!predicate || predicate(*itr)))
      {
        if (!updated_hooks.capacity())
          updated_hooks.reserve(hooks.size());
        if (!freeze.initialized())
        {
          if (!enabled_count)
            freeze.init(*this, true);
          else
            freeze.init();
        }

        itr->enabled = new_state;
        updated_hooks.push_back(itr);
        if (new_state)
        {
          ++enabled_diff;

          if (!current_poriginal)
          {
            const auto prev_enabled =
                std::find_if(std::reverse_iterator(first), rend(),
                             [](const hook& item) { return item.enabled; });
            prev_poriginal = current_poriginal =
                prev_enabled != rend() ? prev_enabled->pdetour : get_original();
          }
        }
        else
          --enabled_diff;

        state_changed = true;
      }

      // 2. Safely relink pointers (threads are frozen)
      if (itr->enabled)
      {
        if (itr->poriginal != current_poriginal)
          itr->redirect_original(current_poriginal);

        current_poriginal = itr->pdetour;
        // the surviving hook was just turned on? the tip was disrupted. the
        // surviving hook was already enabled? the tip is stable.
        tip_changed       = state_changed;
      }
      // the hook was just disabled? tip changed
      else if (state_changed)
        tip_changed = true;
    }

    if (updated_hooks.empty())
      return 0;
    // nothing to modify outside the range if the tip didn't change
    if (!tip_changed)
    {
      enabled_count += enabled_diff;
      return updated_hooks.size();
    }

    // --- PHASE 3: TAIL RELINKING & SYSTEM MEMORY COMMIT ---
    const iterator next_enabled = std::find_if(last, end(), [](const hook& item)
                                               { return item.enabled; });

    if (next_enabled != end())
    {
      if (next_enabled->poriginal != current_poriginal)
        next_enabled->redirect_original(current_poriginal);
    }
    else
    {
      try
      {
        // we exited earlier for when disabled stayed disabled
        if (!new_state)
        {
          // disabled all hooks case
          if (enabled_count == static_cast<size_t>(-enabled_diff))
            inject(backup.data(), false);
          // redirecting to previous enabled in line
          else
            patch(current_poriginal);
        }
        // went from 0 to some enabled hooks
        else if (!enabled_count)
          inject(current_poriginal, true);
        else
          patch(current_poriginal);
      }
      catch (...)
      {
        // --- PHASE 4: EXCEPTION ROLLBACK ---
        // The OS refused to patch memory. Target function is still in its old
        // state. Revert our internal data to perfectly synchronize with
        // reality.

        for (iterator update : updated_hooks)
          update->enabled = !new_state;

        current_poriginal = prev_poriginal;

        // Revert the poriginal pointers of the enabled hooks to their original
        // state
        for (iterator itr = first; itr != last; ++itr)
        {
          if (!itr->enabled)
            continue;

          if (itr->poriginal != current_poriginal)
            itr->redirect_original(current_poriginal);
          current_poriginal = itr->pdetour;
        }

        throw; // Rethrow to the caller
      }
    }

    enabled_count += enabled_diff;
    return updated_hooks.size();
  }

  // Detaches a hook from the chain, bridging the gap using new_poriginal.
  // Passing update_memory = false skips host memory patches (used for
  // transactional safety).
  void hook_chain::unlink(iterator itr, const std::byte* new_poriginal,
                          bool update_memory)
  {
    // Search forward (upstream) to find the hook that currently jumps to 'itr'
    iterator next = std::find_if(std::next(itr), hooks.end(),
                                 [](const hook& item) { return item.enabled; });

    if (next != hooks.end())
    {
      // The hook is in the middle of the chain. We simply rewire the upstream
      // hook's internal trampoline to bypass 'itr'. No physical memory touched.
      next->redirect_original(new_poriginal);
      return;
    }
    // The hook is at the head of the chain, but hardware patches are
    // deferred.
    else if (!update_memory)
      return;

    // The hook is at the head of the chain and we must patch the physical
    // memory.
    if (enabled_count == 1)
      // It was the last active hook. Restore the target function's original
      // bytes.
      inject(backup.data(), false);
    else
      // Other hooks remain. Overwrite the host's JMP to point to the new head.
      patch(new_poriginal);
  }

  // Inserts a hook into the active execution chain.
  // Passing new_poriginal (optionally) forces a specific downstream target
  // (O(1) optimization). Passing update_memory = false skips host memory
  // patches (used for transactional safety).
  void hook_chain::link(iterator itr, const std::byte* new_poriginal,
                        bool update_memory)
  {
    // Search forward (upstream) to find the hook that will execute just before
    // 'itr'
    iterator next = std::find_if(std::next(itr), hooks.end(),
                                 [](const hook& item) { return item.enabled; });

    if (next != hooks.end())
    {
      // The hook is in the middle of the chain.
      // Point our hook downstream (using the override or stealing the
      // upstream's target).
      itr->redirect_original(new_poriginal ? new_poriginal : next->poriginal);

      // Wire the upstream hook to jump into our new hook.
      // Since the host's physical JMP isn't changing, we exit early.
      next->redirect_original(itr->pdetour);
      return;
    }

    // The hook is at the head of the chain. Handle physical memory updates if
    // requested.
    if (update_memory)
    {
      if (!enabled_count)
        // First active hook in the container: allocate trampoline and write the
        // JMP.
        inject(itr->pdetour, true);
      else
        // Chain is already active: just overwrite the existing JMP destination.
        patch(itr->pdetour);
    }

    // Since 'itr' is at the head, it needs to know what to execute next
    // (downstream).
    if (new_poriginal)
      // O(1) override used during cross-container swaps.
      itr->redirect_original(new_poriginal);
    else
    {
      // Fallback: Search backward (downstream) to find the next active hook in
      // this container.
      auto prev = std::find_if(std::reverse_iterator(itr), rend(),
                               [](const hook& item) { return item.enabled; });

      if (prev != rend())
        // Jump to the closest downstream hook.
        itr->redirect_original(prev->pdetour);
      else
        // No downstream hooks exist. Jump to the host application's original
        // function.
        itr->redirect_original(get_original());
    }
  }

  // Determines if a cross-container swap will physically overwrite the prologue
  // of the target function, requiring the thread_freezer to perform IP
  // relocation.
  bool hook_chain::cross_splice_requires_injection(
      iterator other_itr) const noexcept
  {
    utils_assert(this != &other_itr->chain.get(),
                 "hook_chain::cross_splice_requires_injection: improper use of "
                 "the tool, other_itr belongs to `this`");

    // Relocation is only required when transitioning between 0 and 1 active
    // hooks, as this is when the target function's prologue instructions are
    // physically altered:
    // 1. (!enabled_count && other_itr->enabled): 0 -> 1. We are writing a JMP
    // (inject).
    //    Frozen threads caught in the prologue must be relocated to the
    //    trampoline.
    // 2. (enabled_count == 1 && !other_itr->enabled): 1 -> 0. We are restoring
    // original bytes.
    //    Frozen threads must be relocated accordingly.
    return (!enabled_count && other_itr->enabled) ||
           (enabled_count == 1 && !other_itr->enabled);
  }

  // Physically swaps two hook nodes across containers without copying their
  // internal data.
  void hook_chain::swap_raw(iterator& left, iterator left_next,
                            hook_chain& other, iterator& right,
                            iterator right_next) noexcept
  {
    // 1. Adapt domain-specific metadata (chain references and poriginals)
    left->swap(*right);

    // 2. Structurally move 'right' into 'this' container, right where 'left'
    // was
    hooks.splice(left_next, other.hooks, right);

    // 3. Structurally move 'left' into the 'other' container, right where
    // 'right' was
    other.hooks.splice(right_next, hooks, left);

    // 4. Realign the iterator variables in the caller's scope.
    // This ensures 'left' still refers to the slot in 'this' container,
    // and 'right' still refers to the slot in 'other'.
    std::swap(left, right);
  }

  // Analyzes two hooks in the same container to determine if swapping them
  // alters the active execution topology, and identifies their spatial
  // relationship (left < right).
  hook_chain::intra_swap_info
      hook_chain::analyse_intra_swap(iterator left,
                                     iterator right) const noexcept
  {
    // O(1) Fast path: Disabled hooks are invisible to the active execution
    // chain. Swapping them never changes the topology.
    if (!left->enabled && !right->enabled)
      return { false, false };

    // If both are enabled, swapping them will always change the execution
    // order.
    const bool both_enabled    = left->enabled && right->enabled;
    bool       enabled_spotted = false;

    // 1. Forward Search: Assume 'left' comes before 'right' in the chain.
    for (iterator itr = std::next(left); itr != end(); ++itr)
    {
      if (itr == right)
      {
        // 'right' was found downstream. The topology changes if both are
        // enabled, or if there is at least one active hook strictly between
        // them.
        return { both_enabled || enabled_spotted, true };
      }
      if (itr->enabled)
        enabled_spotted = true;
    }

    // 2. Reverse Search: If the forward search hit end(), 'right' MUST precede
    // 'left'. We set up strictly exclusive bounds to check the nodes between
    // them.
    auto ritr  = std::reverse_iterator(left);
    auto rstop = std::reverse_iterator(std::next(right));

#ifdef NDEBUG
    // Release mode: Fast strictly-between search using the exclusive rstop
    // bound.
    const bool rearranged =
        both_enabled || std::find_if(ritr, rstop, [](const hook& item)
                                     { return item.enabled; }) != rstop;
    return { rearranged, false };
#else
    // Debug mode: Manual loop to enforce safety guarantees.
    enabled_spotted = false;
    for (; ritr != rend(); ++ritr)
    {
      if (ritr == rstop)
        return { both_enabled || enabled_spotted, false };
      if (ritr->enabled)
        enabled_spotted = true;
    }

    // If we hit rend() before rstop, 'left' and 'right' belong to entirely
    // different containers!
    utils_assert(false, "hook_chain::swap: `left` and `right` don't form a "
                        "valid range with `other` set to `*this`");
    return { false, false };
#endif
  }

  void hook_chain::splice_disabled(iterator newpos, hook_chain& other,
                                   iterator first, iterator last) noexcept
  {
    const bool intra_splice = this == &other;

    for (iterator itr = first; itr != last;)
    {
      if (itr->enabled)
      {
        ++itr;
        continue;
      }

      if (!intra_splice)
        itr->chain = *this;
      hooks.splice(newpos, other.hooks, itr++);
    }
  }

  void hook_chain::splice_rollback(iterator first, iterator last,
                                   iterator newpos, hook_chain& other,
                                   const rollback_t& rollback_data,
                                   const std::byte*  prev_poriginal) noexcept
  {
    const std::byte* current_poriginal = prev_poriginal;
    const bool       intra_splice      = this == &other;

    if (!rollback_data.capacity())
    {
      for (iterator itr = first; itr != newpos;)
      {
        if (!intra_splice)
          itr->chain = other;
        if (itr->enabled)
        {
          itr->redirect_original(current_poriginal);
          current_poriginal = itr->pdetour;
        }
        other.hooks.splice(last, hooks, itr++);
      }
      return;
    }

    iterator next_unmatched        = last;
    bool     search_next_unmatched = true;

    for (auto rollback_itr = rollback_data.begin();
         rollback_itr != rollback_data.end(); ++rollback_itr)
    {
      if (!rollback_itr->was_matched)
      {
        search_next_unmatched = true;
        continue;
      }

      if (search_next_unmatched)
      {
        const auto search_itr = std::find_if_not(
            std::next(rollback_itr), rollback_data.end(),
            [](const splicer_rollback_info& item) { return item.was_matched; });
        if (search_itr == rollback_data.end())
          next_unmatched = last;
        else
          next_unmatched = search_itr->itr;
        search_next_unmatched = false;
      }

      const auto itr = rollback_itr->itr;

      if (rollback_itr->changed_state)
        itr->enabled = !itr->enabled;

      if (itr->enabled)
      {
        itr->redirect_original(current_poriginal);
        current_poriginal = itr->pdetour;
      }

      if (!intra_splice)
        itr->chain = other;

      other.hooks.splice(next_unmatched, hooks, itr);
    }
  }

  hook_chain::hook_chain(hook_chain&& other) noexcept
      : trampoline(std::move(other)), backup(other.backup),
        hooks(std::move(other.hooks)),
        enabled_count(std::exchange(other.enabled_count, 0))
  {
    for (hook& h : *this)
      h.chain = *this;
  }

  hook_chain::hook_chain(alterhook::hook&& other)
      : trampoline(std::move(other)), backup(other.backup),
        enabled_count(other.enabled ? 1 : 0)
  {
    utils_assert(other.original_ref,
                 "hook_chain::hook_chain: can't initialize hook chain with a "
                 "hook that doesn't hold a reference to the original");
    reference item =
        hooks.emplace_back(*this, std::exchange(other.pdetour, nullptr),
                           std::move(other.original_ref), get_original(),
                           std::exchange(other.enabled, false));
    item.current = hooks.begin();
  }

#if utils_msvc
  #pragma warning(push)
  #pragma warning(disable : 4297)
#endif

  hook_chain::~hook_chain() noexcept
  {
    try
    {
      clear();
    }
    catch (...)
    {
      // release the trampoline, that's the safest approach we can use here
      release();
    }
  }

#if utils_msvc
  #pragma warning(pop)
#endif

  hook_chain& hook_chain::operator=(hook_chain&& other) noexcept
  {
    if (this == &other)
      return *this;
    safe_uninject_all();
    trampoline::operator=(std::move(other));

    backup        = other.backup;
    hooks         = std::move(other.hooks);
    enabled_count = std::exchange(other.enabled_count, 0);

    for (hook& h : *this)
      h.chain = *this;
    return *this;
  }

  hook_chain& hook_chain::operator=(const trampoline& other)
  {
    if (ptarget != other.get_target())
      uninject_all();
    else if (!enabled_count)
    {
      trampoline::operator=(other);
      return *this;
    }
    else
    {
      auto tmp = static_cast<trampoline&&>(*this);
      trampoline::operator=(other);
      try
      {
        thread_freezer freeze;
        enabled_hooks().front().redirect_original(get_original());
      }
      catch (...)
      {
        trampoline::operator=(std::move(tmp));
        throw;
      }
      return *this;
    }

    try
    {
      trampoline::operator=(other);
      helpers::make_backup(ptarget, backup.data(), patch_above);
      if (enabled_count)
        enabled_hooks().front().redirect_original(get_original());
      inject_back_all();
    }
    catch (...)
    {
      for (hook& hook : hooks)
        hook.enabled = false;
      enabled_count = 0;
      throw;
    }
    return *this;
  }

  hook_chain& hook_chain::operator=(trampoline&& other)
  {
    if (ptarget != other.get_target())
      uninject_all();
    else if (!enabled_count)
    {
      trampoline::operator=(std::move(other));
      return *this;
    }
    else
    {
      std::swap(static_cast<trampoline&>(*this), other);
      try
      {
        thread_freezer freeze;
        enabled_hooks().front().redirect_original(get_original());
      }
      catch (...)
      {
        std::swap(static_cast<trampoline&>(*this), other);
        throw;
      }

      other.reset();
      return *this;
    }

    trampoline::operator=(std::move(other));
    helpers::make_backup(ptarget, backup.data(), patch_above);

    try
    {
      if (enabled_count)
        enabled_hooks().front().redirect_original(get_original());
      inject_back_all();
    }
    catch (...)
    {
      for (hook& hook : hooks)
        hook.enabled = false;
      enabled_count = 0;
      throw;
    }
    return *this;
  }

  void hook_chain::clear(state_filter filter)
  {
    if (hooks.empty())
      return;

    switch (filter)
    {
    case state_filter::disabled:
      if (enabled_count == hooks.size())
        return;
      hooks.remove_if([](const hook& item) { return !item.enabled; });
      break;
    case state_filter::enabled:
      if (!enabled_count)
        return;
      uninject_all();
      hooks.remove_if([](const hook& item) { return item.enabled; });
      enabled_count = 0;
      break;
    case state_filter::any:
      uninject_all();
      hooks.clear();
      enabled_count = 0;
      break;
    }
  }

  void hook_chain::pop_back(state_filter filter)
  {
    if (empty())
      return;
    if (filter == state_filter::any)
    {
      erase(std::prev(hooks.end()), hooks.end());
      return;
    }

    const bool enabled_check = filter == state_filter::enabled;
    const auto result        = std::find_if(hooks.rbegin(), hooks.rend(),
                                            [enabled_check](const hook& item)
                                            { return item.enabled == enabled_check; });

    if (result != hooks.rend())
      erase(std::prev(result.base()), result.base(), filter);
  }

  void hook_chain::pop_front(state_filter filter)
  {
    if (empty())
      return;
    if (filter == state_filter::any)
    {
      erase(begin(), std::next(begin()), filter);
      return;
    }

    const bool enabled_check = filter == state_filter::enabled;
    const auto itr =
        std::find_if(begin(), end(), [enabled_check](const hook& item)
                     { return item.enabled == enabled_check; });

    if (itr != end())
      erase(itr, std::next(itr), filter);
  }

  // Swaps two hooks. Handles both intra-container (same target) and
  // cross-container (different targets) swaps. Provides Strong Exception
  // Guarantee for intra-container swaps and Basic Exception Guarantee for
  // cross-container swaps, minimizing hardware cache flushes via deferred
  // memory patching.
  void hook_chain::swap(iterator left, hook_chain& other, iterator right)
  {
    utils_assert(&left->chain.get() == this,
                 "hook_chain::swap: the left iterator passed is outside the "
                 "range of `this` object");
    utils_assert(&right->chain.get() == &other,
                 "hook_chain::swap: the right iterator passed is outside the "
                 "range of `other` object");

    // =========================================================================
    // PHASE 1: Normalization & Early Exits (Intra-container only)
    // =========================================================================
    if (this == &other)
    {
      if (left == right)
        return;

      auto [rearranged, left_is_first] = analyse_intra_swap(left, right);

      if (!rearranged)
      {
        // Topology is unchanged. Perform a raw physical splice and exit (O(1)).
        const iterator left_next  = std::next(left);
        const iterator right_next = std::next(right);
        hooks.splice(left_next, hooks, right);
        hooks.splice(right_next, hooks, left);
        return;
      }

      // Enforce the spatial invariant: `left` must always physically precede
      // `right`. This allows upstream/downstream linking logic to be
      // unidirectional.
      if (!left_is_first)
        std::swap(left, right);
    }

    // =========================================================================
    // PHASE 2: State Capture & Thread Synchronization
    // =========================================================================
    const iterator         left_next             = std::next(left);
    const bool             left_was_enabled      = left->enabled;
    const std::byte* const left_poriginal        = left->poriginal;
    const iterator         right_next            = std::next(right);
    const bool             right_was_enabled     = right->enabled;
    const std::byte* const right_poriginal       = right->poriginal;
    bool                   this_gap_hard_closed  = false;
    bool                   other_gap_hard_closed = false;

    thread_freezer freeze{ defer_freeze };
    if (left->enabled || right->enabled)
    {
      // Initialize the freezer. If crossing containers requires an
      // inject/uninject, pass relocation info to prevent freezing threads on
      // overwritten prologues.
      if (this == &other)
        freeze.init();
      else if (cross_splice_requires_injection(right))
        freeze.init(*this, !enabled_count);
      else if (other.cross_splice_requires_injection(left))
        freeze.init(other, !other.enabled_count);
      else
        freeze.init();
    }

    // =========================================================================
    // PHASE 3: Unlink Phase (Ghosting)
    // =========================================================================
    if (this == &other)
    {
      left->enabled  = false;
      right->enabled = false;

      // Intra-container: Defer physical memory updates (false).
      // global enabled_count remains stable.
      if (left_was_enabled)
        unlink(left, left_poriginal, false);
      if (right_was_enabled)
        other.unlink(right, right_poriginal, false);
    }
    else if (left->enabled && right->enabled)
    {
      // Cross-container Dual-Enabled: Optimize by naturally orphaning `left`.
      // Only `right` forces a hard gap close on the `other` container.
      other.unlink(right, right_poriginal, true);
      other_gap_hard_closed = true;
      --other.enabled_count;
    }
    else if (left->enabled || right->enabled)
    {
      // Swapping an enabled hook with a disabled one. Hard unlink the enabled
      // and hard link it to its next container.
      if (left->enabled)
      {
        unlink(left, left_poriginal, true);
        this_gap_hard_closed = true;
        --enabled_count;
      }
      else
      {
        other.unlink(right, right_poriginal, true);
        other_gap_hard_closed = true;
        --other.enabled_count;
      }
    }

    // =========================================================================
    // PHASE 4: Physical Node Swap
    // =========================================================================
    swap_raw(left, left_next, other, right, right_next);

    bool left_linked             = false;
    bool cross_dual_enabled_swap = false;

    // =========================================================================
    // PHASE 5: Link Phase (Wiring)
    // =========================================================================
    try
    {
      if (this == &other)
      {
        // 1-Patch Optimization: `left` is downstream, `right` is upstream.
        // Link `left` first. If `left_was_enabled` is true, pass false to skip
        // memory patch. It seamlessly wires internal trampolines via its
        // backward search.
        left->enabled = right_was_enabled;
        if (left->enabled)
        {
          link(left, nullptr, !left_was_enabled);
          left_linked = true;
        }

        // Link `right` second. Passes true to trigger exactly 1 patch if it is
        // the head node.
        right->enabled = left_was_enabled;

        if (right->enabled)
          other.link(right, nullptr, true);
      }
      else if (left->enabled || right->enabled)
      {
        if (left->enabled && right->enabled)
        {
          // hard link the new left, automatically unlinking the old one. then
          // hard link the new right to other.
          cross_dual_enabled_swap = true;
          link(left, left_poriginal, true);
          left_linked = true;
          other.link(right, right_poriginal, true);
          ++other.enabled_count;
        }
        // just hard link the enabled hook to its new location
        else if (right->enabled)
        {
          other.link(right, right_poriginal, true);
          ++other.enabled_count;
        }
        else
        {
          link(left, left_poriginal, true);
          ++enabled_count;
        }
      }
    }
    // =========================================================================
    // PHASE 6: Exception Rollback
    // =========================================================================
    catch (...)
    {
      left->enabled  = false;
      right->enabled = false;

      // 1. Unlink left if it was successfully wired before the exception
      if (left_linked)
      {
        try
        {
          // Pass `this != &other` to avoid touching physical memory for
          // intra-container rollbacks
          unlink(left, left->poriginal, this != &other);
        }
        catch (...)
        {
          // Double-fault fallback: Basic Guarantee. Re-enable and adjust
          // counts.
          left->enabled = true;
          if (right_was_enabled && !other_gap_hard_closed)
            --other.enabled_count;
          throw;
        }

        this_gap_hard_closed = this != &other;
        if (this_gap_hard_closed)
          --enabled_count;
      }

      // 2. Restore physical topology
      swap_raw(left, left_next, other, right, right_next);

      const bool this_was_untouched =
          !left_was_enabled || (cross_dual_enabled_swap && !left_linked);
      left->enabled  = left_was_enabled;
      right->enabled = right_was_enabled;
      left_linked    = false;

      // 3. Relink original targets
      try
      {
        if (!this_was_untouched)
        {
          link(left, nullptr, this_gap_hard_closed);
          left_linked = true;
          if (this_gap_hard_closed)
            ++enabled_count;
        }

        if (right_was_enabled)
        {
          other.link(right, nullptr, other_gap_hard_closed);
          if (other_gap_hard_closed)
            ++other.enabled_count;
        }
      }
      catch (...)
      {
        // on double failure, mark the failed hooks as disabled. they were hard
        // unlinked at this point, therefore providing basic guarantee
        if (!left_linked && !this_was_untouched)
          left->enabled = false;
        if (right_was_enabled)
          right->enabled = false;
        throw;
      }
      throw;
    }
  }

  void hook_chain::swap(hook_chain& other)
  {
    if (this == &other)
      return;
    if (!enabled_count && !other.enabled_count)
    {
      hooks.swap(other.hooks);
      for (hook& item : *this)
        item.chain = *this;
      for (hook& item : other)
        item.chain = other;
      return;
    }

    thread_freezer freeze{ defer_freeze };
    if (enabled_count && other.enabled_count)
      freeze.init();
    else
    {
      hook_chain& to = enabled_count ? other : *this;
      freeze.init(to, true);
    }

    bool first_injected = false;

    try
    {
      if (enabled_count && other.enabled_count)
      {
        other.inject(other.backup.data(), false);
        patch(other.enabled_hooks().back().pdetour);
        enabled_hooks().front().redirect_original(get_original());
        first_injected = true;

        other.inject(enabled_hooks().back().pdetour, true);
        other.enabled_hooks().front().redirect_original(get_original());
      }
      else
      {
        auto [from, to] =
            enabled_count ? std::tie(*this, other) : std::tie(other, *this);
        from.inject(from.backup.data(), false);
        to.inject(from.enabled_hooks().back().pdetour, true);
        from.enabled_hooks().front().redirect_original(get_original());
      }
    }
    catch (...)
    {
      if (first_injected)
      {
        try
        {
          patch(enabled_hooks().back().pdetour);
        }
        catch (...)
        {
          hooks.swap(other.hooks);
          std::swap(enabled_count, other.enabled_count);
          for (hook& item : hooks)
            item.chain = *this;
          for (hook& item : other.hooks)
          {
            item.enabled = false;
            item.chain   = other;
          }
          throw;
        }

        enabled_hooks().front().redirect_original(get_original());
      }

      try
      {
        if (enabled_count && !other.enabled_count)
        {
          inject(enabled_hooks().back().pdetour, true);
          enabled_hooks().front().redirect_original(get_original());
          first_injected = true;
        }
        else if (other.enabled_count)
        {
          other.inject(other.enabled_hooks().back().pdetour, true);
          other.enabled_hooks().front().redirect_original(get_original());
        }
      }
      catch (...)
      {
        if (enabled_count && !other.enabled_count)
        {
          for (hook& item : hooks)
            item.enabled = false;
        }
        else if (other.enabled_count)
        {
          for (hook& item : other.hooks)
            item.enabled = false;
        }
        throw;
      }
      throw;
    }

    hooks.swap(other.hooks);
    std::swap(enabled_count, other.enabled_count);
    for (hook& item : hooks)
      item.chain = *this;
    for (hook& item : other.hooks)
      item.chain = other;
  }

#if utils_clang
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wswitch"
#endif

  void hook_chain::splice(iterator newpos, hook_chain& other, iterator first,
                          iterator last, splicer_flags flags)
  {
    if (first == last)
      return;
    const bool intra_splice = this == &other;

    if (intra_splice && newpos == last)
    {
      if (flags.target != target_state::preserve)
        set_status_range(first, last, flags.target == target_state::enabled);
      return;
    }
    if (flags.target == target_state::preserve &&
        flags.filter == state_filter::disabled)
    {
      splice_disabled(newpos, other, first, last);
      return;
    }

    iterator         this_next_enabled   = end();
    const std::byte* this_prev_poriginal = nullptr;

    if (!enabled_count)
      this_prev_poriginal = get_original();
    else
    {
      this_next_enabled = std::find_if(newpos, end(), [](const hook& item)
                                       { return item.enabled; });
      this_prev_poriginal =
          this_next_enabled != end()
              ? this_next_enabled->poriginal
              : std::find_if(std::reverse_iterator(newpos), rend(),
                             [](const hook& item) { return item.enabled; })
                    ->pdetour;
    }

    thread_freezer   freeze{ defer_freeze };
    iterator         first_enabled          = other.end();
    iterator         other_next_enabled     = other.end();
    const std::byte* other_prev_poriginal   = nullptr;
    const std::byte* current_this_poriginal = this_prev_poriginal;
    ptrdiff_t        this_enabled_diff      = 0;
    ptrdiff_t        other_enabled_diff     = 0;
    rollback_t       rollback_data;

    // Optimization Case: if splicing the whole range intra container without
    // state updates, we can make use of the O(1) std::list::splice. We only
    // need to look for the boundaries of the enabled subrange.
    if (intra_splice && flags.filter == state_filter::any &&
        flags.target == target_state::preserve)
    {
      first_enabled = std::find_if(first, last, [](const hook& item)
                                   { return item.enabled; });
      if (first_enabled != last)
      {
        if (!enabled_count)
          freeze.init(*this, true);
        else
          freeze.init();

        other_prev_poriginal = first_enabled->poriginal;
        first_enabled->redirect_original(current_this_poriginal);
        current_this_poriginal =
            std::find_if(std::reverse_iterator(last),
                         std::reverse_iterator(first),
                         [](const hook& item) { return item.enabled; })
                ->pdetour;
      }

      hooks.splice(newpos, other.hooks, first, last);
    }
    else
    {
      if (flags.filter != state_filter::any ||
          flags.target != target_state::preserve)
        rollback_data.reserve(hooks.size());

      for (iterator itr = first; itr != last;)
      {
        bool match = false;
        switch (flags.filter)
        {
        case state_filter::any: match = true; break;
        case state_filter::enabled: match = itr->enabled; break;
        case state_filter::disabled: match = !itr->enabled; break;
        }

        if (!match)
        {
          rollback_data.push_back({ itr, false, false });
          ++itr;
          continue;
        }

        bool will_be_enabled = false;
        switch (flags.target)
        {
        case target_state::preserve: will_be_enabled = itr->enabled; break;
        case target_state::enabled: will_be_enabled = true; break;
        case target_state::disabled: will_be_enabled = false; break;
        }

        // we will be initializing the freezer only when it's absolutely
        // necessary (since it's a heavy call). that is when state changes occur
        // or when the hook moved is enabled. so basically the freezer is not
        // initialized when moving a disabled and keeping it as disabled
        if (!freeze.initialized() &&
            (will_be_enabled != itr->enabled || itr->enabled))
        {
          if (!enabled_count)
            freeze.init(*this, true);
          else
            freeze.init();
        }

        if (!intra_splice)
        {
          itr->chain = *this;
          if (will_be_enabled)
            ++this_enabled_diff;
          if (itr->enabled)
            --other_enabled_diff;
        }
        else if (will_be_enabled != itr->enabled)
        {
          if (will_be_enabled)
            ++other_enabled_diff;
          else
            --other_enabled_diff;
        }

        if (!other_prev_poriginal && itr->enabled)
        {
          other_prev_poriginal = itr->poriginal;
          first_enabled        = itr;
        }

        if (will_be_enabled)
        {
          if (itr->poriginal != current_this_poriginal)
            itr->redirect_original(current_this_poriginal);
          current_this_poriginal = itr->pdetour;
        }

        if (rollback_data.capacity())
          rollback_data.push_back(
              { itr, true, will_be_enabled != itr->enabled });
        itr->enabled = will_be_enabled;
        hooks.splice(newpos, other.hooks, itr++);
      }

      if (first->enabled)
        first_enabled = first;
    }

    // unlink phase, only required if there was at least one enabled hook in the
    // range
    if (other_prev_poriginal)
    {
      // intra splice early exits: the following checks detect whether hooks
      // were actually rearranged
      if (intra_splice)
      {
        // if newpos >= last and it's true that no enabled hooks exist in the
        // range [last, newpos) then we can fix the broken first_enabled
        // redirection (points to last_enabled) currently and exit.
        if (this_prev_poriginal == current_this_poriginal)
        {
          first_enabled->redirect_original(other_prev_poriginal);
          enabled_count += other_enabled_diff;
          return;
        }
        // if newpos < first and it's true that no enabled hooks exist in the
        // range [newpos, first) we can just exit (provided that there wasn't
        // any hook that changed state at the end). pointer redirections were
        // setup correctly in the loop earlier.
        if (this_next_enabled == first_enabled &&
            (!rollback_data.capacity() || !rollback_data.back().changed_state))
        {
          enabled_count += other_enabled_diff;
          return;
        }
      }

      other_next_enabled = std::find_if(last, other.end(), [](const hook& item)
                                        { return item.enabled; });

      if (other_next_enabled != other.end())
        other_next_enabled->redirect_original(other_prev_poriginal);
      // we don't touch memory for intra splicing (for performance benefits and
      // to provide strong guarantee) unless all hooks in the container are left
      // as disabled and therefore this is the last part of the process
      else if (!intra_splice ||
               (other_enabled_diff < 0 &&
                enabled_count == static_cast<size_t>(-other_enabled_diff)))
      {
        try
        {
          if (other.enabled_count == static_cast<size_t>(-other_enabled_diff))
            other.inject(other.backup.data(), false);
          else
            other.patch(other_prev_poriginal);
        }
        catch (...)
        {
          splice_rollback(first, last, newpos, other, rollback_data,
                          other_prev_poriginal);
          throw;
        }
      }
    }

    // link phase: if the first enabled hook that was found within the range was
    // disabled then all of the rest did too. so if it's still enabled we
    // proceed linking
    if (first_enabled->enabled)
    {
      if (this_next_enabled != end())
        this_next_enabled->redirect_original(current_this_poriginal);
      else
      {
        try
        {
          if (!intra_splice && !enabled_count)
            inject(current_this_poriginal, true);
          else
            patch(current_this_poriginal);
        }
        catch (...)
        {
          splice_rollback(first, last, newpos, other, rollback_data,
                          other_prev_poriginal);

          // for intra splices no hard unlink ever happened, therefore providing
          // strong guarantee!
          if (intra_splice && other_next_enabled == other.end())
            throw;

          const auto rstop = std::reverse_iterator(first);
          const auto last_enabled =
              std::find_if(std::reverse_iterator(last), rstop,
                           [](const hook& item) { return item.enabled; });

          // there were no enabled hooks to link back!
          if (last_enabled == rstop)
            throw;
          if (other_next_enabled != other.end())
            other_next_enabled->redirect_original(last_enabled->pdetour);
          else
          {
            try
            {
              if (other.enabled_count ==
                  static_cast<size_t>(-other_enabled_diff))
                inject(last_enabled->pdetour, true);
              else
                patch(last_enabled->pdetour);
            }
            catch (...)
            {
              for (iterator itr = first; itr != last; ++itr)
                itr->enabled = false;
              throw;
            }
          }
          throw;
        }
      }
    }

    enabled_count       += this_enabled_diff;
    other.enabled_count += other_enabled_diff;
  }

  void hook_chain::set_target(std::byte* target)
  {
    if (ptarget == target)
      return;
    trampoline new_trampoline{ target };
    backup_t   old_backup = backup;
    if (enabled_count)
    {
      thread_freezer freeze{ *this, true };
      inject(backup.data(), false);
      std::swap(static_cast<trampoline&>(*this), new_trampoline);
      helpers::make_backup(ptarget, backup.data(), patch_above);
      try
      {
        inject(enabled_hooks().back().pdetour, true);
      }
      catch (...)
      {
        backup = old_backup;
        std::swap(static_cast<trampoline&>(*this), new_trampoline);
        try
        {
          inject(enabled_hooks().back().pdetour, true);
        }
        catch (...)
        {
          for (hook& item : *this)
            item.enabled = false;
          enabled_count = 0;
          throw;
        }
        throw;
      }

      enabled_hooks().front().redirect_original(get_original());
      return;
    }

    static_cast<trampoline&>(*this) = std::move(new_trampoline);
    helpers::make_backup(ptarget, backup.data(), patch_above);
  }

#if utils_clang
  #pragma clang diagnostic pop
#endif

  // hook_chain utilities

  void hook_chain::init_with_list(hook_init_range range, bool enable)
  {
    helpers::make_backup(ptarget, backup.data(), patch_above);
    const std::byte* original = get_original();

    for (auto init_list_itr = range.first; init_list_itr != range.second;
         ++init_list_itr)
    {
      auto& [detour, buffer] = *init_list_itr;
      const iterator entry_itr =
          hooks.emplace(hooks.end(), *this, detour, buffer, original, enable);
      entry_itr->current = entry_itr;
      original           = detour;
    }

    if (enable)
      enabled_count = hooks.size();
  }

  void hook_chain::initial_inject()
  {
    thread_freezer freezer{ *this, true };
    inject(hooks.back().pdetour, true);
  }

  hook_chain::list_range hook_chain::do_insert(iterator        pos,
                                               hook_init_range range,
                                               bool            auto_enable)
  {
    if (range.first == range.second)
      return { pos, pos };

    const iterator   range_prev     = pos != begin() ? std::prev(pos) : end();
    iterator         next_enabled   = end();
    const std::byte* prev_poriginal = nullptr;
    const bool       was_empty      = !enabled_count;
    size_t           enabled_added_count = 0;

    if (auto_enable)
    {
      if (was_empty)
        prev_poriginal = get_original();
      else
      {
        next_enabled = std::find_if(pos, end(), [](const hook& item)
                                    { return item.enabled; });
        prev_poriginal =
            next_enabled != end()
                ? next_enabled->poriginal
                : std::find_if(std::reverse_iterator(pos), rend(),
                               [](const hook& item) { return item.enabled; })
                      ->pdetour;
      }
    }

    try
    {
      for (auto init_itr = range.first; init_itr != range.second; ++init_itr)
      {
        iterator itr =
            hooks.emplace(pos, *this, init_itr->first, init_itr->second,
                          prev_poriginal, auto_enable);
        itr->current = itr;
        if (auto_enable)
        {
          prev_poriginal = itr->pdetour;
          ++enabled_added_count;
        }
      }

      const iterator range_begin =
          range_prev != end() ? std::next(range_prev) : begin();

      if (auto_enable)
      {
        thread_freezer freeze{ defer_freeze };
        if (was_empty)
          freeze.init(*this, true);
        else
          freeze.init();

        if (next_enabled != end())
          next_enabled->redirect_original(prev_poriginal);
        else if (was_empty)
          inject(prev_poriginal, true);
        else
          patch(prev_poriginal);
      }

      enabled_count += enabled_added_count;
      return { range_begin, pos };
    }
    catch (...)
    {
      const iterator range_begin =
          range_prev != end() ? std::next(range_prev) : begin();
      hooks.erase(range_begin, pos);
      throw;
    }
  }

  size_t hook_chain::do_erase_if(iterator first, iterator last,
                                 state_filter                      filter,
                                 predicate_view<bool(const hook&)> predicate)
  {
    if (first == last)
      return 0;

    thread_freezer        freeze{ defer_freeze };
    std::vector<iterator> to_erase;
    const std::byte*      current_poriginal     = nullptr;
    bool                  tip_changed           = false;
    size_t                enabled_removed_count = 0;

    for (iterator itr = first; itr != last; ++itr)
    {
      if (!current_poriginal && itr->enabled)
        current_poriginal = itr->poriginal;

      bool match = false;
      switch (filter)
      {
      case state_filter::any: match = true; break;
      case state_filter::enabled: match = itr->enabled; break;
      case state_filter::disabled: match = !itr->enabled; break;
      }

      bool erased_enabled_entry = false;
      if (match && (!predicate || predicate(*itr)))
      {
        if (!to_erase.capacity())
          to_erase.reserve(hooks.size());
        to_erase.push_back(itr);
        if (itr->enabled)
        {
          if (!freeze.initialized())
            freeze.init();
          ++enabled_removed_count;
          erased_enabled_entry = true;
        }
      }

      if (itr->enabled)
      {
        if (!erased_enabled_entry)
        {
          if (itr->poriginal != current_poriginal)
            itr->redirect_original(current_poriginal);
          current_poriginal = itr->pdetour;
        }

        // what we did with the last enabled dictates whether the tip changed
        tip_changed = erased_enabled_entry;
      }
    }

    if (to_erase.empty())
      return 0;

    if (tip_changed)
    {
      try
      {
        if (enabled_removed_count == enabled_count)
          inject(backup.data(), false);
        else
        {
          const iterator next_enabled = std::find_if(
              last, end(), [](const hook& item) { return item.enabled; });
          if (next_enabled != end())
            next_enabled->redirect_original(current_poriginal);
          else
            patch(current_poriginal);
        }
      }
      catch (...)
      {
        current_poriginal = nullptr;

        for (iterator itr = first; itr != last; ++itr)
        {
          if (!itr->enabled)
            continue;
          if (!current_poriginal)
          {
            current_poriginal = itr->pdetour;
            continue;
          }
          if (itr->poriginal != current_poriginal)
            itr->redirect_original(current_poriginal);
          current_poriginal = itr->pdetour;
        }
        throw;
      }
    }

    for (iterator itr : to_erase)
      hooks.erase(itr);
    enabled_count -= enabled_removed_count;
    return to_erase.size();
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

    const iterator next_enabled =
        std::find_if(std::next(current), chain.get().end(),
                     [](const hook& item) { return item.enabled; });

    thread_freezer freeze;

    if (next_enabled != chain.get().end())
      next_enabled->redirect_original(detour);
    else
      chain.get().patch(detour);
    pdetour = detour;
  }

  void hook_chain::hook::set_original(
      const helpers::original_ref_handler& new_original_ref)
  {
    if (original_ref.same_reference(new_original_ref))
      return;
    if (!enabled)
    {
      original_ref = new_original_ref;
      original_ref.bind_original(poriginal);
      return;
    }

    thread_freezer freeze;
    original_ref.unbind_original();
    original_ref = new_original_ref;
    original_ref.bind_original(poriginal);
  }
} // namespace alterhook

#pragma clang diagnostic pop
