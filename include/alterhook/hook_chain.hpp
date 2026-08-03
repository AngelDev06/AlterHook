/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include <algorithm>
#include <iterator>
#include <list>
#include <tuple>
#include <type_traits>
#include <utility>
#include "detail/injectable.hpp"
#include "hook.hpp"
#include "tools.hpp"
#include "utilities/concepts.hpp"
#include "utilities/index_sequence.hpp"
#include "utilities/macros.hpp"
#include "utilities/other.hpp"
#include "utilities/type_sequence.hpp"

#if utils_msvc
  #pragma warning(push)
  #pragma warning(disable : 4251 4715)
#elif utils_clang
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wreturn-type"
  #pragma clang diagnostic ignored "-Wnon-virtual-dtor"
#endif

namespace alterhook
{
  struct defer_enable_t
  {
    explicit constexpr defer_enable_t() = default;
  };

  inline constexpr defer_enable_t defer_enable{};

  /**
   * @brief A class representing a chain of inline hooks with (possibly)
   * different **detour**, **original callback** and **status** but same
   * **trampoline function** and **target**.
   *
   * The hooks are linked together with the **original callback** of the
   * previous hook leading to the **detour** of the next one, till the final
   * hook calls back the trampoline function. The container is responsible for
   * maintaining the chain of inline hooks as well as allow anyone to:
   * - add new hooks (at any position)
   * - erase hooks
   * - reorder the hooks
   * - change the status of the hooks (i.e. enabled/disabled)
   * - iterate over the enabled or disabled hooks individually or through all of
   *   them at once.
   *
   * The container is designed so that all of the operations mentioned above do
   * not invalidate/break any hooks unless it's explicitly requested (e.g. by
   * disabling a hook or erasing it entirely). This was made possible by
   * dynamically modifying the target function or hooks nearby the affected ones
   * so that execution flow continues normally without unwanted side effects.
   * The underlying structure consists of two linked lists, one for the enabled
   * hooks and one for the disabled ones. The order in which the detours of the
   * enabled hooks are invoked is **always** the reverse of the
   * **iteration order**.
   */
  class ALTERHOOK_API hook_chain : trampoline,
                                   detail::injectable<hook_chain>
  {
  public:
    class ALTERHOOK_API hook;

    template <bool enabled, typename adapted_itr_t, typename adapted_chain_t>
    class filter_view;
    /// @brief An enum class that acts as a tag to control the target list of
    /// the algorithms provided. Note that in some cases `both` isn't accepted
    /// so it is advised to refer to the documentation before using it.
    enum class state_filter
    {
      disabled,
      enabled,
      any
    };
    enum class target_state
    {
      disabled,
      enabled,
      preserve
    };

    struct splicer_flags
    {
      state_filter filter = state_filter::any;
      target_state target = target_state::preserve;
    };

    /// Alias of @ref alterhook::hook_chain::transfer
    using allocator_type = typename helpers::alloc_wrapper<
        std::allocator>::template allocator<hook>;
    using hook_list = std::list<hook, allocator_type>;

    /**
     * @name List Iterators
     * @brief A group of bidirectional iterators that make it possible to loop
     * over the enabled or disabled hooks individually in the order they were
     * inserted to their corresponding lists.
     *
     * As already mentioned an instance of @ref alterhook::hook_chain consists
     * of two lists, one for the enabled and one for the disabled hooks. The
     * iterators in this group are just iterators to one of the two lists
     * provided by the standard library. They are only invalidated when their
     * corresponding hook is erased.
     * @note The order in which elements appear when looping over the container
     * using an iterator of this group is often referred to by the documentation
     * as the **list iteration order** (i.e. the insertion order to the
     * corresponding list). This order is affected by both changes to the status
     * of the hooks (as they move from one list to another) and by any explicit
     * changes to the order of the corresponding list (using the available api).
     * @{
     */

    using const_iterator         = hook_list::const_iterator;
    using iterator               = hook_list::iterator;
    using const_reverse_iterator = hook_list::const_reverse_iterator;
    using reverse_iterator       = hook_list::reverse_iterator;
    using enabled_view           = filter_view<true, iterator, hook_chain>;
    using const_enabled_view =
        filter_view<true, const_iterator, const hook_chain>;
    using disabled_view = filter_view<false, iterator, hook_chain>;
    using const_disabled_view =
        filter_view<false, const_iterator, const hook_chain>;

    /// @}

    using value_type      = hook;
    using size_type       = size_t;
    using difference_type = ptrdiff_t;
    using pointer         = hook*;
    using const_pointer   = const hook*;
    using reference       = hook&;
    using const_reference = const hook&;
    using list_range      = std::pair<iterator, iterator>;

    /**
     * @name Constructors with Target and Detour/Original Callback pairs
     * @brief Takes in the Target and a variable amount of detour/original
     * callback pairs constructing a hook with each of them in the order they
     * are passed. It then enables all hooks.
     *
     * There are two ways to forward the detour and the original callback pairs
     * to the constructor. One is by passing them sequentially and the other is
     * by grouping them into @ref alterhook::utils::tuple_like "tuple-like" or
     * @ref alterhook::utils::pair_like "pair-like" objects.
     * @par Sequential Forwarding
     * @code{.cpp}
     * alterhook::hook_chain chain{ &originalcls::func,
     *                              &detourcls::func, original,
     *                              &detourcls::func2, original2,
     *                              &detourcls::func3, original3 };
     * @endcode
     * @par Grouped in Tuples
     * @code{.cpp}
     * alterhook::hook_chain chain{
     *     &originalcls::func,
     *     std::forward_as_tuple(&detourcls::func, original),
     *     std::forward_as_tuple(&detourcls::func2, original2),
     *     std::forward_as_tuple(&detourcls::func3, original3)
     * };
     * @endcode
     *
     * All hooks will be added to the enabled list in the order they are passed
     * and will therefore be enabled after construction is finished.
     * @par Exceptions
     * - @ref trampoline-init-exceptions
     * - @ref thread-freezer-exceptions
     * - @ref target-injection-exceptions
     * @{
     */

    /// @brief Construct with a raw pointer to the target and a sequence of
    /// detour and original callbacks
    template <typename dtr, typename orig, typename... types,
              typename = std::enable_if_t<
                  utils::detours_and_originals<dtr, orig&, types...>>>
    hook_chain(std::byte* target, dtr&& detour, orig& original,
               types&&... rest);

    template <typename dtr, typename orig, typename... types,
              typename = std::enable_if_t<
                  utils::detours_and_originals<dtr, orig&, types...>>>
    hook_chain(defer_enable_t, std::byte* target, dtr&& detour, orig& original,
               types&&... rest);

    /// Construct with target and a sequence of detour and original callbacks
    template <typename trg, typename dtr, typename orig, typename... types,
              typename = std::enable_if_t<
                  utils::callable_type<trg> &&
                  utils::detours_and_originals<dtr, orig&, types...>>>
    hook_chain(trg&& target, dtr&& detour, orig& original, types&&... rest);

    template <typename trg, typename dtr, typename orig, typename... types,
              typename = std::enable_if_t<
                  utils::callable_type<trg> &&
                  utils::detours_and_originals<dtr, orig&, types...>>>
    hook_chain(defer_enable_t, trg&& target, dtr&& detour, orig& original,
               types&&... rest);

    /// @brief Construct with a raw pointer to the target and a sequence of
    /// @ref alterhook::utils::pair_like "pair-like" objects holding the detour
    /// and the original callbacks.
    template <typename pair, typename... types,
              typename = std::enable_if_t<
                  utils::detour_and_original_pairs<pair, types...>>>
    hook_chain(std::byte* target, pair&& first, types&&... rest);

    template <typename pair, typename... types,
              typename = std::enable_if_t<
                  utils::detour_and_original_pairs<pair, types...>>>
    hook_chain(defer_enable_t, std::byte* target, pair&& first,
               types&&... rest);

    /// @brief Construct with the target and a sequence of
    /// @ref alterhook::utils::pair_like "pair-like" objects holding the detour
    /// and the original callbacks.
    template <typename trg, typename pair, typename... types,
              typename = std::enable_if_t<
                  utils::callable_type<trg> &&
                  utils::detour_and_original_pairs<pair, types...>>>
    hook_chain(trg&& target, pair&& first, types&&... rest);

    template <typename trg, typename pair, typename... types,
              typename = std::enable_if_t<
                  utils::callable_type<trg> &&
                  utils::detour_and_original_pairs<pair, types...>>>
    hook_chain(defer_enable_t, trg&& target, pair&& first, types&&... rest);

    /// @}

    /**
     * @brief Construct with just a raw pointer to the target leaving the
     * container empty.
     *
     * @par Exceptions
     * - @ref trampoline-init-exceptions
     */
    hook_chain(std::byte* target);

    /**
     * @brief Construct with just the target leaving the container empty.
     *
     * @par Exceptions
     * - @ref trampoline-init-exceptions
     */
    template <typename trg,
              typename = std::enable_if_t<utils::callable_type<trg>>>
    hook_chain(trg&& target)
        : hook_chain(get_target_address(std::forward<trg>(target)))
    {
    }

    /**
     * @brief Moves all contents of `other` to `*this` leaving `other`
     * uninitialized. The hooks are moved into their respective lists in the
     * same order therefore retaining their state (i.e. enabled or disabled)
     * @param other the chain to move from
     */
    hook_chain(hook_chain&& other) noexcept;

    /**
     * @brief Construct by moving an instance of @ref alterhook::hook to the
     * chain. The hook that is moved will remain enabled if it was before
     * construction.
     *
     * This does not require any extra arguments as it claims ownership of
     * everything `other` holds including the original callback. It can
     * therefore be used as a conversion constructor.
     */
    hook_chain(alterhook::hook&& other);

    /**
     * @brief Construct with a copy of an @ref alterhook::trampoline instance
     *
     * @par Exceptions
     * - @ref trampoline-copy-exceptions
     */
    hook_chain(const trampoline& other) : trampoline(other)
    {
      helpers::make_backup(ptarget, backup.data(), patch_above);
    }

    /// Construct by moving an @ref alterhook::trampoline instance to the chain.
    hook_chain(trampoline&& other) noexcept : trampoline(std::move(other))
    {
      helpers::make_backup(ptarget, backup.data(), patch_above);
    }

    /// @brief Default constructs the chain leaving it target-less and therefore
    /// uninitialized
    hook_chain() noexcept = default;

    ~hook_chain() noexcept;

    /**
     * @brief Disables all hooks from `*this` and moves both lists from `other`
     * to `*this`. It will also copy the target and move the trampoline.
     * @param other the chain to move from
     * @returns `*this`
     */
    hook_chain& operator=(hook_chain&& other) noexcept;

    /**
     * @brief Replaces the current trampoline with a copy of `other` redirecting
     * the stored hooks to a new target if needed.
     * @param other the trampoline to copy into `*this`
     * @returns `*this`
     * @par Exceptions
     * - @ref trampoline-copy-exceptions
     * - @ref thread-freezer-exceptions
     * - @ref target-injection-exceptions
     * @par Exception Guarantee
     * Exactly the same as with the
     * @ref alterhook::hook_chain::operator=(const hook_chain&)
     * "copy assignment operator"
     */
    hook_chain& operator=(const trampoline& other);

    /**
     * @brief Replace the current trampoline by moving `other` into `*this`. All
     * hooks will be redirected to the new target (if needed) and will retain
     * their state (i.e. enabled or disabled)
     * @param other the trampoline to replace the current one with
     * @returns `*this`
     * @par Exceptions
     * - @ref thread-freezer-exceptions
     * - @ref target-injection-exceptions
     * @par Exception Guarantee
     * - strong: Only when an attempt to disable any enabled hooks failed, in
     *   which case it belongs to either of the groups @ref
     *   thread-freezer-exceptions or @ref target-injection-exceptions or when
     *   there are no enabled hooks in the container.
     * - basic: In any other case the container will stay initialized but with
     *   all hooks disabled (including the ones that were previously enabled).
     */
    hook_chain& operator=(trampoline&& other);

    /**
     * @name Status Updaters
     * @brief Special methods used to change the status of all hooks that
     * currently have a different status. If all hooks have the same status as
     * the target one then no operation is done.
     *
     * It should be mentioned that none of these operations affect the
     * **iteration order** but only the **list iteration order** as it implies
     * moving hooks from one list to another. It will however invalidate any
     * iterators that refer to the target list since they are not notified about
     * the change in status.
     * @par Exceptions
     * - @ref thread-freezer-exceptions
     * - @ref target-injection-exceptions
     * @{
     */

    /// Enables all hooks that are currently disabled in the container
    size_t enable_all() { return set_status_range(begin(), end(), true); }

    /// Disables all hooks that are currently enabled in the container
    size_t disable_all() { return set_status_range(begin(), end(), false); }

    size_t enable(iterator first, iterator last)
    {
      return set_status_range(first, last, true);
    }

    size_t disable(iterator first, iterator last)
    {
      return set_status_range(first, last, false);
    }

    template <typename callable,
              typename = std::enable_if_t<
                  std::is_invocable_r_v<bool, callable&, const hook&>>>
    size_t enable_if(iterator first, iterator last, callable&& predicate)
    {
      return set_status_range(first, last, true, predicate);
    }

    template <typename callable,
              typename = std::enable_if_t<
                  std::is_invocable_r_v<bool, callable&, const hook&>>>
    size_t disable_if(iterator first, iterator last, callable&& predicate)
    {
      return set_status_range(first, last, false, predicate);
    }

    template <typename callable,
              typename = std::enable_if_t<
                  std::is_invocable_r_v<bool, callable&, const hook&>>>
    size_t enable_if(callable&& predicate)
    {
      return enable_if(begin(), end(), predicate);
    }

    template <typename callable,
              typename = std::enable_if_t<
                  std::is_invocable_r_v<bool, callable&, const hook&>>>
    size_t disable_if(callable&& predicate)
    {
      return disable_if(begin(), end(), predicate);
    }

    /// @}

    /**
     * @name Hook Erasers
     * @brief Methods used to erase one or more hooks from the container
     * entirely, meaning they will both be disabled and deleted afterwards.
     * @par Exceptions
     * - @ref thread-freezer-exceptions
     * - @ref target-injection-exceptions
     * @warning Erasing from an empty list or passing an invalidated iterator
     * (or an invalid range) will lead to **undefined behaviour**. Despite that
     * assertions are generally provided for debug builds to prevent certain
     * situations (such as popping from an empty container).
     * @{
     */

    /**
     * @brief Cleanup a specific list or the container entirely, meaning all
     * hooks from one or both lists will be erased.
     * @param trg specifies the list to erase the hooks from (defaults to both)
     */
    void clear(state_filter target = state_filter::any);
    /**
     * @brief Erases either the last hook from the container (the last in
     * iteration order) or the last in one of the two lists.
     * @param trg specifies the list from which the last hook will be erased or
     * when set to 'both' it removes the last one in iteration order (i.e. the
     * last one from the container) which is the default behaviour.
     */
    void pop_back(state_filter target = state_filter::any);
    /**
     * @brief Erases either the first hook from the container (the first in
     * iteration order) or the first in one of the two lists.
     * @param target specifies the list from which the first hook will be erased
     * or when set to 'both' it removes the first one in iteration order (i.e.
     * the first one from the container) which is the default behaviour.
     */
    void pop_front(state_filter target = state_filter::any);

    /**
     * @brief Erases a single hook at the position specified by `position`.
     * @param position the list iterator to the hook that will be erased.
     * @returns a list iterator to the hook that follows the one pointed to by
     * `position` in list iteration order
     */
    size_t erase(iterator position)
    {
      return erase(position, std::next(position), state_filter::any);
    }

    /**
     * @brief Erases all hooks in the range [first, last) in list iteration
     * order.
     * @param first the beginning of the range (also included in the range)
     * @param last the end of the range (not included in the range)
     * @returns `last`
     */
    size_t erase(iterator first, iterator last,
                 state_filter filter = state_filter::any)
    {
      return do_erase_if(first, last, filter);
    }

    template <typename callable,
              typename = std::enable_if_t<
                  std::is_invocable_r_v<bool, callable&, const hook&>>>
    size_t erase_if(iterator first, iterator last, state_filter filter,
                    callable&& predicate)
    {
      return do_erase_if(first, last, filter, predicate);
    }

    template <typename callable,
              typename = std::enable_if_t<
                  std::is_invocable_r_v<bool, callable&, const hook&>>>
    size_t erase_if(iterator first, iterator last, callable&& predicate)
    {
      return do_erase_if(first, last, state_filter::any, predicate);
    }

    template <typename callable,
              typename = std::enable_if_t<
                  std::is_invocable_r_v<bool, callable&, const hook&>>>
    size_t erase_if(state_filter filter, callable&& predicate)
    {
      return do_erase_if(begin(), end(), filter, predicate);
    }

    template <typename callable,
              typename = std::enable_if_t<
                  std::is_invocable_r_v<bool, callable&, const hook&>>>
    size_t erase_if(callable&& predicate)
    {
      return do_erase_if(begin(), end(), state_filter::any, predicate);
    }

    /// @}

    /**
     * @name Inserters
     * @brief Methods useful for inserting one or more hooks into the container
     * at any position.
     *
     * Methods that accept variable amount of arguments allow the same syntax
     * that the constructors do, i.e. both sequential forwarding and grouping
     * arguments in tuple-like objects.
     * @par Exceptions
     * - @ref thread-freezer-exceptions
     * - @ref target-injection-exceptions
     * @note For the append methods, the value `transfer::both` is not accepted
     * and therefore debug assertions are put to prevent such incorrect usage.
     * @{
     */

    /**
     * @brief Insert a single hook at the end of the container and sets its
     * state as either enabled or disabled.
     * @param detour the detour of the hook
     * @param original the reference to the original callback of the hook
     * @param enable_hook whether to enable the hook
     * @returns A reference to the inserted hook.
     */
    template <
        typename dtr, typename orig,
        typename = std::enable_if_t<utils::detours_and_originals<dtr, orig&>>>
    hook& push_back(dtr&& detour, orig& original, bool enable_hook = true);

    /**
     * @brief Insert a single hook at the beginning of the container and sets
     * its state as either enabled or disabled.
     * @param detour the detour of the hook
     * @param original the reference to the original callback of the hook
     * @param enable_hook whether to enable the hook
     * @returns A reference to the inserted hook.
     */
    template <
        typename dtr, typename orig,
        typename = std::enable_if_t<utils::detours_and_originals<dtr, orig&>>>
    hook& push_front(dtr&& detour, orig& original, bool enable_hook = true);

    template <typename dtr, typename orig, typename... types,
              typename = std::enable_if_t<
                  utils::detours_and_originals<dtr, orig&, types...>>>
    list_range insert(iterator pos, dtr&& detour, orig& original,
                      types&&... rest);

    template <typename dtr, typename orig, typename... types,
              typename = std::enable_if_t<
                  utils::detours_and_originals<dtr, orig&, types...>>>
    list_range insert(defer_enable_t, iterator pos, dtr&& detour,
                      orig& original, types&&... rest);

    template <typename pair, typename... types,
              typename = std::enable_if_t<
                  utils::detour_and_original_pairs<pair, types...>>>
    list_range insert(iterator pos, pair&& first, types&&... rest);

    template <typename pair, typename... types,
              typename = std::enable_if_t<
                  utils::detour_and_original_pairs<pair, types...>>>
    list_range insert(defer_enable_t, iterator pos, pair&& first,
                      types&&... rest);

    /// @}

    /**
     * @name Swappers
     * @brief Methods for swapping two elements from within or across containers
     * and for swapping the whole containers.
     * @par Exceptions
     * - @ref thread-freezer-exceptions
     * - @ref target-injection-exceptions
     * @warning None of these methods accept the end iterator as a valid
     * argument. Therefore passing it will result in **undefined behaviour** and
     * no checks are done to ensure the iterator is valid.
     * @{
     */

    /**
     * @brief Swaps `left` from `*this` and `right` from `other`.
     * @param left a list iterator to the element of the current container
     * @param other the container to which the element referred to by `right`
     * belongs
     * @param right a list iterator to the other element to be swapped
     * @par Exception Guarantee
     * - strong:
     *   + The exception is of group @ref thread-freezer-exceptions
     *   + Only one of the hooks is enabled and the exception is of group
     *     @ref target-injection-exceptions
     *   + Both hooks are enabled and during the injection of the first one to
     *     the new location, an exception of group @ref
     *     target-injection-exceptions was raised.
     *   + Both hooks are enabled and during the injection of the second one to
     *     the new location, an exception of group @ref
     *     target-injection-exceptions. However if the attempt to inject the
     *     first hook back to its original location was successful then strong
     *     guarantee is provided.
     * - none: When the situation is the same as the fourth case of the strong
     *   guarantee but the attempt of injecting back the first hook was
     *   unsuccessful.
     */
    void swap(iterator left, hook_chain& other, iterator right);

    /**
     * @brief Swaps `left` with `right`. Both iterators should point to elements
     * of the current container, otherwise the @ref
     * alterhook::hook_chain::swap(iterator,hook_chain&,iterator)
     * "other overload" should be used.
     * @param left a list iterator to the first element to be swapped
     * @param right a list iterator to the second element to be swapped
     */
    void swap(iterator left, iterator right) { swap(left, *this, right); }

    /**
     * @brief Swaps the current container with `other`. Unlike `std::swap` this
     * one only swaps the two lists and therefore the enabled hooks of each
     * container are redirected to their new target and trampoline.
     * @param other the container to swap with
     * @par Exception Guarantee
     * Same as @ref
     * alterhook::hook_chain::swap(iterator,hook_chain&,iterator)
     * "the other overload" except in this case it depends on whether the
     * containers have any enabled hooks.
     */
    void swap(hook_chain& other);

    /// @}

    /**
     * @name Splicers
     * @brief Powerful methods used to transfer a single or a range of hooks
     * from one location to another. This works both across lists of the same
     * container and across containers.
     *
     * A few things to note about the splicers:
     * - The state of the hooks that are moved will change according to the list
     *   they are transferred to. For example transferring a range of hooks from
     *   the enabled list to the disabled one will disable them.
     * - The hooks are always placed right before the target location and not
     *   after it. However they will be placed after any hooks that precede the
     *   target location in **iteration order**.
     * - The target location can be the end iterator. Because of this for any
     *   splicers that accept a list iterator as the target, an additional
     *   argument should be passed that specifies whether the target is the
     *   enabled or the disabled list (that is the `to` argument). However if
     *   the value passed is incorrect the behaviour is undefined.
     * @par Exceptions
     * - @ref thread-freezer-exceptions
     * - @ref target-injection-exceptions
     * @par Exception Guarantee
     * - strong:
     *   + When an attempt to uninject any enabled hooks from their original
     *     location failed in which case the exception should be of group @ref
     *     thread-freezer-exceptions or @ref target-injection-exceptions
     *   + Injecting the hooks to their new location failed but reverting the
     *     operation was successful (i.e. the hooks were moved back to their
     *     original location)
     *   + If no injection needs to occur at all (i.e. when no enabled hooks are
     *     involved and the target is a disabled list) then strong guarantee is
     *     always provided as no exceptions are ever thrown.
     * - basic: When the situation is the same as the second case of the strong
     *   guarantee but the attempt to inject back the hooks to their original
     *   location was unsuccessful. If that happens then the hooks remain in the
     *   same container but in the disabled state and therefore they are
     *   transferred to the respective disabled list while also maintaining the
     *   iteration order. Whether that is the case can easily be determined by
     *   just checking if the exception raised is nested (i.e. it inherits from
     *   [std::nested_exception](https://en.cppreference.com/w/cpp/error/nested_exception)).
     *   Utilities like
     *   [std::rethrow_if_nested](https://en.cppreference.com/w/cpp/error/rethrow_if_nested)
     *   are recommended for this case.
     * @{
     */

    /**
     * @brief Transfers all hooks from one or both lists of `other` to `newpos`.
     * @param newpos the location before which the hooks of `other` will be
     * placed
     * @param other the container from which hooks will be transferred (it
     * cannot be the current container)
     * @param to specifies which list `newpos` refers to
     * @param from specifies from which list to transfer the hooks, or when set
     * to `both` transfers the whole container
     */
    void splice(iterator newpos, hook_chain& other, splicer_flags flags = {})
    {
      splice(newpos, other, other.begin(), other.end(), flags);
    }

    /**
     * @brief Transfers a single hook referred to by `oldpos` to `newpos`
     * @param newpos the target location
     * @param other the container from which the hook will be transferred
     * @param oldpos the list iterator to the hook that will be transferred
     * @param to specifies which list `newpos` refers to
     */
    void splice(iterator newpos, hook_chain& other, iterator oldpos,
                target_state target = target_state::preserve)
    {
      splice(newpos, other, oldpos, std::next(oldpos),
             { state_filter::any, target });
    }

    /**
     * @brief Transfers the range of hooks [first, last) to `newpos`.
     * @param newpos the target location
     * @param other the container from which the range will be transferred
     * @param first the beginning of the range (also included in the range)
     * @param last the end of the range (not included in the range)
     * @param to specifies which list `newpos` refers to
     * @note The range [first, last) is in **list iteration order** and
     * therefore refers to a range of hooks in the same list (which means same
     * state). Any other hooks that are in between this range in
     * **iteration order** but in a different list will not be included in the
     * range.
     */
    void splice(iterator newpos, hook_chain& other, iterator first,
                iterator last, splicer_flags flags = {});

    /// @brief Calls the @ref
    /// splice(iterator,hook_chain&,iterator,transfer)
    /// "other overload" with `other` set to `*this`.
    void splice(iterator newpos, iterator oldpos,
                target_state target = target_state::preserve)
    {
      splice(newpos, *this, oldpos, target);
    }

    /// @brief Calls the @ref
    /// splice(iterator,hook_chain&,iterator,iterator,transfer)
    /// "other overload" with `other` set to `*this`.
    void splice(iterator newpos, iterator first, iterator last,
                splicer_flags flags = {})
    {
      splice(newpos, *this, first, last, flags);
    }

    /// @}

    /**
     * @name Element Accessors
     * @brief A few useful methods for accessing specific hooks in the
     * container.
     *
     * Note that methods and overloads for accessing elements at random
     * positions will require iterating over the container till the position is
     * reached. Therefore they should be avoided when possible as they can be
     * costly for performance. The rest of those methods have constant time
     * complexity.
     * @warning All of these methods except the @ref at(size_t) "at methods"
     * will lead to **undefined behaviour** when accessing non-existing
     * elements.
     * @{
     */

    /// Access the first hook.
    reference front() noexcept { return *begin(); }

    /// Const version of @ref front().
    const_reference front() const noexcept { return *begin(); }

    /// Const version of @ref front().
    const_reference cfront() const noexcept { return front(); }

    /// Access the last hook.
    reference back() noexcept { return *std::prev(end()); }

    /// Const version of @ref back().
    const_reference back() const noexcept { return *std::prev(end()); }

    /// Const version of @ref back().
    const_reference cback() const noexcept { return back(); }

    /// @}

    /**
     * @name Target Setters
     * @brief Setters for initializing the container or redirecting it to a new
     * target (if previously initialized).
     *
     * If the chain is already initialized and contains any enabled hooks, it
     * makes sure to temporarily disable them and re-enable them after the
     * trampoline is updated based on the new target. This of course means that
     * the hooks will have been removed from the previous target and applied to
     * the new one after the operation is finished.
     * @par Exceptions
     * - @ref trampoline-init-exceptions
     * - @ref thread-freezer-exceptions
     * - @ref target-injection-exceptions
     * @par Exception Guarantee
     * - strong:
     *   + The container has any enabled hooks and an attempt to disable them
     *     failed.
     *   + The container does NOT have any enabled hooks and the exception
     *     thrown is of group @ref memalloc-and-address-validation.
     *   + The container has enabled hooks, the exception thrown is of group
     *     @ref memalloc-and-address-validation and an attempt to re-enable the
     *     disabled hooks in order to undo the operation was successful.
     * - basic:
     *   + If the situation is the same as the third case of the strong
     *     guarantee except the attempt to re-enable the hooks was unsuccessful,
     *     then the hooks are left as disabled and a nested exception is thrown
     *     that includes both errors. The trampoline is left untouched and
     *     therefore the target has not been updated.
     *   + Otherwise the trampoline is reset and therefore the chain will be
     *     uninitialized (i.e. with target set to null). The hooks that were
     *     enabled before will remain in the container but will be moved to the
     *     disabled list while keeping the same order.
     * @{
     */

    void set_target(std::byte* target);

    template <typename trg,
              typename = std::enable_if_t<utils::callable_type<trg>>>
    void set_target(trg&& target)
    {
      set_target(get_target_address(std::forward<trg>(target)));
    }

    /// @}

    /**
     * @name Getters
     * @brief Getters that return useful information about the container such as
     * its size or the target it's initialized with.
     * @{
     */

    /// Returns whether the container is empty.
    bool empty() const noexcept { return hooks.empty(); }

    /// Returns `true` when the container is non-empty, `false` otherwise.
    explicit operator bool() const noexcept { return !empty(); }

    /// Returns the size of the container (i.e. the number of hooks)
    size_t size() const noexcept { return hooks.size(); }

    /// Returns the result of @ref alterhook::trampoline::size.
    size_t trampoline_size() const noexcept { return trampoline::size(); }

    /// Returns the result of @ref alterhook::trampoline::count.
    size_t trampoline_count() const noexcept { return trampoline::count(); }

    /// Returns the result of @ref alterhook::trampoline::str.
    std::string trampoline_str() const { return trampoline::str(); }

    using trampoline::get_target;

    /// @}

    /**
     * @name Iterator Accessors
     * @brief Methods for accessing all sorts of iterators provided by this
     * class.
     *
     * Regular iterators are for iterating over the whole container which
     * means both enabled and disabled hooks will appear in the order they were
     * inserted (i.e. the iteration order). List iterators are for iterating
     * over individual lists, which means only enabled or disabled hooks will
     * appear and in the order they were inserted in the specific list.
     * @par Naming Conventions
     * - `begin`: Methods with this suffix return an iterator to the beginning
     *   of the range.
     * - `end`: Methods with this suffix return an iterator to the end of the
     *   range.
     * - `e`: Stands for enabled. Methods with such prefix return a list
     *   iterator to the enabled list.
     * - `d`: Stands for disabled. Methods with such prefix return a list
     *   iterator to the disabled list.
     * - `r`: Stands for reverse. Methods with such prefix return a reversed
     *   version of the iterator that the method without the said prefix return.
     *   This means that the beginning of a reversed range starts from the end
     *   of the list and ends at the beginning of the list. Only provided for
     *   bidirectional iterators, so `rbegin` does not exist.
     * - `c`: Stands for const. Methods with such prefix return a const version
     *   of the iterator that the method without the said prefix return. A const
     *   iterator lets one read but not modify the element it references. These
     *   type of methods are useful for getting a const iterator from a
     *   non-const @ref alterhook::hook_chain instance as const instances always
     *   return const iterators.
     * @{
     */

    iterator begin() noexcept { return hooks.begin(); }

    iterator end() noexcept { return hooks.end(); }

    const_iterator begin() const noexcept { return hooks.begin(); }

    const_iterator end() const noexcept { return hooks.end(); }

    const_iterator cbegin() const noexcept { return hooks.cbegin(); }

    const_iterator cend() const noexcept { return hooks.cend(); }

    reverse_iterator rbegin() noexcept { return hooks.rbegin(); }

    reverse_iterator rend() noexcept { return hooks.rend(); }

    const_reverse_iterator rbegin() const noexcept { return hooks.rbegin(); }

    const_reverse_iterator rend() const noexcept { return hooks.rend(); }

    const_reverse_iterator crbegin() const noexcept { return hooks.crbegin(); }

    const_reverse_iterator crend() const noexcept { return hooks.crend(); }

    /// @}

    /**
     * @name Filtered View Getters
     * @brief Accessors for filtered views of the hooks based on their active
     * state.
     * @{
     */

    enabled_view       enabled_hooks() noexcept;
    const_enabled_view enabled_hooks() const noexcept;
    const_enabled_view const_enabled_hooks() const noexcept;

    disabled_view       disabled_hooks() noexcept;
    const_disabled_view disabled_hooks() const noexcept;
    const_disabled_view const_disabled_hooks() const noexcept;

    /// @}

  private:
    template <typename derived>
    friend class detail::injectable;

    template <state_filter filter>
    struct filtered_list_range;
    struct intra_swap_info;
    struct splicer_rollback_info;

    using backup_t = std::array<std::byte, detail::constants::backup_size>;
    using enabled_list_range  = filtered_list_range<state_filter::enabled>;
    using disabled_list_range = filtered_list_range<state_filter::disabled>;
    using any_list_range      = filtered_list_range<state_filter::any>;
    using rollback_t          = std::vector<splicer_rollback_info>;

    backup_t  backup{};
    hook_list hooks{};
    size_t    enabled_count = 0;

    template <bool auto_enable, size_t... d_indexes, size_t... o_indexes,
              typename... types>
    void init_chain(std::index_sequence<d_indexes...>,
                    std::index_sequence<o_indexes...>,
                    std::tuple<types...>&& args);
    template <bool auto_enable, typename... detours, typename... originals,
              size_t... indexes>
    void init_chain(
        std::index_sequence<indexes...>,
        std::pair<std::tuple<detours...>, std::tuple<originals...>>&& args);

    template <bool auto_enable, size_t... d_indexes, size_t... o_indexes,
              typename... types>
    list_range do_insert(std::index_sequence<d_indexes...>,
                         std::index_sequence<o_indexes...>, iterator pos,
                         std::tuple<types...>&& args);
    template <bool auto_enable, size_t... indexes, typename... detours,
              typename... originals>
    list_range do_insert(
        std::index_sequence<indexes...>, iterator pos,
        std::pair<std::tuple<detours...>, std::tuple<originals...>>&& args);

    void   inject_back_all();
    void   uninject_all();
    void   safe_uninject_all() noexcept;
    size_t set_status_range(iterator first, iterator last, bool new_state,
                            predicate_view<bool(const hook&)> predicate = {});
    void   unlink(iterator itr, const std::byte* new_poriginal,
                  bool update_memory);
    void link(iterator itr, const std::byte* new_poriginal, bool update_memory);
    bool cross_splice_requires_injection(iterator other_itr) const noexcept;
    void swap_raw(iterator& left, iterator left_next, hook_chain& other,
                  iterator& right, iterator right_next) noexcept;
    intra_swap_info analyse_intra_swap(iterator left,
                                       iterator right) const noexcept;
    void splice_disabled(iterator newpos, hook_chain& other, iterator first,
                         iterator last) noexcept;
    void splice_rollback(iterator first, iterator last, iterator newpos,
                         hook_chain& other, const rollback_t& rollback_data,
                         const std::byte* prev_poriginal) noexcept;

  protected:
    using hook_init_item =
        std::pair<const std::byte*, helpers::original_ref_handler>;
    using hook_init_iterator = const hook_init_item*;
    using hook_init_range = std::pair<hook_init_iterator, hook_init_iterator>;
    using hook_init_list  = std::initializer_list<hook_init_item>;

    trampoline& get_trampoline() { return *this; }

    const trampoline& get_trampoline() const { return *this; }

    void       init_with_list(hook_init_range range, bool enable);
    void       initial_inject();
    list_range do_insert(iterator pos, hook_init_range range, bool auto_enable);
    size_t     do_erase_if(iterator first, iterator last, state_filter filter,
                           predicate_view<bool(const hook&)> predicate = {});
  };

  /**
   * @brief A class representing a single element in the
   * @ref alterhook::hook_chain container
   *
   * This holds all information that is unique per hook in the hook chain
   * instance such as the **detour** and the reference to the
   * **original callback**. It also keeps track of its location in the container
   * which allows someone to directly enable/disable the hook from the api
   * provided.
   */
  class ALTERHOOK_API hook_chain::hook
  {
  public:
    /**
     * @name Status Updaters
     * @brief Update the status of the hook (i.e. from enabled to disabled and
     * vise versa). Does nothing if the target status is the same as the current
     * one.
     * @par Exceptions
     * - @ref thread-freezer-exceptions
     * - @ref target-injection-exceptions
     * @{
     */

    /// Enable the hook
    void enable()
    {
      if (enabled)
        return;
      chain.get().set_status_range(current, std::next(current), true);
    }

    /// Disable the hook
    void disable()
    {
      if (!enabled)
        return;
      chain.get().set_status_range(current, std::next(current), false);
    }

    /// @}

    /**
     * @name Iterator Getters
     * @brief Get iterators to the current hook instance (either normal or list
     * ones)
     * @{
     */

    iterator get_iterator() noexcept { return current; }

    const_iterator get_iterator() const noexcept { return current; }

    const_iterator get_const_iterator() const noexcept { return current; }

    /// @}

    /**
     * @name Getters
     * @brief Retrieve information about the current hook instance (such as the
     * detour and the status)
     * @{
     */

    /// Returns a reference to the chain this hook belongs to
    hook_chain& get_chain() const noexcept { return chain.get(); }

    /// Returns a raw pointer to the target of all hooks of the container
    std::byte* get_target() const noexcept { return chain.get().ptarget; }

    /// Returns a raw pointer to the detour of the current hook
    const std::byte* get_detour() const noexcept { return pdetour; }

    /// Returns `true` if the hook is enabled, `false` otherwise
    bool is_enabled() const noexcept { return enabled; }

    /// Same as @ref alterhook::hook_chain::hook::is_enabled
    explicit operator bool() const noexcept { return enabled; }

    /// @}

    /**
     * @name Setters
     * @brief Set/Update some of the hook's properties such as the detour and
     * the reference to the original callback
     * @{
     */

    /**
     * @brief Overrides the hook's detour with `detour`
     * @tparam dtr the callable type of the detour passed (must satisfy
     * @ref alterhook::utils::callable_type)
     * @param detour the detour to use
     * @returns `*this`
     *
     * @par Exceptions
     * - @ref thread-freezer-exceptions (only if currently enabled)
     * - @ref target-injection-exceptions (only if currently enabled)
     */
    template <typename dtr,
              typename = std::enable_if_t<utils::callable_type<dtr>>>
    hook& set_detour(dtr&& detour)
    {
      set_detour(get_target_address(std::forward<dtr>(detour)));
      return *this;
    }

    /**
     * @brief Sets `original` to the next function to call and sets the old
     * reference to `nullptr`
     * @tparam orig the function like type of `original` (must satisfy
     * @ref alterhook::utils::function_type)
     * @param original the new reference to the original callback to use
     * @returns `*this`
     *
     * @par Exceptions
     * - @ref thread-freezer-exceptions (only if currently enabled)
     */
    template <typename orig,
              typename = std::enable_if_t<utils::function_type<orig>>>
    hook& set_original(orig& original)
    {
      set_original(helpers::original_ref_handler(original));
      return *this;
    }

    /// @}

  private:
    friend class hook_chain;
    template <template <typename> typename alloc>
    friend struct helpers::alloc_wrapper;
    template <typename T, size_t N>
    friend class utils::static_vector;
    using chain_ref_t = std::reference_wrapper<hook_chain>;

    chain_ref_t                   chain;
    iterator                      current{};
    const std::byte*              pdetour   = nullptr;
    const std::byte*              poriginal = nullptr;
    helpers::original_ref_handler original_ref{};
    bool                          enabled = false;

    hook(const hook&)            = delete;
    hook& operator=(const hook&) = delete;

    template <typename orig,
              typename = std::enable_if_t<utils::function_type<orig>>>
    hook(hook_chain& chain, const std::byte* pdetour, orig& origref,
         const std::byte* poriginal = nullptr, bool enabled = false);
    hook(hook_chain& chain, const std::byte* detour,
         const helpers::original_ref_handler& original_ref,
         const std::byte* poriginal = nullptr, bool enabled = false);

    void redirect_original(const std::byte* original) noexcept
    {
      poriginal = original;
      original_ref.bind_original(poriginal);
    }

    void set_detour(std::byte* detour);
    void set_original(const helpers::original_ref_handler& original);
    void swap(hook& right);
  };

  template <bool enabled, typename adapted_itr_t, typename adapted_chain_t>
  class hook_chain::filter_view
  {
  public:
    class iterator
    {
    public:
#if utils_cpp20
      using iterator_concept = std::bidirectional_iterator_tag;
#endif
      using iterator_category = std::bidirectional_iterator_tag;
      using value_type        = typename adapted_itr_t::value_type;
      using difference_type   = ptrdiff_t;
      using pointer           = typename adapted_itr_t::pointer;
      using reference         = typename adapted_itr_t::reference;
      using const_iterator =
          typename filter_view<enabled, hook_chain::const_iterator,
                               const hook_chain>::iterator;

      explicit iterator() = default;

      iterator(const const_iterator& other) noexcept
          : itr(other.itr), pchain(other.pchain)
      {
      }

      reference operator*() const noexcept
      {
        assert_dereferencable();
        return *itr;
      }

      pointer operator->() const noexcept
      {
        assert_dereferencable();
        return itr.operator->();
      }

      iterator& operator++() noexcept
      {
        assert_forward_traversal();
        itr = std::find_if(std::next(itr), pchain->end(), [](reference item)
                           { return item.is_enabled() == enabled; });
        return *this;
      }

      iterator operator++(int) noexcept
      {
        iterator tmp = *this;
        operator++();
        return tmp;
      }

      iterator& operator--() noexcept
      {
        assert_usable();
        itr = assert_and_fix_backwards_traversal(std::find_if(
            std::reverse_iterator(itr), pchain->rend(),
            [](reference item) { return item.is_enabled() == enabled; }));
        return *this;
      }

      iterator operator--(int) noexcept
      {
        iterator tmp = *this;
        operator--();
        return tmp;
      }

      bool operator==(const iterator& other) const noexcept
      {
        assert_compatible(other);
        return itr == other.itr;
      }

      bool operator!=(const iterator& other) const noexcept
      {
        assert_compatible(other);
        return itr != other.itr;
      }

      adapted_itr_t get_underlying_iterator() const noexcept { return itr; }

      operator adapted_itr_t() const noexcept { return itr; }

    private:
      template <bool, typename, typename>
      friend class filter_view;
      friend class hook_chain;

      adapted_itr_t itr;
      hook_chain*   pchain = nullptr;

      explicit iterator(adapted_itr_t itr, hook_chain& chain) noexcept
          : itr(itr), pchain(&chain)
      {
        this->itr = std::find_if(this->itr, pchain->end(), [](reference item)
                                 { return item.is_enabled() == enabled; });
      }

      void assert_compatible(const iterator& other) const noexcept
      {
        utils_assert(
            pchain == other.pchain,
            "hook_chain::filter_view::iterator: iterators incompatible");
      }

      adapted_itr_t assert_and_fix_backwards_traversal(
          std::reverse_iterator<adapted_itr_t> r_found) const noexcept
      {
        utils_assert(r_found != pchain->rend(),
                     "hook_chain::filter_view::iterator: cannot decrement past "
                     "first valid element");
        return std::prev(r_found.base());
      }

      void assert_forward_traversal() const noexcept
      {
        assert_usable();
        utils_assert(
            itr != pchain->end(),
            "hook_chain::filter_view::iterator: cannot increment past end");
      }

      void assert_dereferencable() const noexcept
      {
        assert_usable();
        utils_assert(itr != pchain->end(),
                     "hook_chain::filter_view::iterator: cannot dereference "
                     "the end iterator");
      }

      void assert_usable() const noexcept
      {
        utils_assert(pchain, "hook_chain::filter_view::iterator: attempted use "
                             "of an uninitialized iterator");
        utils_assert(itr == pchain->end() || itr->is_enabled() == enabled,
                     "hook_chain::filter_view::iterator: cannot use logically "
                     "invalidated iterator");
      }
    };

    using reverse_iterator = std::reverse_iterator<iterator>;
    using value_type       = typename iterator::value_type;
    using pointer          = typename iterator::pointer;
    using reference        = typename iterator::reference;

    explicit filter_view(adapted_chain_t& chain) : chain(chain) {}

    size_t size() const noexcept
    {
      if constexpr (enabled)
        return chain.enabled_count;
      else
        return chain.hooks.size() - chain.enabled_count;
    }

    bool empty() const noexcept { return !size(); }

    explicit operator bool() const noexcept { return !empty(); }

    iterator begin() const noexcept { return iterator(chain.begin(), chain); }

    iterator end() const noexcept { return iterator(chain.end(), chain); }

    reverse_iterator rbegin() const noexcept { return reverse_iterator(end()); }

    reverse_iterator rend() const noexcept { return reverse_iterator(begin()); }

    reference front() const noexcept { return *begin(); }

    reference back() const noexcept { return *rbegin(); }

  private:
    adapted_chain_t& chain;
  };

  /*
   * IMPLEMENTATION
   */

  template <hook_chain::state_filter filter>
  struct hook_chain::filtered_list_range
  {
    using iterator = std::conditional_t<
        filter == state_filter::enabled, enabled_view::iterator,
        std::conditional_t<filter == state_filter::disabled,
                           disabled_view::iterator, hook_chain::iterator>>;
    iterator first{};
    iterator last{};
  };

  /*
   * TEMPLATE DEFINITIONS
   */

  // ---------------------------------------------------------
  // 1. Sequential Callbacks (Raw Target)
  // ---------------------------------------------------------

  template <typename dtr, typename orig, typename... types, typename>
  hook_chain::hook_chain(std::byte* target, dtr&& detour, orig& original,
                         types&&... rest)
      : trampoline(target)
  {
    init_chain<true>(
        utils::make_index_sequence_with_step<sizeof...(types) + 2>(),
        utils::make_index_sequence_with_step<sizeof...(types) + 2, 1>(),
        std::forward_as_tuple(std::forward<dtr>(detour), original,
                              std::forward<types>(rest)...));
  }

  template <typename dtr, typename orig, typename... types, typename>
  hook_chain::hook_chain(defer_enable_t, std::byte* target, dtr&& detour,
                         orig& original, types&&... rest)
      : trampoline(target)
  {
    init_chain<false>(
        utils::make_index_sequence_with_step<sizeof...(types) + 2>(),
        utils::make_index_sequence_with_step<sizeof...(types) + 2, 1>(),
        std::forward_as_tuple(std::forward<dtr>(detour), original,
                              std::forward<types>(rest)...));
  }

  // ---------------------------------------------------------
  // 2. Sequential Callbacks (Generic Target)
  // ---------------------------------------------------------

  template <typename trg, typename dtr, typename orig, typename... types,
            typename>
  hook_chain::hook_chain(trg&& target, dtr&& detour, orig& original,
                         types&&... rest)
      : hook_chain(get_target_address(std::forward<trg>(target)),
                   std::forward<dtr>(detour), original,
                   std::forward<types>(rest)...)
  {
    helpers::assert_valid_target_and_detours<trg>(
        helpers::extract_detour_sequence_t<dtr, orig, types...>());
  }

  template <typename trg, typename dtr, typename orig, typename... types,
            typename>
  hook_chain::hook_chain(defer_enable_t, trg&& target, dtr&& detour,
                         orig& original, types&&... rest)
      : hook_chain(defer_enable, get_target_address(std::forward<trg>(target)),
                   std::forward<dtr>(detour), original,
                   std::forward<types>(rest)...)
  {
    helpers::assert_valid_target_and_detours<trg>(
        helpers::extract_detour_sequence_t<dtr, orig, types...>());
  }

  // ---------------------------------------------------------
  // 3. Paired Callbacks (Raw Target)
  // ---------------------------------------------------------

  template <typename pair, typename... types, typename>
  hook_chain::hook_chain(std::byte* target, pair&& first, types&&... rest)
      : trampoline(target)
  {
    init_chain<true>(
        std::make_index_sequence<sizeof...(types) + 1>(),
        std::pair(
            std::forward_as_tuple(
                std::forward<
                    std::tuple_element_t<0, utils::remove_cvref_t<pair>>>(
                    std::get<0>(first)),
                std::forward<
                    std::tuple_element_t<0, utils::remove_cvref_t<types>>>(
                    std::get<0>(rest))...),
            std::forward_as_tuple(
                std::forward<
                    std::tuple_element_t<1, utils::remove_cvref_t<pair>>>(
                    std::get<1>(first)),
                std::forward<
                    std::tuple_element_t<1, utils::remove_cvref_t<types>>>(
                    std::get<1>(rest))...)));
  }

  template <typename pair, typename... types, typename>
  hook_chain::hook_chain(defer_enable_t, std::byte* target, pair&& first,
                         types&&... rest)
      : trampoline(target)
  {
    init_chain<false>(
        std::make_index_sequence<sizeof...(types) + 1>(),
        std::pair(
            std::forward_as_tuple(
                std::forward<
                    std::tuple_element_t<0, utils::remove_cvref_t<pair>>>(
                    std::get<0>(first)),
                std::forward<
                    std::tuple_element_t<0, utils::remove_cvref_t<types>>>(
                    std::get<0>(rest))...),
            std::forward_as_tuple(
                std::forward<
                    std::tuple_element_t<1, utils::remove_cvref_t<pair>>>(
                    std::get<1>(first)),
                std::forward<
                    std::tuple_element_t<1, utils::remove_cvref_t<types>>>(
                    std::get<1>(rest))...)));
  }

  // ---------------------------------------------------------
  // 4. Paired Callbacks (Generic Target)
  // ---------------------------------------------------------

  template <typename trg, typename pair, typename... types, typename>
  hook_chain::hook_chain(trg&& target, pair&& first, types&&... rest)
      : hook_chain(get_target_address(std::forward<trg>(target)),
                   std::forward<pair>(first), std::forward<types>(rest)...)
  {
    helpers::assert_valid_target_and_detours<trg>(
        helpers::extract_detour_sequence_from_tuples_t<pair, types...>());
  }

  template <typename trg, typename pair, typename... types, typename>
  hook_chain::hook_chain(defer_enable_t, trg&& target, pair&& first,
                         types&&... rest)
      : hook_chain(defer_enable, get_target_address(std::forward<trg>(target)),
                   std::forward<pair>(first), std::forward<types>(rest)...)
  {
    helpers::assert_valid_target_and_detours<trg>(
        helpers::extract_detour_sequence_from_tuples_t<pair, types...>());
  }

  // --------------------------------------------------------
  // Initializers
  // ---------------------------------------------------------

  template <bool auto_enable, size_t... d_indexes, size_t... o_indexes,
            typename... types>
  void hook_chain::init_chain(std::index_sequence<d_indexes...>,
                              std::index_sequence<o_indexes...>,
                              std::tuple<types...>&& args)
  {
    typedef utils::type_sequence<types...> seq;
    init_chain<auto_enable>(
        std::make_index_sequence<sizeof...(d_indexes)>(),
        std::pair(std::forward_as_tuple(
                      std::forward<utils::type_at_t<d_indexes, seq>>(
                          std::get<d_indexes>(args))...),
                  std::forward_as_tuple(
                      std::forward<utils::type_at_t<o_indexes, seq>>(
                          std::get<o_indexes>(args))...)));
  }

  template <bool auto_enable, typename... detours, typename... originals,
            size_t... indexes>
  void hook_chain::init_chain(
      std::index_sequence<indexes...>,
      std::pair<std::tuple<detours...>, std::tuple<originals...>>&& args)
  {
    helpers::assert_valid_detour_and_original_pairs(
        utils::type_sequence<detours...>(),
        utils::type_sequence<originals...>());
    hook_init_list arg_list = {
      { get_target_address<originals>(
            std::forward<detours>(std::get<indexes>(args.first))),
       helpers::original_ref_handler(std::get<indexes>(args.second)) }
      ...
    };
    init_with_list({ arg_list.begin(), arg_list.end() }, auto_enable);

    if constexpr (auto_enable)
      initial_inject();
  }

  template <typename dtr, typename orig, typename>
  hook_chain::hook& hook_chain::push_back(dtr&& detour, orig& original,
                                          bool enable_hook)
  {
    if (enable_hook)
      return *insert(end(), std::forward<dtr>(detour), original).first;
    return *insert(defer_enable, end(), std::forward<dtr>(detour), original)
                .first;
  }

  template <typename dtr, typename orig, typename>
  hook_chain::hook& hook_chain::push_front(dtr&& detour, orig& original,
                                           bool enable_hook)
  {
    if (enable_hook)
      return *insert(begin(), std::forward<dtr>(detour), original).first;
    return *insert(defer_enable, begin(), std::forward<dtr>(detour), original)
                .first;
  }

  template <typename dtr, typename orig, typename... types, typename>
  hook_chain::list_range hook_chain::insert(iterator pos, dtr&& detour,
                                            orig& original, types&&... rest)
  {
    return do_insert<true>(
        utils::make_index_sequence_with_step<sizeof...(types) + 2>(),
        utils::make_index_sequence_with_step<sizeof...(types) + 2, 1>(), pos,
        std::forward_as_tuple(std::forward<dtr>(detour), original,
                              std::forward<types>(rest)...));
  }

  template <typename dtr, typename orig, typename... types, typename>
  hook_chain::list_range hook_chain::insert(defer_enable_t, iterator pos,
                                            dtr&& detour, orig& original,
                                            types&&... rest)
  {
    return do_insert<false>(
        utils::make_index_sequence_with_step<sizeof...(types) + 2>(),
        utils::make_index_sequence_with_step<sizeof...(types) + 2, 1>(), pos,
        std::forward_as_tuple(std::forward<dtr>(detour), original,
                              std::forward<types>(rest)...));
  }

  template <typename pair, typename... types, typename>
  hook_chain::list_range hook_chain::insert(iterator pos, pair&& first,
                                            types&&... rest)
  {
    return do_insert<true>(
        std::make_index_sequence<sizeof...(types) + 1>(), pos,
        std::pair(
            std::forward_as_tuple(
                std::forward<
                    std::tuple_element_t<0, utils::remove_cvref_t<pair>>>(
                    std::get<0>(first)),
                std::forward<
                    std::tuple_element_t<0, utils::remove_cvref_t<types>>>(
                    std::get<0>(rest))...),
            std::forward_as_tuple(std::get<1>(first), std::get<1>(rest)...)));
  }

  template <typename pair, typename... types, typename>
  hook_chain::list_range hook_chain::insert(defer_enable_t, iterator pos,
                                            pair&& first, types&&... rest)
  {
    return do_insert<false>(
        std::make_index_sequence<sizeof...(types) + 1>(), pos,
        std::pair(
            std::forward_as_tuple(
                std::forward<
                    std::tuple_element_t<0, utils::remove_cvref_t<pair>>>(
                    std::get<0>(first)),
                std::forward<
                    std::tuple_element_t<0, utils::remove_cvref_t<types>>>(
                    std::get<0>(rest))...),
            std::forward_as_tuple(std::get<1>(first), std::get<1>(rest)...)));
  }

  template <bool auto_enable, size_t... d_indexes, size_t... o_indexes,
            typename... types>
  hook_chain::list_range
      hook_chain::do_insert(std::index_sequence<d_indexes...>,
                            std::index_sequence<o_indexes...>, iterator pos,
                            std::tuple<types...>&& args)
  {
    using seq = utils::type_sequence<types...>;
    return do_insert<auto_enable>(
        std::make_index_sequence<sizeof...(d_indexes)>(), pos,
        std::pair(std::forward_as_tuple(
                      std::forward<utils::type_at_t<d_indexes, seq>>(
                          std::get<d_indexes>(args))...),
                  std::forward_as_tuple(
                      std::forward<utils::type_at_t<o_indexes, seq>>(
                          std::get<o_indexes>(args))...)));
  }

  template <bool auto_enable, size_t... indexes, typename... detours,
            typename... originals>
  hook_chain::list_range hook_chain::do_insert(
      std::index_sequence<indexes...>, iterator pos,
      std::pair<std::tuple<detours...>, std::tuple<originals...>>&& args)
  {
    hook_init_list args_list = {
      { get_target_address<originals>(
            std::forward<detours>(std::get<indexes>(args.first))),
       helpers::original_ref_handler(std::get<indexes>(args.second)) }
      ...
    };
    return do_insert(pos, { args_list.begin(), args_list.end() }, auto_enable);
  }

  template <typename orig, typename>
  hook_chain::hook::hook(hook_chain& chain, const std::byte* pdetour,
                         orig& origref, const std::byte* poriginal,
                         bool enabled)
      : chain(chain), pdetour(pdetour), poriginal(poriginal),
        original_ref(origref), enabled(enabled)
  {
    if (poriginal)
      original_ref.bind_original(poriginal);
  }

  /*
   * NON-TEMPLATE DEFINITIONS
   */
  inline hook_chain::hook_chain(std::byte* target) : trampoline(target)
  {
    helpers::make_backup(target, backup.data(), patch_above);
  }

  // ---------------------------------------------------------
  // hook_chain filtered view getter definitions
  // ---------------------------------------------------------

  inline hook_chain::enabled_view hook_chain::enabled_hooks() noexcept
  {
    return enabled_view(*this);
  }

  inline hook_chain::const_enabled_view
      hook_chain::enabled_hooks() const noexcept
  {
    return const_enabled_view(*this);
  }

  inline hook_chain::const_enabled_view
      hook_chain::const_enabled_hooks() const noexcept
  {
    return const_enabled_view(*this);
  }

  inline hook_chain::disabled_view hook_chain::disabled_hooks() noexcept
  {
    return disabled_view(*this);
  }

  inline hook_chain::const_disabled_view
      hook_chain::disabled_hooks() const noexcept
  {
    return const_disabled_view(*this);
  }

  inline hook_chain::const_disabled_view
      hook_chain::const_disabled_hooks() const noexcept
  {
    return const_disabled_view(*this);
  }

  inline hook_chain::hook::hook(
      hook_chain& chain, const std::byte* pdetour,
      const helpers::original_ref_handler& init_original_ref,
      const std::byte* poriginal, bool enabled)
      : chain(chain), pdetour(pdetour), poriginal(poriginal),
        original_ref(init_original_ref), enabled(enabled)
  {
    if (poriginal)
      original_ref.bind_original(poriginal);
  }
} // namespace alterhook

#if utils_msvc
  #pragma warning(pop)
#elif utils_clang
  #pragma clang diagnostic pop
#endif
