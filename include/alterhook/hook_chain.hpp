/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include <algorithm>
#include <cstddef>
#include <initializer_list>
#include <iterator>
#include <list>
#include <type_traits>
#include <utility>
#include "detail/injectable.hpp"
#include "hook.hpp"
#include "tools.hpp"
#include "trampoline.hpp"
#include "utilities/traits/concepts.hpp"
#include "utilities/traits/function_traits.hpp"
#include "utilities/iterators.hpp"
#include "utilities/macros.hpp"
#include "utilities/other.hpp"

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
  namespace helpers
  {
    template <template <typename> typename InitType, typename Itr,
              typename Target = void>
    constexpr bool is_valid_init_iterator = utils::iter::is_iterator_yielding<
        Itr, InitType<utils::remove_cvref_t<Target>>,
        const InitType<utils::remove_cvref_t<Target>>&>;
    template <template <typename> typename InitType, typename Range,
              typename Target = void, typename = void>
    constexpr bool is_valid_init_range = false;
  } // namespace helpers

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
    template <typename Target = void>
    class init_type;
    template <bool enabled>
    struct filter_predicate;

    template <typename Detour, typename Original>
    init_type(Detour, Original) -> init_type<>;

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

      static constexpr splicer_flags make_default() noexcept
      {
        return { state_filter::any, target_state::preserve };
      }
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
    using enabled_view =
        utils::iter::filter_view<hook_chain, filter_predicate<true>>;
    using const_enabled_view =
        utils::iter::filter_view<const hook_chain, filter_predicate<true>>;
    using disabled_view =
        utils::iter::filter_view<hook_chain, filter_predicate<false>>;
    using const_disabled_view =
        utils::iter::filter_view<const hook_chain, filter_predicate<false>>;

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

    template <typename Target,
              std::enable_if_t<utils::callable_type<Target>, size_t> = 0>
    hook_chain(
        Target&&                                                        target,
        std::initializer_list<init_type<utils::remove_cvref_t<Target>>> args)
        : hook_chain(std::forward<Target>(target), args.begin(), args.end())
    {
    }

    hook_chain(std::byte* target, std::initializer_list<init_type<>> args);

    template <typename Target, typename Itr,
              std::enable_if_t<
                  utils::callable_type<Target> &&
                      helpers::is_valid_init_iterator<init_type, Itr, Target>,
                  size_t> = 0>
    hook_chain(Target&& target, Itr first, Itr last)
        : hook_chain(get_target_address(std::forward<Target>(target)), first,
                     last)
    {
    }

    template <typename Itr,
              std::enable_if_t<helpers::is_valid_init_iterator<init_type, Itr>,
                               size_t> = 0>
    hook_chain(std::byte* target, Itr first, Itr last);

    template <typename Target, typename Range,
              std::enable_if_t<
                  utils::callable_type<Target> &&
                      helpers::is_valid_init_range<init_type, Range, Target>,
                  size_t> = 0>
    hook_chain(Target&& target, Range&& range)
        : hook_chain(std::forward<Target>(target), utils::iter::begin(range),
                     utils::iter::end(range))
    {
    }

    template <typename Range,
              std::enable_if_t<helpers::is_valid_init_range<init_type, Range>,
                               size_t> = 0>
    hook_chain(std::byte* target, Range&& range)
        : hook_chain(target, utils::iter::begin(range), utils::iter::end(range))
    {
    }

    /// @}

    /**
     * @brief Construct with just a raw pointer to the target leaving the
     * container empty.
     *
     * @par Exceptions
     * - @ref trampoline-init-exceptions
     */
    explicit hook_chain(std::byte* target);

    /**
     * @brief Construct with just the target leaving the container empty.
     *
     * @par Exceptions
     * - @ref trampoline-init-exceptions
     */
    template <typename trg,
              std::enable_if_t<utils::callable_type<trg>, size_t> = 0>
    explicit hook_chain(trg&& target)
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
    explicit hook_chain(alterhook::hook&& other);

    /**
     * @brief Construct with a copy of an @ref alterhook::trampoline instance
     *
     * @par Exceptions
     * - @ref trampoline-copy-exceptions
     */
    explicit hook_chain(const trampoline& other) : trampoline(other)
    {
      helpers::make_backup(ptarget, backup.data(), patch_above);
    }

    /// Construct by moving an @ref alterhook::trampoline instance to the chain.
    explicit hook_chain(trampoline&& other) noexcept
        : trampoline(std::move(other))
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
     *iteration order) or the last in one of the two lists.
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
    hook& push_back(const init_type<>& h) { return *insert(end(), h); }

    /**
     * @brief Insert a single hook at the beginning of the container and sets
     * its state as either enabled or disabled.
     * @param detour the detour of the hook
     * @param original the reference to the original callback of the hook
     * @param enable_hook whether to enable the hook
     * @returns A reference to the inserted hook.
     */
    hook& push_front(const init_type<>& h) { return *insert(begin(), h); }

    iterator insert(iterator pos, const init_type<>& h);

    list_range insert(iterator pos, std::initializer_list<init_type<>> args);

    template <typename Itr,
              std::enable_if_t<helpers::is_valid_init_iterator<init_type, Itr>,
                               size_t> = 0>
    list_range insert(iterator pos, Itr first, Itr last);

    template <typename Range,
              std::enable_if_t<helpers::is_valid_init_range<init_type, Range>,
                               size_t> = 0>
    list_range insert(iterator pos, Range&& range)
    {
      return insert(pos, utils::iter::begin(range), utils::iter::end(range));
    }

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
    void splice(iterator newpos, hook_chain& other,
                splicer_flags flags = splicer_flags::make_default())
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
                iterator      last,
                splicer_flags flags = splicer_flags::make_default());

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
                splicer_flags flags = splicer_flags::make_default())
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
     *+ The container has enabled hooks, the exception thrown is of group
     *     @ref memalloc-and-address-validation and an attempt to re-enable the
     *  disabled hooks in order to undo the operation was successful.
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

    struct intra_swap_info;
    struct splicer_rollback_info;

    using backup_t   = std::array<std::byte, detail::constants::backup_size>;
    using rollback_t = std::vector<splicer_rollback_info>;

    backup_t  backup{};
    hook_list hooks{};
    size_t    enabled_count = 0;

    void       init_enabled_chain(const std::byte* start_pos);
    list_range do_insert(
        iterator pos,
        predicate_view<void(const std::byte*& prev_poriginal,
                            size_t&           enabled_added_count,
                            predicate_view<const std::byte*()> lookup_original)>
            inserter_loop);
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
    trampoline& get_trampoline() { return *this; }

    const trampoline& get_trampoline() const { return *this; }

    size_t do_erase_if(iterator first, iterator last, state_filter filter,
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

    hook& operator=(const init_type<>& item);

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

    template <typename Target>
    hook(hook_chain& chain, const init_type<Target>& init_data,
         const std::byte* poriginal = nullptr)
        : hook(chain, init_data.pdetour, init_data.original_ref, poriginal,
               init_data.enable_hook)
    {
    }

    void bind_original()
    {
      utils_assert(poriginal, "hook_chain::hook::bind_original: use of method "
                              "with unset poriginal");
      original_ref.bind_original(poriginal);
    }

    void redirect_original(const std::byte* original) noexcept
    {
      poriginal = original;
      bind_original();
    }

    void reset() noexcept
    {
      enabled   = false;
      poriginal = nullptr;
      original_ref.unbind_original();
    }

    void set_detour(std::byte* detour);
    void set_original(const helpers::original_ref_handler& original);
    void swap(hook& right);
  };

  template <>
  class hook_chain::init_type<>
  {
  public:
    template <typename Detour, typename Original,
              std::enable_if_t<
                  utils::traits::is_detour_and_original_pair<Detour, Original&>,
                  size_t> = 0>
    init_type(Detour&& detour, Original& original,
              bool enable_hook = true) noexcept
        : pdetour(get_target_address<Original>(std::forward<Detour>(detour))),
          original_ref(original), enable_hook(enable_hook)
    {
      helpers::assert_valid_detour_original_pair<Detour, Original>();
    }

    const std::byte* get_detour() const noexcept { return pdetour; }

    bool will_be_enabled() const noexcept { return enable_hook; }

  protected:
    const std::byte*              pdetour = nullptr;
    helpers::original_ref_handler original_ref;
    bool                          enable_hook = true;

    friend class hook_chain;
  };

  template <typename Target>
  class hook_chain::init_type : public hook_chain::init_type<>
  {
    using base = init_type<>;

  public:
    template <typename Detour, typename Original,
              std::enable_if_t<
                  utils::traits::is_detour_and_original_pair<Detour, Original&>,
                  size_t> = 0>
    init_type(Detour&& detour, Original& original,
              bool enable_hook = true) noexcept
        : base(std::forward<Detour>(detour), original, enable_hook)
    {
      helpers::assert_valid_target_and_detour_pair<Target, Detour>();
    }

    friend class hook_chain;
  };

  template <bool enabled>
  struct hook_chain::filter_predicate
  {
    bool operator()(const hook& item) const noexcept
    {
      return item.enabled == enabled;
    }
  };

  /*
   * IMPLEMENTATION
   */

  /*
   * TEMPLATE DEFINITIONS
   */

  // --------------------------------------------------------
  // Initializers
  // ---------------------------------------------------------

  inline hook_chain::hook_chain(std::byte*                         target,
                                std::initializer_list<init_type<>> args)
      : hook_chain(target, args.begin(), args.end())
  {
  }

  template <
      typename Itr,
      std::enable_if_t<
          helpers::is_valid_init_iterator<hook_chain::init_type, Itr>, size_t>>
  hook_chain::hook_chain(std::byte* target, Itr first, Itr last)
      : trampoline(target)
  {
    helpers::make_backup(ptarget, backup.data(), patch_above);
    const std::byte* original    = get_original();
    bool             has_enabled = false;

    for (auto itr = first; itr != last; ++itr)
    {
      const iterator entry_itr =
          hooks.emplace(hooks.end(), *this, *itr, original);
      entry_itr->current = entry_itr;
      if (entry_itr->enabled)
      {
        entry_itr->bind_original();
        original    = entry_itr->pdetour;
        has_enabled = true;
      }
    }

    if (has_enabled)
    {
      init_enabled_chain(original);
      enabled_count = hooks.size();
    }
  }

  inline hook_chain::iterator hook_chain::insert(iterator           pos,
                                                 const init_type<>& h)
  {
    auto inserter_loop =
        [this, pos, &h](const std::byte*&                  prev_poriginal,
                        size_t&                            enabled_added_count,
                        predicate_view<const std::byte*()> lookup_original)
    {
      iterator inserted = hooks.emplace(pos, *this, h);
      inserted->current = inserted;

      if (!inserted->enabled)
        return;
      prev_poriginal = lookup_original();
      inserted->redirect_original(prev_poriginal);
      prev_poriginal = inserted->pdetour;
      ++enabled_added_count;
    };

    return do_insert(pos, inserter_loop).first;
  }

  inline hook_chain::list_range
      hook_chain::insert(iterator pos, std::initializer_list<init_type<>> args)
  {
    return insert(pos, args.begin(), args.end());
  }

  template <
      typename Itr,
      std::enable_if_t<
          helpers::is_valid_init_iterator<hook_chain::init_type, Itr>, size_t>>
  hook_chain::list_range hook_chain::insert(iterator pos, Itr first, Itr last)
  {
    if (first == last)
      return { pos, pos };
    auto inserter_loop =
        [this, pos, first,
         last](const std::byte*& prev_poriginal, size_t& enabled_added_count,
               predicate_view<const std::byte*()> lookup_original)
    {
      for (auto itr = first; itr != last; ++itr)
      {
        iterator inserted = hooks.emplace(pos, *this, *itr, prev_poriginal);
        inserted->current = inserted;

        if (inserted->enabled)
        {
          if (!prev_poriginal)
          {
            prev_poriginal = lookup_original();
            inserted->redirect_original(prev_poriginal);
          }
          prev_poriginal = inserted->pdetour;
          ++enabled_added_count;
        }
      }
    };

    return do_insert(pos, inserter_loop);
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
    return enabled_view{ *this, {} };
  }

  inline hook_chain::const_enabled_view
      hook_chain::enabled_hooks() const noexcept
  {
    return const_enabled_view{ *this, {} };
  }

  inline hook_chain::const_enabled_view
      hook_chain::const_enabled_hooks() const noexcept
  {
    return enabled_hooks();
  }

  inline hook_chain::disabled_view hook_chain::disabled_hooks() noexcept
  {
    return disabled_view{ *this, {} };
  }

  inline hook_chain::const_disabled_view
      hook_chain::disabled_hooks() const noexcept
  {
    return const_disabled_view{ *this, {} };
  }

  inline hook_chain::const_disabled_view
      hook_chain::const_disabled_hooks() const noexcept
  {
    return disabled_hooks();
  }

  inline hook_chain::hook::hook(
      hook_chain& chain, const std::byte* pdetour,
      const helpers::original_ref_handler& init_original_ref,
      const std::byte* poriginal, bool enabled)
      : chain(chain), pdetour(pdetour), poriginal(poriginal),
        original_ref(init_original_ref), enabled(enabled)
  {
    if (poriginal && enabled)
      original_ref.bind_original(poriginal);
  }

  namespace helpers
  {
    template <template <typename> typename InitType, typename Range,
              typename Target>
    constexpr bool is_valid_init_range<
        InitType, Range, Target,
        std::enable_if_t<
            is_valid_init_iterator<InitType, utils::iter::range_begin_t<Range>,
                                   Target> &&
            is_valid_init_iterator<InitType, utils::iter::range_end_t<Range>,
                                   Target>>> = true;
  }
} // namespace alterhook

#if utils_msvc
  #pragma warning(pop)
#elif utils_clang
  #pragma clang diagnostic pop
#endif
