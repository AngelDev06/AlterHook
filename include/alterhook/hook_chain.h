/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include <list>
#include "hook.h"

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
  class ALTERHOOK_API hook_chain : trampoline
  {
  public:
    class ALTERHOOK_API hook;
    class const_iterator;
    class iterator;

    /// @brief An enum class that acts as a tag to control the target list of
    /// the algorithms provided. Note that in some cases `both` isn't accepted
    /// so it is advised to refer to the documentation before using it.
    enum class transfer
    {
      disabled,
      enabled,
      both
    };
    /// Alias of @ref alterhook::hook_chain::transfer
    typedef transfer include;
    typedef typename helpers::alloc_wrapper<std::allocator>::template allocator<
        hook>
                                            allocator_type;
    typedef std::list<hook, allocator_type> hook_list;

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

    typedef typename hook_list::const_iterator const_list_iterator;
    typedef typename hook_list::iterator       list_iterator;
    typedef
        typename hook_list::const_reverse_iterator const_reverse_list_iterator;
    typedef typename hook_list::reverse_iterator   reverse_list_iterator;

    /// @}

    typedef hook                                    value_type;
    typedef size_t                                  size_type;
    typedef ptrdiff_t                               difference_type;
    typedef hook*                                   pointer;
    typedef const hook*                             const_pointer;
    typedef hook&                                   reference;
    typedef const hook&                             const_reference;
    typedef std::pair<list_iterator, list_iterator> list_range;

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

    /// Construct with target and a sequence of detour and original callbacks
    template <typename trg, typename dtr, typename orig, typename... types,
              typename = std::enable_if_t<
                  utils::callable_type<trg> &&
                  utils::detours_and_originals<dtr, orig&, types...>>>
    hook_chain(trg&& target, dtr&& detour, orig& original, types&&... rest);

    /// @brief Construct with a raw pointer to the target and a sequence of
    /// @ref alterhook::utils::pair_like "pair-like" objects holding the detour
    /// and the original callbacks.
    template <typename pair, typename... types,
              typename = std::enable_if_t<
                  utils::detour_and_original_pairs<pair, types...>>>
    hook_chain(std::byte* target, pair&& first, types&&... rest);

    /// @brief Construct with the target and a sequence of
    /// @ref alterhook::utils::pair_like "pair-like" objects holding the detour
    /// and the original callbacks.
    template <typename trg, typename pair, typename... types,
              typename = std::enable_if_t<
                  utils::callable_type<trg> &&
                  utils::detour_and_original_pairs<pair, types...>>>
    hook_chain(trg&& target, pair&& first, types&&... rest);

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
     * @brief Construct with a copy of an @ref alterhook::hook instance and a
     * reference to the original callback. It does NOT enable the added hook
     * afterwards.
     *
     * @par Exceptions
     * - @ref trampoline-init-exceptions
     * @note The reference to the original callback is required since having
     * only one that is managed by two containers at the same time would cause
     * conflicts. Therefore the user should pass a different callback for the
     * hook chain that is constructed.
     */
    template <typename orig,
              typename = std::enable_if_t<utils::function_type<orig>>>
    hook_chain(const alterhook::hook& other, orig& original);

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

    /**
     * @brief Copies the target, the trampoline and all hooks from `other` to
     * the disabled list of `*this`.
     * @param other the chain to copy from
     * @par Exceptions
     * - @ref trampoline-copy-exceptions
     * @note As mentioned the hooks from `other` are copied to the disabled list
     * of `*this` in **iteration order**. This means that all copies of the
     * hooks will remain disabled after construction till they are manually
     * enabled.
     */
    hook_chain(const hook_chain& other);

    /**
     * @brief Moves all contents of `other` to `*this` leaving `other`
     * uninitialized. The hooks are moved into their respective lists in the
     * same order therefore retaining their state (i.e. enabled or disabled)
     * @param other the chain to move from
     */
    hook_chain(hook_chain&& other) noexcept;

    /// @brief Default constructs the chain leaving it target-less and therefore
    /// uninitialized
    hook_chain() noexcept {}

    ~hook_chain() noexcept;

    /**
     * @brief Disables all hooks currently stored in `*this` and replaces them
     * with a copy of those of `other` (which will be left disabled). It will
     * also copy the target and the trampoline of `other`.
     * @param other the chain to copy from
     * @returns `*this`
     * @par Exceptions
     * - @ref trampoline-copy-exceptions
     * - @ref thread-freezer-exceptions
     * - @ref target-injection-exceptions
     * @par Exception Guarantee
     * - strong:
     *   + When there is at least one enabled hook in the container and an
     *     attempt to disable it failed. The exception thrown will belong in the
     *     groups: @ref thread-freezer-exceptions,
     *     @ref target-injection-exceptions
     *   + There were no enabled hooks in the container and the exception thrown
     *     is of group @ref memalloc-and-address-validation
     * - basic: If none of the above is true then the guarantee is basic and the
     *   container is either left uninitialized (i.e. target-less) and/or with
     *   enabled hooks being left as disabled.
     * @note Just like the
     * @ref alterhook::hook_chain::hook_chain(const hook_chain&)
     * "copy constructor", the hooks that are copied to `*this` are all put in
     * the disabled list in **iteration order** and are therefore left disabled
     * till manually enabled.
     */
    hook_chain& operator=(const hook_chain& other);

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
    void enable_all();
    /// Disables all hooks that are currently enabled in the container
    void disable_all();

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
    void          clear(include trg = include::both);
    /**
     * @brief Erases either the last hook from the container (the last in
     * iteration order) or the last in one of the two lists.
     * @param trg specifies the list from which the last hook will be erased or
     * when set to 'both' it removes the last one in iteration order (i.e. the
     * last one from the container) which is the default behaviour.
     */
    void          pop_back(include trg = include::both);
    /**
     * @brief Erases either the first hook from the container (the first in
     * iteration order) or the first in one of the two lists.
     * @param trg specifies the list from which the first hook will be erased or
     * when set to 'both' it removes the first one in iteration order (i.e. the
     * first one from the container) which is the default behaviour.
     */
    void          pop_front(include trg = include::both);
    /**
     * @brief Erases a single hook at the position specified by `position`.
     * @param position the list iterator to the hook that will be erased.
     * @returns a list iterator to the hook that follows the one pointed to by
     * `position` in list iteration order
     */
    list_iterator erase(list_iterator position);
    /**
     * @brief Erases all hooks in the range [first, last) in list iteration
     * order.
     * @param first the beginning of the range (also included in the range)
     * @param last the end of the range (not included in the range)
     * @returns `last`
     */
    list_iterator erase(list_iterator first, list_iterator last);
    /**
     * @brief Erases a single hook at the position specified by `position`.
     * @param position the iterator to the hook that will be erased.
     * @returns an iterator to the hook that follows the one pointed to by
     * `position` in iteration order.
     */
    iterator      erase(iterator position);
    /**
     * @brief Erases all hooks in the range [first, last) in iteration order
     * @param first the beginning of the range (also included in the range)
     * @param last the end of the range (not included in the range)
     * @returns `last`
     * @par Exception Guarantee
     * - basic: if an exception is thrown it is due to an unsuccessful attempt
     *   to disable all the enabled hooks that are included in the range [first,
     *   last). At that point however, all the disabled hooks have been erased
     *   so the only ones that remain in the container are the enabled hooks.
     */
    iterator      erase(iterator first, iterator last);

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
     * @brief Insert multiple hooks (with the arguments forwarded in sequential
     * order) at the end of the container and set their state as either enabled
     * or disabled.
     * @param to whether to append to the enabled or the disabled list
     * @param detour the first detour
     * @param original the first reference to the original callback
     * @param rest the arguments for the rest of the hooks
     * @returns A pair of list iterators pointing to the beginning and the end
     * of the inserted range respectively.
     */
    template <typename dtr, typename orig, typename... types,
              typename = std::enable_if_t<
                  utils::detours_and_originals<dtr, orig&, types...>>>
    list_range append(transfer to, dtr&& detour, orig& original,
                      types&&... rest);
    /**
     * @brief Insert multiple hooks (with the arguments forwarded in sequential
     * order) at the end of the container and set their state to enabled.
     * @param detour the first detour
     * @param original the first reference to the original callback
     * @param rest the arguments for the rest of the hooks
     * @returns A pair of list iterators pointing to the beginning and the end
     * of the inserted range respectively.
     */
    template <typename dtr, typename orig, typename... types,
              typename = std::enable_if_t<
                  utils::detours_and_originals<dtr, orig&, types...>>>
    list_range append(dtr&& detour, orig& original, types&&... rest);
    /**
     * @brief Insert multiple hooks (with the arguments grouped in @ref
     * alterhook::utils::pair_like "pair-like objects") at the end of the
     * container and set their state as either enabled or disabled.
     * @param to whether to append to the enabled or the disabled list
     * @param first the pair of arguments for the first hook
     * @param rest the pairs of arguments for the rest of the hooks
     * @returns A pair of list iterators pointing to the beginning and the end
     * of the inserted range respectively.
     */
    template <typename pair, typename... types,
              typename = std::enable_if_t<
                  utils::detour_and_original_pairs<pair, types...>>>
    list_range append(transfer to, pair&& first, types&&... rest);
    /**
     * @brief Insert multiple hooks (with the arguments grouped in @ref
     * alterhook::utils::pair_like "pair-like objects") at the end of the
     * container and set their state as either enabled or disabled.
     * @param first the pair of arguments for the first hook
     * @param rest the pairs of arguments for the rest of the hooks
     * @returns A pair of list iterators pointing to the beginning and the end
     * of the inserted range respectively.
     */
    template <typename pair, typename... types,
              typename = std::enable_if_t<
                  utils::detour_and_original_pairs<pair, types...>>>
    list_range append(pair&& first, types&&... rest);
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
    /**
     * @brief Insert a single hook right before the position specified by
     * `position`.
     * @param position the position before which the hook will be inserted
     * @param detour the detour of the hook
     * @param original the reference to the original callback of the hook
     * @param to whether position is an iterator to the enabled or the disabled
     * list (required)
     * @returns A reference to the inserted hook.
     */
    template <
        typename dtr, typename orig,
        typename = std::enable_if_t<utils::detours_and_originals<dtr, orig&>>>
    hook& insert(list_iterator position, dtr&& detour, orig& original,
                 include to);
    /**
     * @brief Insert a single hook right before the position specified by
     * `position`.
     * @param position the position before which the hook will be inserted
     * @param detour the detour of the hook
     * @param original the reference to the original callback of the hook
     * @returns A reference to the inserted hook.
     * @note For this overload, no specification of the list to which `position`
     * points to is required because it's included in the iterator itself. It
     * should be noted though that for both overloads the hook will be placed in
     * the same position and its state will be set based on the type of list it
     * is inserted to (e.g. if inserted to the enabled list, it will be enabled
     * afterwards). So this is just some handy wrapper over the other overload.
     */
    template <
        typename dtr, typename orig,
        typename = std::enable_if_t<utils::detours_and_originals<dtr, orig&>>>
    hook& insert(iterator position, dtr&& detour, orig& original);

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
    void swap(list_iterator left, hook_chain& other, list_iterator right);

    /**
     * @brief Swaps `left` with `right`. Both iterators should point to elements
     * of the current container, otherwise the @ref
     * alterhook::hook_chain::swap(list_iterator,hook_chain&,list_iterator)
     * "other overload" should be used.
     * @param left a list iterator to the first element to be swapped
     * @param right a list iterator to the second element to be swapped
     */
    void swap(list_iterator left, list_iterator right)
    {
      swap(left, *this, right);
    }

    /**
     * @brief Swaps the current container with `other`. Unlike `std::swap` this
     * one only swaps the two lists and therefore the enabled hooks of each
     * container are redirected to their new target and trampoline.
     * @param other the container to swap with
     * @par Exception Guarantee
     * Same as @ref
     * alterhook::hook_chain::swap(list_iterator,hook_chain&,list_iterator)
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
     * @brief A wrapper that effectively merges two containers into one that has
     * the hooks from both with the same state as before.
     * @param other the container to merge to the current one
     * @param at_back whether the hooks of `other` should be moved at the end of
     * the current container (the default behaviour) or at the beginning
     * @note After the operation is finished, `other` is left empty (i.e. with
     * no hooks) and `*this` now holds the hooks of both containers. `other`
     * remains initialized nevertheless and new hooks can be added to it
     * afterwards.
     */
    void merge(hook_chain& other, bool at_back = true);

    /// @brief Same behaviour as the @ref merge(hook_chain&,bool)
    /// "other overload"
    void merge(hook_chain&& other, bool at_back = true)
    {
      merge(other, at_back);
    }

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
    void splice(list_iterator newpos, hook_chain& other, transfer to,
                transfer from = transfer::both);

    /// @brief Same behaviour as the @ref
    /// splice(list_iterator,hook_chain&,transfer,transfer) "other overload"
    void splice(list_iterator newpos, hook_chain&& other, transfer to,
                transfer from = transfer::both)
    {
      splice(newpos, other, to, from);
    }

    /// @brief Same behaviour as the @ref
    /// splice(list_iterator,hook_chain&,transfer,transfer) "other overload"
    /// except no specification of the target list is required.
    void splice(iterator newpos, hook_chain& other,
                transfer from = transfer::both);

    /// @brief Same behaviour as the @ref splice(iterator,hook_chain&,transfer)
    /// "other overload"
    void splice(iterator newpos, hook_chain&& other,
                transfer from = transfer::both);

    /**
     * @brief Transfers a single hook referred to by `oldpos` to `newpos`
     * @param newpos the target location
     * @param other the container from which the hook will be transferred
     * @param oldpos the list iterator to the hook that will be transferred
     * @param to specifies which list `newpos` refers to
     */
    void splice(list_iterator newpos, hook_chain& other, list_iterator oldpos,
                transfer to);

    /// @brief Same behaviour as the @ref
    /// splice(list_iterator,hook_chain&,list_iterator,transfer)
    /// "other overload".
    void splice(list_iterator newpos, hook_chain&& other, list_iterator oldpos,
                transfer to)
    {
      splice(newpos, other, oldpos, to);
    }

    /// @brief Same behaviour as the @ref
    /// splice(list_iterator,hook_chain&,list_iterator,transfer)
    /// "other overload" except no specification of the target list is required.
    void splice(iterator newpos, hook_chain& other, list_iterator oldpos);

    /// @brief Same behaviour as the @ref
    /// splice(iterator,hook_chain&,list_iterator) "other overload".
    void splice(iterator newpos, hook_chain&& other, list_iterator oldpos);

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
    void splice(list_iterator newpos, hook_chain& other, list_iterator first,
                list_iterator last, transfer to);

    /// @brief Same behaviour as the @ref
    /// splice(list_iterator,hook_chain&,list_iterator,list_iterator,transfer)
    /// "other overload"
    void splice(list_iterator newpos, hook_chain&& other, list_iterator first,
                list_iterator last, transfer to)
    {
      splice(newpos, other, first, last, to);
    }

    /// @brief Same behaviour as the @ref
    /// splice(list_iterator,hook_chain&,list_iterator,list_iterator,transfer)
    /// "other overload" except no specification of the target list is required.
    void splice(iterator newpos, hook_chain& other, list_iterator first,
                list_iterator last);

    /// @brief Same behaviour as the @ref
    /// splice(iterator,hook_chain&,list_iterator,list_iterator)
    /// "other overload"
    void splice(iterator newpos, hook_chain&& other, list_iterator first,
                list_iterator last);

    /**
     * @brief Transfers the range of hooks [first, last) to `newpos` in
     * **iteration order** without changing the state of the original hooks.
     * @param newpos the target location
     * @param other the container from which the range will be transferred
     * @param first the beginning of the range (also included in the range)
     * @param last the end of the range (not included in the range)
     * @param to specifies which list `newpos` refers to
     * @note Unlike the other splicers, in this one the state of the hooks that
     * are transferred is not altered based on the list that `newpos` refers to.
     * This for example means that disabled hooks will be transferred to the
     * disabled list even if `newpos` refers to an element of the enabled one.
     * The order of the range is maintained and it's transferred to the target
     * so that the hook that precedes `newpos` in iteration order is linked with
     * the beginning of the range and the last element of it is linked with
     * `newpos` (if it's not the end iterator). This is the method that @ref
     * merge(hook_chain&,bool) "the merger" uses under
     * the hood.
     */
    void splice(list_iterator newpos, hook_chain& other, iterator first,
                iterator last, transfer to);

    /// @brief Same behaviour as the @ref
    /// splice(list_iterator,hook_chain&,iterator,iterator,transfer)
    /// "other overload".
    void splice(list_iterator newpos, hook_chain&& other, iterator first,
                iterator last, transfer to);

    /// @brief Same behaviour as the @ref
    /// splice(list_iterator,hook_chain&,iterator,iterator,transfer)
    /// "other overload" except no specification of the target list is required.
    void splice(iterator newpos, hook_chain& other, iterator first,
                iterator last);

    /// @brief Same behaviour as the @ref
    /// splice(iterator,hook_chain&,iterator,iterator) "other overload".
    void splice(iterator newpos, hook_chain&& other, iterator first,
                iterator last);

    /// @brief Calls the @ref
    /// splice(list_iterator,hook_chain&,list_iterator,transfer)
    /// "other overload" with `other` set to `*this`.
    void splice(list_iterator newpos, list_iterator oldpos, transfer to)
    {
      splice(newpos, *this, oldpos, to);
    }

    /// @brief Calls the @ref splice(iterator,hook_chain&,list_iterator)
    /// "other overload" with `other` set to `*this`.
    void splice(iterator newpos, list_iterator oldpos);

    /// @brief Calls the @ref
    /// splice(list_iterator,hook_chain&,list_iterator,list_iterator,transfer)
    /// "other overload" with `other` set to `*this`.
    void splice(list_iterator newpos, list_iterator first, list_iterator last,
                transfer to)
    {
      splice(newpos, *this, first, last, to);
    }

    /// @brief Calls the @ref
    /// splice(iterator,hook_chain&,list_iterator,list_iterator)
    /// "other overload" with `other` set to `*this`.
    void splice(iterator newpos, list_iterator first, list_iterator last);

    /// @brief Calls the @ref
    /// splice(list_iterator,hook_chain&,iterator,iterator,transfer)
    /// "other overload" with `other` set to `*this`.
    void splice(list_iterator newpos, iterator first, iterator last,
                transfer to);

    /// @brief Calls the @ref splice(iterator,hook_chain&,iterator,iterator)
    /// "other overload" with `other` set to `*this`.
    void splice(iterator newpos, iterator first, iterator last);

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

    /// Access specific hook at position `n`.
    reference       operator[](size_t n) noexcept;
    /// Const version of @ref operator[](size_t).
    const_reference operator[](size_t n) const noexcept;
    /// @brief Access specific hook at position `n`. Throws
    /// [std::out_of_range](https://en.cppreference.com/w/cpp/error/out_of_range)
    /// when `n` is out of range.
    reference       at(size_t n);
    /// Const version of @ref at(size_t).
    const_reference at(size_t n) const;
    /// Access the first hook.
    reference       front() noexcept;
    /// Const version of @ref front().
    const_reference front() const noexcept;
    /// Const version of @ref front().
    const_reference cfront() const noexcept;
    /// Access the first enabled hook.
    reference       efront() noexcept;
    /// Const version of @ref efront().
    const_reference efront() const noexcept;
    /// Const version of @ref efront().
    const_reference cefront() const noexcept;
    /// Access the first disabled hook.
    reference       dfront() noexcept;
    /// Const version of @ref dfront().
    const_reference dfront() const noexcept;
    /// Const version of @ref dfront().
    const_reference cdfront() const noexcept;
    /// Access the last hook.
    reference       back() noexcept;
    /// Const version of @ref back().
    const_reference back() const noexcept;
    /// Const version of @ref back().
    const_reference cback() const noexcept;
    /// Access the last enabled hook.
    reference       eback() noexcept;
    /// Const version of @ref eback().
    const_reference eback() const noexcept;
    /// Const version of @ref eback().
    const_reference ceback() const noexcept;
    /// Access the last disabled hook.
    reference       dback() noexcept;
    /// Const version of @ref dback().
    const_reference dback() const noexcept;
    /// Const version of @ref dback().
    const_reference cdback() const noexcept;

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
    bool empty() const noexcept { return enabled.empty() && disabled.empty(); }

    /// Returns whether the container has no enabled hooks.
    bool empty_enabled() const noexcept { return enabled.empty(); }

    /// Returns whether the container has no disabled hooks.
    bool empty_disabled() const noexcept { return disabled.empty(); }

    /// Returns `true` when the container is non-empty, `false` otherwise.
    explicit operator bool() const noexcept { return !empty(); }

    /// Returns the size of the container (i.e. the number of hooks)
    size_t size() const noexcept { return enabled.size() + disabled.size(); }

    /// Returns the size of the enabled list (i.e. the number of enabled hooks).
    size_t enabled_size() const noexcept { return enabled.size(); }

    /// @brief Returns the size of the disabled list (i.e. the number of
    /// disabled hooks).
    size_t disabled_size() const noexcept { return disabled.size(); }

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

    iterator                    begin() noexcept;
    iterator                    end() noexcept;
    const_iterator              begin() const noexcept;
    const_iterator              end() const noexcept;
    const_iterator              cbegin() const noexcept;
    const_iterator              cend() const noexcept;
    list_iterator               ebegin() noexcept;
    list_iterator               eend() noexcept;
    const_list_iterator         ebegin() const noexcept;
    const_list_iterator         eend() const noexcept;
    reverse_list_iterator       rebegin() noexcept;
    reverse_list_iterator       reend() noexcept;
    const_reverse_list_iterator rebegin() const noexcept;
    const_reverse_list_iterator reend() const noexcept;
    const_list_iterator         cebegin() const noexcept;
    const_list_iterator         ceend() const noexcept;
    const_reverse_list_iterator crebegin() const noexcept;
    const_reverse_list_iterator creend() const noexcept;
    list_iterator               dbegin() noexcept;
    list_iterator               dend() noexcept;
    const_list_iterator         dbegin() const noexcept;
    const_list_iterator         dend() const noexcept;
    reverse_list_iterator       rdbegin() noexcept;
    reverse_list_iterator       rdend() noexcept;
    const_reverse_list_iterator rdbegin() const noexcept;
    const_reverse_list_iterator rdend() const noexcept;
    const_list_iterator         cdbegin() const noexcept;
    const_list_iterator         cdend() const noexcept;
    const_reverse_list_iterator crdbegin() const noexcept;
    const_reverse_list_iterator crdend() const noexcept;

    /// @}

    /**
     * @name Comparison
     * @brief Compare two chains and determine equality if the target, the
     * number of hooks on each individual list and the detours of each hook
     * compare equal in the same order. Note that the state of each hook should
     * also compare equal in the same order.
     * @{
     */

    /// Return `true` if `*this` and `other` are equal, `false` otherwise.
    bool operator==(const hook_chain& other) const noexcept;
    /// Return `true` if `*this` and `other` are not equal, `false` otherwise.
    bool operator!=(const hook_chain& other) const noexcept;

    /// @}

  private:
#ifdef __alterhook_expose_impl
    friend struct injectors;
#endif
    typedef std::array<std::byte, detail::constants::backup_size> backup_t;

    backup_t  backup{};
    hook_list disabled{};
    hook_list enabled{};
    bool      starts_enabled = false;

    struct unbind_range_callback
    {
      virtual void operator()(list_iterator itr, bool forward = true) = 0;

      static void set_pchain(list_iterator itr, hook_chain* pchain);
      static void set_enabled(list_iterator itr, bool status);
      static void set_has_other(list_iterator itr, bool status);
      static void set_other(list_iterator itr, list_iterator other);
    };

    template <size_t... d_indexes, size_t... o_indexes, typename... types>
    void init_chain(std::index_sequence<d_indexes...>,
                    std::index_sequence<o_indexes...>,
                    std::tuple<types...>&& args);
    template <typename... detours, typename... originals, size_t... indexes>
    void init_chain(
        std::index_sequence<indexes...>,
        std::pair<std::tuple<detours...>, std::tuple<originals...>>&& args);
    void  assert_len(size_t n) const;
    void  verify_len(size_t n) const;
    void  join_last_unchecked(size_t enabled_count = 1);
    void  join_last();
    void  join_first();
    void  join(list_iterator itr);
    void  unbind_range(list_iterator first, list_iterator last,
                       unbind_range_callback& callback);
    void  unbind(list_iterator position);
    void  uninject_all();
    void  uninject_range(list_iterator first, list_iterator last);
    void  uninject(list_iterator position);
    void  bind(list_iterator pos, list_iterator oldpos, bool to_enabled);
    void  inject_range(list_iterator pos, list_iterator first,
                       list_iterator last);
    void  inject_back(list_iterator first, list_iterator last);
    void  toggle_status(list_iterator first, list_iterator last);
    void  toggle_status(list_iterator position);
    void  toggle_status_all(include src);
    hook& push_back_impl(const std::byte* detour, helpers::orig_buff_t buffer,
                         bool enable_hook);
    hook& push_front_impl(const std::byte* detour, helpers::orig_buff_t buffer,
                          bool enable_hook);
    hook& insert_impl(list_iterator pos, const std::byte* detour,
                      helpers::orig_buff_t buffer, include trg);
    template <size_t... d_indexes, size_t... o_indexes, typename... types>
    list_range append_impl(transfer to, std::index_sequence<d_indexes...>,
                           std::index_sequence<o_indexes...>,
                           std::tuple<types...>&& args);
    template <typename... detours, typename... originals, size_t... indexes>
    list_range append_impl(
        transfer to, std::index_sequence<indexes...>,
        std::pair<std::tuple<detours...>, std::tuple<originals...>>&& args);

  protected:
    typedef std::pair<const std::byte*, helpers::orig_buff_t> hook_init_item;
    typedef const hook_init_item* hook_init_iterator;
    typedef std::pair<hook_init_iterator, hook_init_iterator> hook_init_range;
    typedef std::initializer_list<hook_init_item>             hook_init_list;

    trampoline& get_trampoline() { return *this; }

    const trampoline& get_trampoline() const { return *this; }

    void set_trampoline(const hook_chain& other)
    {
      trampoline::operator=(other);
      memcpy(backup.data(), other.backup.data(), backup.size());
    }

    void        init_with_list(hook_init_range range);
    list_range  append_list(transfer to, hook_init_range range);
    hook&       happend(const hook& src, bool enable_hook);
    static void hcopy(hook& dest, const hook& src);
    static std::reference_wrapper<hook> empty_ref_wrap();
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
    void enable();
    /// Disable the hook
    void disable();

    /// @}

    /**
     * @name Iterator Getters
     * @brief Get iterators to the current hook instance (either normal or list
     * ones)
     * @{
     */

    iterator       get_iterator() noexcept;
    const_iterator get_iterator() const noexcept;
    const_iterator get_const_iterator() const noexcept;

    list_iterator get_list_iterator() noexcept { return current; }

    const_list_iterator get_list_iterator() const noexcept { return current; }

    const_list_iterator get_const_list_iterator() const noexcept
    {
      return current;
    }

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
      if (originalref() == original)
        return *this;
      set_original(helpers::original_wrapper(original));
      return *this;
    }

    /// @}

    /**
     * @name Comparison
     * @brief Compare two hooks and determine equality if the target, the detour
     * and the status are the same
     * @{
     */

    /// Return `true` if `*this` and `other` are equal, `false` otherwise
    bool operator==(const hook& other) const noexcept;
    /// Return `true` if `*this` and `other` are not equal, `false` otherwise
    bool operator!=(const hook& other) const noexcept;

    /// @}

  private:
    friend class hook_chain;
    template <template <typename> typename alloc>
    friend struct helpers::alloc_wrapper;
    template <typename T, size_t N>
    friend class utils::static_vector;
    typedef std::reference_wrapper<hook_chain> chain_ref_t;

    chain_ref_t          chain;
    list_iterator        current{};
    list_iterator        other{};
    const std::byte*     pdetour   = nullptr;
    const std::byte*     poriginal = nullptr;
    helpers::orig_buff_t origbuff{};
    bool                 enabled   = false;
    bool                 has_other = false;

    hook(const hook&)            = delete;
    hook& operator=(const hook&) = delete;

    template <typename orig,
              typename = std::enable_if_t<utils::function_type<orig>>>
    hook(hook_chain& chain, const std::byte* pdetour, orig& origref,
         const std::byte* poriginal = nullptr, bool should_enable = false);
    hook(hook_chain& chain, const std::byte* detour,
         const helpers::orig_buff_t& buffer,
         const std::byte* poriginal = nullptr, bool should_enable = false);

    helpers::original& originalref() noexcept
    {
      return *std::launder(reinterpret_cast<helpers::original*>(&origbuff));
    }

    const helpers::original& originalref() const noexcept
    {
      return *std::launder(
          reinterpret_cast<const helpers::original*>(&origbuff));
    }

    void redirect_originalref(const std::byte* original) noexcept
    {
      originalref() = poriginal = original;
    }

    void set_detour(std::byte* detour);
    void set_original(helpers::orig_buff_t original);
    void swap(hook& right);
  };

  /**
   * @brief A forward iterator that makes it possible to loop over all the
   * elements of a @ref alterhook::hook_chain instance (i.e. both enabled and
   * disabled) in the order they were inserted.
   *
   * This order is not affected by any changes in the status of the hooks and
   * therefore remains constant unless explicitly updated (e.g. when the
   * splicers or swappers are used). However when a hook changes status any
   * `iterator` that points to it will be invalidated. Also since `iterator`
   * is based on `list_iterator` it won't be invalidated by any changes in the
   * order of the hooks or by the addition of new ones, but it will be
   * invalidated if the corresponding hook is erased from the
   * @ref alterhook::hook_chain instance.
   * @note The order in which elements appear when iterating through the
   * container using an `iterator` is often referred to by the documentation
   * of @ref alterhook::hook_chain as the **iteration order** (i.e. the
   * insertion order) which as mentioned is NOT affected by any changes in the
   * status of the hooks.
   */
  class hook_chain::iterator
  {
  public:
#if utils_cpp20
    typedef std::forward_iterator_tag iterator_concept;
#endif
    typedef std::forward_iterator_tag iterator_category;
    typedef hook                      value_type;
    typedef ptrdiff_t                 difference_type;
    typedef hook*                     pointer;
    typedef hook&                     reference;

    iterator() noexcept = default;

    reference operator*() const noexcept { return *itrs[enabled]; }

    pointer operator->() const noexcept { return itrs[enabled].operator->(); }

    iterator& operator++() noexcept;
    iterator  operator++(int) noexcept;

    bool operator==(const iterator& other) const noexcept
    {
      return enabled == other.enabled && itrs[enabled] == other.itrs[enabled];
    }

    bool operator!=(const iterator& other) const noexcept
    {
      return enabled != other.enabled || itrs[enabled] != other.itrs[enabled];
    }

    operator list_iterator() const noexcept { return itrs[enabled]; }

    operator const_list_iterator() const noexcept { return itrs[enabled]; }

  private:
    friend class hook_chain;
    std::array<list_iterator, 2> itrs{};
    bool                         enabled = false;

    explicit iterator(list_iterator ditr, list_iterator eitr,
                      bool enabled) noexcept
        : itrs({ ditr, eitr }), enabled(enabled)
    {
    }
  };

  /// @brief Const version of @ref alterhook::hook_chain::iterator, which means
  /// no hook can be modified through an instance of it
  class hook_chain::const_iterator
  {
  public:
#if utils_cpp20
    typedef std::forward_iterator_tag iterator_concept;
#endif
    typedef std::forward_iterator_tag iterator_category;
    typedef hook                      value_type;
    typedef ptrdiff_t                 difference_type;
    typedef const hook*               pointer;
    typedef const hook&               reference;

    const_iterator() noexcept = default;

    reference operator*() const noexcept { return *itrs[enabled]; }

    pointer operator->() const noexcept { return itrs[enabled].operator->(); }

    const_iterator& operator++() noexcept;
    const_iterator  operator++(int) noexcept;

    bool operator==(const const_iterator& other) const noexcept
    {
      return enabled == other.enabled && itrs[enabled] == other.itrs[enabled];
    }

    bool operator!=(const const_iterator& other) const noexcept
    {
      return enabled != other.enabled || itrs[enabled] != other.itrs[enabled];
    }

    operator const_list_iterator() const noexcept { return itrs[enabled]; }

  private:
    friend class hook_chain;
    friend class iterator;
    std::array<const_list_iterator, 2> itrs{};
    bool                               enabled = false;

    explicit const_iterator(const_list_iterator ditr, const_list_iterator eitr,
                            bool enabled) noexcept
        : itrs({ ditr, eitr }), enabled(enabled)
    {
    }
  };

  /*
   * IMPLEMENTATION
   */

  /*
   * TEMPLATE DEFINITIONS
   */
  template <typename dtr, typename orig, typename... types, typename>
  hook_chain::hook_chain(std::byte* target, dtr&& detour, orig& original,
                         types&&... rest)
      : trampoline(target)
  {
    init_chain(utils::make_index_sequence_with_step<sizeof...(types) + 2>(),
               utils::make_index_sequence_with_step<sizeof...(types) + 2, 1>(),
               std::forward_as_tuple(std::forward<dtr>(detour), original,
                                     std::forward<types>(rest)...));
  }

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

  template <typename pair, typename... types, typename>
  hook_chain::hook_chain(std::byte* target, pair&& first, types&&... rest)
      : trampoline(target)
  {
    init_chain(
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

  template <typename trg, typename pair, typename... types, typename>
  hook_chain::hook_chain(trg&& target, pair&& first, types&&... rest)
      : hook_chain(get_target_address(std::forward<trg>(target)),
                   std::forward<pair>(first), std::forward<types>(rest)...)
  {
    helpers::assert_valid_target_and_detours<trg>(
        helpers::extract_detour_sequence_from_tuples_t<pair, types...>());
  }

  template <typename orig, typename>
  hook_chain::hook_chain(const alterhook::hook& other, orig& original)
      : trampoline(other)
  {
    memcpy(backup.data(), other.backup.data(), backup.size());
    list_iterator itr = disabled.emplace(
        disabled.end(), *this, other.pdetour, original,
        helpers::resolve_original(ptarget, ptrampoline.get()), false);
    itr->current = itr;
  }

  template <size_t... d_indexes, size_t... o_indexes, typename... types>
  void hook_chain::init_chain(std::index_sequence<d_indexes...>,
                              std::index_sequence<o_indexes...>,
                              std::tuple<types...>&& args)
  {
    typedef utils::type_sequence<types...> seq;
    init_chain(std::make_index_sequence<sizeof...(d_indexes)>(),
               std::pair(std::forward_as_tuple(
                             std::forward<utils::type_at_t<d_indexes, seq>>(
                                 std::get<d_indexes>(args))...),
                         std::forward_as_tuple(
                             std::forward<utils::type_at_t<o_indexes, seq>>(
                                 std::get<o_indexes>(args))...)));
  }

  template <typename... detours, typename... originals, size_t... indexes>
  void hook_chain::init_chain(
      std::index_sequence<indexes...>,
      std::pair<std::tuple<detours...>, std::tuple<originals...>>&& args)
  {
    helpers::assert_valid_detour_and_original_pairs(
        utils::type_sequence<detours...>(),
        utils::type_sequence<originals...>());
    hook_init_list arg_list = {
      {get_target_address<originals>(
            std::forward<detours>(std::get<indexes>(args.first))),
       helpers::original_wrapper(std::get<indexes>(args.second))}
      ...
    };
    init_with_list({ arg_list.begin(), arg_list.end() });
  }

  template <size_t... d_indexes, size_t... o_indexes, typename... types>
  typename hook_chain::list_range
      hook_chain::append_impl(transfer to, std::index_sequence<d_indexes...>,
                              std::index_sequence<o_indexes...>,
                              std::tuple<types...>&& args)
  {
    typedef utils::type_sequence<types...> seq;
    return append_impl(
        to, std::make_index_sequence<sizeof...(d_indexes)>(),
        std::pair(std::forward_as_tuple(
                      std::forward<utils::type_at_t<d_indexes, seq>>(
                          std::get<d_indexes>(args))...),
                  std::forward_as_tuple(
                      std::forward<utils::type_at_t<o_indexes, seq>>(
                          std::get<o_indexes>(args))...)));
  }

  template <typename... detours, typename... originals, size_t... indexes>
  typename hook_chain::list_range hook_chain::append_impl(
      transfer to, std::index_sequence<indexes...>,
      std::pair<std::tuple<detours...>, std::tuple<originals...>>&& args)
  {
    helpers::assert_valid_detour_and_original_pairs(
        utils::type_sequence<detours...>(),
        utils::type_sequence<originals...>());
    hook_init_list arg_list = {
      {get_target_address<originals>(
            std::forward<detours>(std::get<indexes>(args.first))),
       helpers::original_wrapper(std::get<indexes>(args.second))}
      ...
    };
    return append_list(to, { arg_list.begin(), arg_list.end() });
  }

  template <typename orig, typename>
  hook_chain::hook::hook(hook_chain& chain, const std::byte* pdetour,
                         orig& origref, const std::byte* poriginal,
                         bool should_enable)
      : chain(chain), pdetour(pdetour), poriginal(poriginal),
        origbuff(helpers::original_wrapper(origref)), enabled(should_enable)
  {
    if (poriginal)
      originalref() = poriginal;
  }

  template <typename dtr, typename orig, typename>
  hook_chain::hook& hook_chain::insert(list_iterator position, dtr&& detour,
                                       orig& original, include trg)
  {
    helpers::assert_valid_detour_original_pair<dtr, orig>();
    utils_assert(trg != include::both,
                 "hook_chain::insert: base cannot be the both flag");
    return insert_impl(position,
                       get_target_address<orig>(std::forward<dtr>(detour)),
                       helpers::original_wrapper(original), trg);
  }

  template <typename dtr, typename orig, typename>
  hook_chain::hook& hook_chain::insert(iterator position, dtr&& detour,
                                       orig& original)
  {
    return insert(static_cast<list_iterator>(position),
                  std::forward<dtr>(detour), original,
                  position.enabled ? include::enabled : include::disabled);
  }

  template <typename dtr, typename orig, typename... types, typename>
  typename hook_chain::list_range hook_chain::append(transfer to, dtr&& detour,
                                                     orig& original,
                                                     types&&... rest)
  {
    if constexpr (sizeof...(rest) == 0)
    {
      push_back(std::forward<dtr>(detour), original, static_cast<bool>(to));
      hook_list& trg_list = to == transfer::enabled ? enabled : disabled;
      return { std::prev(trg_list.end()), trg_list.end() };
    }
    else
      return append_impl(
          to, utils::make_index_sequence_with_step<sizeof...(rest) + 2>(),
          utils::make_index_sequence_with_step<sizeof...(rest) + 2, 1>(),
          std::forward_as_tuple(std::forward<dtr>(detour), original,
                                std::forward<types>(rest)...));
  }

  template <typename dtr, typename orig, typename... types, typename>
  typename hook_chain::list_range
      hook_chain::append(dtr&& detour, orig& original, types&&... rest)
  {
    return append(transfer::enabled, std::forward<dtr>(detour), original,
                  std::forward<types>(rest)...);
  }

  template <typename pair, typename... types, typename>
  typename hook_chain::list_range hook_chain::append(transfer to, pair&& first,
                                                     types&&... rest)
  {
    if constexpr (sizeof...(rest) == 0)
    {
      push_back(
          std::forward<std::tuple_element_t<0, utils::remove_cvref_t<pair>>>(
              std::get<0>(first)),
          std::forward<std::tuple_element_t<1, utils::remove_cvref_t<pair>>>(
              std::get<1>(first)),
          static_cast<bool>(to));
      hook_list& trg_list = to == transfer::enabled ? enabled : disabled;
      return { std::prev(trg_list.end()), trg_list.end() };
    }
    else
      return append_impl(
          to, std::make_index_sequence<sizeof...(rest) + 1>(),
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
  typename hook_chain::list_range hook_chain::append(pair&& first,
                                                     types&&... rest)
  {
    return append(transfer::enabled, std::forward<pair>(first),
                  std::forward<types>(rest)...);
  }

  template <typename dtr, typename orig, typename>
  typename hook_chain::hook& hook_chain::push_back(dtr&& detour, orig& original,
                                                   bool enable_hook)
  {
    return push_back_impl(get_target_address<orig>(std::forward<dtr>(detour)),
                          helpers::original_wrapper(original), enable_hook);
  }

  template <typename dtr, typename orig, typename>
  typename hook_chain::hook&
      hook_chain::push_front(dtr&& detour, orig& original, bool enable_hook)
  {
    return push_front_impl(get_target_address<orig>(std::forward<dtr>(detour)),
                           helpers::original_wrapper(original), enable_hook);
  }

  /*
   * NON-TEMPLATE DEFINITIONS
   */
  inline hook_chain::hook_chain(std::byte* target) : trampoline(target)
  {
    helpers::make_backup(target, backup.data(), patch_above);
  }

  inline hook_chain::iterator hook_chain::erase(iterator position)
  {
    iterator next = std::next(position);
    erase(static_cast<list_iterator>(position));
    return next;
  }

  inline void hook_chain::merge(hook_chain& other, bool at_back)
  {
    iterator where = at_back ? end() : begin();
    splice(where, other, other.begin(), other.end());
  }

  inline void hook_chain::splice(iterator newpos, hook_chain& other,
                                 transfer from)
  {
    splice(static_cast<list_iterator>(newpos), other,
           newpos.enabled ? transfer::enabled : transfer::disabled, from);
  }

  inline void hook_chain::splice(iterator newpos, hook_chain&& other,
                                 transfer from)
  {
    splice(newpos, other, from);
  }

  inline void hook_chain::splice(iterator newpos, hook_chain& other,
                                 list_iterator oldpos)
  {
    splice(static_cast<list_iterator>(newpos), other, oldpos,
           newpos.enabled ? transfer::enabled : transfer::disabled);
  }

  inline void hook_chain::splice(iterator newpos, hook_chain&& other,
                                 list_iterator oldpos)
  {
    splice(newpos, other, oldpos);
  }

  inline void hook_chain::splice(iterator newpos, hook_chain& other,
                                 list_iterator first, list_iterator last)
  {
    splice(static_cast<list_iterator>(newpos), other, first, last,
           newpos.enabled ? transfer::enabled : transfer::disabled);
  }

  inline void hook_chain::splice(iterator newpos, hook_chain&& other,
                                 list_iterator first, list_iterator last)
  {
    splice(newpos, other, first, last);
  }

  inline void hook_chain::splice(list_iterator newpos, hook_chain&& other,
                                 iterator first, iterator last, transfer to)
  {
    splice(newpos, other, first, last, to);
  }

  inline void hook_chain::splice(iterator newpos, hook_chain& other,
                                 iterator first, iterator last)
  {
    splice(static_cast<list_iterator>(newpos), other, first, last,
           newpos.enabled ? transfer::enabled : transfer::disabled);
  }

  inline void hook_chain::splice(iterator newpos, hook_chain&& other,
                                 iterator first, iterator last)
  {
    splice(newpos, other, first, last);
  }

  inline void hook_chain::splice(iterator newpos, list_iterator oldpos)
  {
    splice(static_cast<list_iterator>(newpos), oldpos,
           newpos.enabled ? transfer::enabled : transfer::disabled);
  }

  inline void hook_chain::splice(iterator newpos, list_iterator first,
                                 list_iterator last)
  {
    splice(static_cast<list_iterator>(newpos), first, last,
           newpos.enabled ? transfer::enabled : transfer::disabled);
  }

  inline void hook_chain::splice(list_iterator newpos, iterator first,
                                 iterator last, transfer to)
  {
    splice(newpos, *this, first, last, to);
  }

  inline void hook_chain::splice(iterator newpos, iterator first, iterator last)
  {
    splice(static_cast<list_iterator>(newpos), first, last,
           newpos.enabled ? transfer::enabled : transfer::disabled);
  }

  inline typename hook_chain::iterator hook_chain::begin() noexcept
  {
    return iterator(disabled.begin(), enabled.begin(), starts_enabled);
  }

  inline typename hook_chain::iterator hook_chain::end() noexcept
  {
    return iterator(disabled.end(), enabled.end(),
                    disabled.empty() ? starts_enabled
                                     : disabled.back().has_other);
  }

  inline typename hook_chain::const_iterator hook_chain::begin() const noexcept
  {
    return const_iterator(disabled.begin(), enabled.begin(), starts_enabled);
  }

  inline typename hook_chain::const_iterator hook_chain::end() const noexcept
  {
    return const_iterator(disabled.end(), enabled.end(),
                          disabled.empty() ? starts_enabled
                                           : disabled.back().has_other);
  }

  inline typename hook_chain::const_iterator hook_chain::cbegin() const noexcept
  {
    return begin();
  }

  inline typename hook_chain::const_iterator hook_chain::cend() const noexcept
  {
    return end();
  }

#define __alterhook_def_getter_impl(type, name, func, list, cv)                \
  inline typename hook_chain::type hook_chain::name() cv noexcept              \
  {                                                                            \
    return list.func();                                                        \
  }

#define __alterhook_const_layer_getter_impl(type, name, func, list)            \
  __alterhook_def_getter_impl(const_##type, c##name, func, list, const)        \
      __alterhook_def_getter_impl(const_##type, name, func, list, const)       \
          __alterhook_def_getter_impl(type, name, func, list, )

#define __alterhook_reverse_layer_getter_impl(type, name, func, list)          \
  __alterhook_const_layer_getter_impl(reverse_##type, r##name, r##func, list)  \
      __alterhook_const_layer_getter_impl(type, name, func, list)

#define __alterhook_range_layer_getter_impl(prefix, list)                      \
  __alterhook_reverse_layer_getter_impl(list_iterator, prefix##begin, begin,   \
                                        list)                                  \
      __alterhook_reverse_layer_getter_impl(list_iterator, prefix##end, end,   \
                                            list)

#define __alterhook_state_layer_itr_getter_impl()                              \
  __alterhook_range_layer_getter_impl(e, enabled)                              \
      __alterhook_range_layer_getter_impl(d, disabled)

#define __alterhook_gen_itr_getter_definitions()                               \
  __alterhook_state_layer_itr_getter_impl()

  __alterhook_gen_itr_getter_definitions();

  inline void hook_chain::assert_len([[maybe_unused]] size_t n) const
  {
    utils_assert(
        n < size(),
        "hook_chain::operator[]: element at index specified is out of range");
  }

  inline void hook_chain::verify_len(size_t n) const
  {
    if (n < size())
      return;
    std::stringstream stream{};
    stream << "Element at index " << n
           << " of the hook_chain instance is out of range because: n >= "
              "size() <=> "
           << n << " >= " << size();
    throw(std::out_of_range(stream.str()));
  }

  inline typename hook_chain::reference
      hook_chain::operator[](size_t n) noexcept
  {
    assert_len(n);
    return *std::next(begin(), n);
  }

  inline typename hook_chain::const_reference
      hook_chain::operator[](size_t n) const noexcept
  {
    assert_len(n);
    return *std::next(begin(), n);
  }

  inline typename hook_chain::reference hook_chain::at(size_t n)
  {
    verify_len(n);
    return *std::next(begin(), n);
  }

  inline typename hook_chain::const_reference hook_chain::at(size_t n) const
  {
    verify_len(n);
    return *std::next(begin(), n);
  }

  inline typename hook_chain::reference hook_chain::front() noexcept
  {
    return *begin();
  }

  inline typename hook_chain::const_reference hook_chain::front() const noexcept
  {
    return *begin();
  }

  inline typename hook_chain::const_reference
      hook_chain::cfront() const noexcept
  {
    return front();
  }

  inline typename hook_chain::reference hook_chain::back() noexcept
  {
    if (disabled.empty() || disabled.back().has_other)
      return enabled.back();
    return disabled.back();
  }

  inline typename hook_chain::const_reference hook_chain::back() const noexcept
  {
    if (disabled.empty() || disabled.back().has_other)
      return enabled.back();
    return disabled.back();
  }

  inline typename hook_chain::const_reference hook_chain::cback() const noexcept
  {
    return back();
  }

#define __alterhook_side_layer_getter_impl(prefix, list)                       \
  __alterhook_const_layer_getter_impl(reference, prefix##front, front, list)   \
      __alterhook_const_layer_getter_impl(reference, prefix##back, back, list)

#define __alterhook_gen_elem_access_definitions()                              \
  __alterhook_side_layer_getter_impl(e, enabled)                               \
      __alterhook_side_layer_getter_impl(d, disabled)

  __alterhook_gen_elem_access_definitions();

  inline void hook_chain::unbind_range_callback::set_pchain(list_iterator itr,
                                                            hook_chain* pchain)
  {
    itr->chain = *pchain;
  }

  inline void hook_chain::unbind_range_callback::set_enabled(list_iterator itr,
                                                             bool status)
  {
    itr->enabled = status;
  }

  inline void
      hook_chain::unbind_range_callback::set_has_other(list_iterator itr,
                                                       bool          status)
  {
    itr->has_other = status;
  }

  inline void hook_chain::unbind_range_callback::set_other(list_iterator itr,
                                                           list_iterator other)
  {
    itr->other = other;
  }

  inline typename hook_chain::hook& hook_chain::happend(const hook& src,
                                                        bool        enable_hook)
  {
    return push_back_impl(src.pdetour, src.origbuff, enable_hook);
  }

  inline void hook_chain::hcopy(hook& dest, const hook& src)
  {
    dest.pdetour  = src.pdetour;
    dest.origbuff = src.origbuff;
  }

  inline hook_chain::const_iterator&
      hook_chain::const_iterator::operator++() noexcept
  {
    if (itrs[enabled]->has_other)
    {
      itrs[!enabled] = itrs[enabled]->other;
      enabled        = !enabled;
    }
    else
      ++itrs[enabled];
    return *this;
  }

  inline hook_chain::const_iterator
      hook_chain::const_iterator::operator++(int) noexcept
  {
    const_iterator tmp = *this;
    operator++();
    return tmp;
  }

  inline hook_chain::iterator& hook_chain::iterator::operator++() noexcept
  {
    if (itrs[enabled]->has_other)
    {
      itrs[!enabled] = itrs[enabled]->other;
      enabled        = !enabled;
    }
    else
      ++itrs[enabled];
    return *this;
  }

  inline hook_chain::iterator hook_chain::iterator::operator++(int) noexcept
  {
    iterator tmp = *this;
    operator++();
    return tmp;
  }

  inline hook_chain::iterator hook_chain::hook::get_iterator() noexcept
  {
    return iterator(current, current, enabled);
  }

  inline hook_chain::const_iterator
      hook_chain::hook::get_iterator() const noexcept
  {
    return const_iterator(current, current, enabled);
  }

  inline hook_chain::const_iterator
      hook_chain::hook::get_const_iterator() const noexcept
  {
    return get_iterator();
  }

  inline hook_chain::hook::hook(hook_chain& chain, const std::byte* pdetour,
                                const helpers::orig_buff_t& buffer,
                                const std::byte* poriginal, bool should_enable)
      : chain(chain), pdetour(pdetour), poriginal(poriginal), origbuff(buffer),
        enabled(should_enable)
  {
    if (poriginal)
      originalref() = poriginal;
  }
} // namespace alterhook

#if utils_msvc
  #pragma warning(pop)
#elif utils_clang
  #pragma clang diagnostic pop
#endif
