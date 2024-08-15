/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include <array>
#include "detail/constants.h"
#include "trampoline.h"

namespace alterhook
{
  /**
   * @brief A class representing an individual inline hook, that is a class
   * capable of redirecting execution from the target function to the detour and
   * back.
   *
   * It consists of 5 main properties: the **target**, the **detour**, the
   * **original callback**, the **trampoline function** and of course the
   * **status**. The **trampoline function** and the **target** are both managed
   * by the @ref alterhook::trampoline "trampoline class" which is inherited
   * from this one for convenience. The **detour** refers to the function to
   * which execution will be redirected, which can be of any callable type the
   * library can handle. The **original callback** is a (usually static)
   * variable of a function-like type (i.e. one that satisfies
   * @ref alterhook::utils::function_type) that is accessible from inside the
   * detour and is used to call back the original function. One may wonder, why
   * not call the original directly? and the answer is simple: it is because the
   * original's first few bytes of code have been replaced by a jump to the
   * detour and an attempt to call the original as is would lead to infinite
   * recursion. To solve this problem the original callback is meant to hold an
   * address to the **trampoline function** which when called will forward
   * execution safely back to the original function. Therefore the library takes
   * a reference of the said callback and makes sure to put the address of the
   * trampoline function to it. One thing to note is that this class allows a
   * hook to be instantiated without the original callback as the detour may not
   * always need to call back the original function which allows a user to fully
   * override the behavior of it. The **status** property denotes whether the
   * hook is enabled or not. Enabled means the redirection to the detour is
   * currently active, while disabled means the opposite.
   */
  class ALTERHOOK_API hook : trampoline
  {
  public:
    /**
     * @name Constructors with Target, Detour and Original Callback
     * @brief Takes in the target, the detour and the original callback and
     * proceeds to fully initialize the hook instance. It also enables the hook
     * if the additional parameter `enable_hook` is set to true (the default)
     * @par Exceptions
     * - @ref trampoline-init-exceptions
     * - @ref thread-freezer-exceptions
     * - @ref target-injection-exceptions
     * @{
     */

    /// @brief Construct with a raw pointer to the target, the detour and the
    /// reference to the original callback. Optionally specifying whether to
    /// enable the hook (default is true).
    template <
        typename dtr, typename orig,
        typename = std::enable_if_t<utils::detours_and_originals<dtr, orig&>>>
    hook(std::byte* target, dtr&& detour, orig& original,
         bool enable_hook = true);

    /// @brief Construct with the target the detour and the reference to the
    /// original callback. Optionally specifying whether to enable the hook
    /// (default is true)
    template <
        typename trg, typename dtr, typename orig,
        typename = std::enable_if_t<utils::callable_type<trg> &&
                                    utils::detours_and_originals<dtr, orig&>>>
    hook(trg&& target, dtr&& detour, orig& original, bool enable_hook = true);

    /// @}

    /**
     * @name Constructors with Target and Detour
     * @brief Takes in the target and the detour and proceeds to initialize the
     * hook instance. It also enables the hook if the additional parameter
     * `enable_hook` is set to true (the default).
     * @par Exceptions
     * - @ref trampoline-init-exceptions
     * - @ref thread-freezer-exceptions
     * - @ref target-injection-exceptions
     * @{
     */

    /// @brief Construct with a raw pointer to the target and the detour.
    /// Optionally specifying whether to enable the hook (default is true).
    template <typename dtr,
              typename = std::enable_if_t<utils::callable_type<dtr>>>
    hook(std::byte* target, dtr&& detour, bool enable_hook = true);

    /// @brief Construct with the target and the detour. Optionally specifying
    /// whether to enable the hook (default is true).
    template <typename trg, typename dtr,
              typename = std::enable_if_t<utils::callable_type<trg> &&
                                          utils::callable_type<dtr>>>
    hook(trg&& target, dtr&& detour, bool enable_hook = true);

    /// @}

    /**
     * @brief Copies the trampoline and all the other properties (except for the
     * state) from `other` to `*this`.
     * @param other the hook to copy from
     * @par Exceptions
     * - @ref trampoline-copy-exceptions
     *
     * As mentioned the state isn't copied, which means that regardless of
     * whether `other` is enabled or not, the new hook will stay as disabled.
     */
    hook(const hook& other);
    /**
     * @brief Moves the trampoline and all the other properties from `other` to
     * `*this` leaving `other` uninitialized but reusable.
     * @param other the hook to move from
     *
     * The new hook instance will now be responsible for managing what was
     * previously managed by `other` and `other` can be reused by subsequent
     * calls to @ref alterhook::hook::set_target(std::byte*),
     * @ref alterhook::hook::set_detour etc.
     */
    hook(hook&& other) noexcept;

    /**
     * @brief Constructs a new hook with a copy of the trampoline `tramp`.
     * @param tramp the trampoline to copy from
     * @par Exceptions
     * - @ref trampoline-copy-exceptions
     */
    hook(const trampoline& tramp) : trampoline(tramp)
    {
      helpers::make_backup(ptarget, backup.data(), patch_above);
    }

    /**
     * @brief Constructs a new hook while claiming ownership of the trampoline
     * `tramp`
     * @param tramp the trampoline to move from
     */
    hook(trampoline&& tramp) noexcept : trampoline(std::move(tramp))
    {
      helpers::make_backup(ptarget, backup.data(), patch_above);
    }

    /// Default constructs a hook and leaves it uninitialized
    hook() noexcept {}

    /// Disables the hook (if enabled) and destructs the trampoline
    ~hook() noexcept;

    /**
     * @brief Disables the current hook and replaces all properties of `*this`
     * with a copy of those of `other`.
     * @param other the hook to copy from
     * @returns `*this`
     * @par Exceptions
     * - @ref trampoline-copy-exceptions
     * - @ref thread-freezer-exceptions
     * - @ref target-injection-exceptions
     */
    hook& operator=(const hook& other);
    /**
     * @brief Disables the hook (if enabled) and moves all properties of `other`
     * to `*this`, claiming ownership of the hook previously maintained by
     * `other`.
     * @param other the hook to move from
     * @returns `*this`
     */
    hook& operator=(hook&& other) noexcept;
    /**
     * @brief Disables the hook (if enabled), copy assigns the trampoline stored
     * on `*this` with `other` and re-enables the hook (if previously enabled).
     * As the target is stored in the trampoline this may also redirect the hook
     * to a new target.
     * @param other the trampoline to copy assign from
     * @returns `*this`
     * @par Exceptions
     * - @ref trampoline-copy-exceptions
     * - @ref thread-freezer-exceptions (only if currently enabled)
     * - @ref target-injection-exceptions (only if currently enabled)
     */
    hook& operator=(const trampoline& other);
    /**
     * @brief Disables the hook (if enabled), move assigns the trampoline stored
     * on `*this` with `other` and re-enables afterwards (if previously
     * enabled). This will claim ownership of the trampoline function of `other`
     * and may redirect the hook to a new target.
     * @param other the trampoline to move assign from
     * @returns `*this`
     * @par Exceptions
     * - @ref thread-freezer-exceptions (only if currently enabled)
     * - @ref target-injection-exceptions (only if currently enabled)
     */
    hook& operator=(trampoline&& other);

    /**
     * @name Status Updaters
     * @brief Update the status of the hook, that is whether it's enabled or
     * not. If the target status is the same as the current one then nothing is
     * done.
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
     * @name Getters
     * @brief retrieve information about the current hook instance.
     * @{
     */

    using trampoline::get_target;

    /// Returns a pointer to the detour currently in use, `nullptr` if none.
    const std::byte* get_detour() const noexcept { return pdetour; }

    /// Returns the result of @ref alterhook::trampoline::size
    size_t trampoline_size() const noexcept { return size(); }

    /// Returns the result of @ref alterhook::trampoline::count
    size_t trampoline_count() const noexcept { return count(); }

    /// Returns the result of @ref alterhook::trampoline::str
    std::string trampoline_str() const { return str(); }

    /// Returns `true` if the hook is enabled, `false` otherwise
    bool is_enabled() const noexcept { return enabled; }

    /// @brief Convenient conversion operator that returns the same thing
    /// @ref alterhook::hook::is_enabled does
    explicit operator bool() const noexcept { return enabled; }

    /// @}

    /**
     * @name Setters
     * @brief Set/Update some of the hook's properties using any of the
     * following methods.
     * @{
     */

    /**
     * @brief If the hook is currently targetless, this can be used to
     * initialize the instance using `target` (similar to
     * @ref alterhook::trampoline::init()), otherwise it overrides the existing
     * target with the one specified and regenerates the trampoline function.
     * @param target the target to update/initialize the instance with
     * @returns `*this`
     *
     * @par Exceptions
     * - @ref trampoline-init-exceptions
     * - @ref thread-freezer-exceptions
     * - @ref target-injection-exceptions
     * @par Exception Guarantee
     * - strong: Provided when one of the following cases are true
     *   + It is already enabled and an attempt to disable the hook failed (can
     *     be verified by checking that @ref alterhook::hook::is_enabled ==
     *     `true`)
     *   + It is not enabled and the exception thrown is in the group
     *     @ref memalloc-and-address-validation
     * - basic: For everything else the guarantee provided is basic. The cases
     *   are the following
     *   + It is already enabled and the exception thrown belongs in the group
     *     @ref memalloc-and-address-validation. The hook is left with the same
     *     properties as before except that now it's disabled.
     *   + The exception belongs in the group @ref trampoline-init-exceptions
     *     but not on @ref memalloc-and-address-validation. The hook is left
     *     target-less and therefore uninitialized.
     *   + If it's neither of the other two then the exception must be due to a
     *     failed attempt to re-enable the hook (when it was enabled before).
     *     The hook's target has been successfully overriden in that case but
     *     left disabled.
     * @note If the current instance is NOT target-less it is first disabled
     * from the old target and then re-enabled to the new one. Otherwise, no
     * status updates occur. You can prevent the hook from being re-enabled to
     * the new target by making sure it's manually disabled before calling this
     * method.
     */
    hook& set_target(std::byte* target);

    /**
     * @brief Same as @ref alterhook::hook::set_target(std::byte*) except it
     * handles any callable passed (not raw addresses).
     * @tparam trg the callable type of the target passed (must satisfy
     * @ref alterhook::utils::callable_type)
     * @param target the target to use
     * @returns `*this`
     */
    template <typename trg,
              typename = std::enable_if_t<utils::callable_type<trg>>>
    hook& set_target(trg&& target)
    {
      return set_target(get_target_address(std::forward<trg>(target)));
    }

    /**
     * @brief Overrides (or sets) the hook's detour with `detour`
     * @tparam dtr the callable type of the detour passed (must satisfy
     * @ref alterhook::utils::callable_type)
     * @param detour the detour to use
     * @returns `*this`
     *
     * @par Exceptions
     * - @ref thread-freezer-exceptions (only if currently enabled)
     * - @ref target-injection-exceptions (only if currently enabled)
     * @note If the hook is enabled before calling the setter, then instead of
     * disabling and re-enabling (which can be costly for performance), it
     * directly patches the jump, redirecting it to the new detour. This also
     * provides always strong guarantee.
     */
    template <typename dtr,
              typename = std::enable_if_t<utils::callable_type<dtr>>>
    hook& set_detour(dtr&& detour);

    /**
     * @brief Sets `original` to the trampoline function (for invocation from
     * inside the detour) and sets the old callback (if any) to `nullptr`.
     * @tparam orig the function-like type of the original callback (must
     * satisfy @ref alterhook::utils::function_type)
     * @param original the reference to the original callback that should be
     * invoked from the detour.
     * @returns `*this`
     *
     * @par Exceptions
     * - @ref thread-freezer-exceptions (only if currently enabled)
     * @note Just like @ref alterhook::hook::set_detour this also doesn't
     * disable and re-enable the hook. What it does is freezing all threads (to
     * avoid data races with the original callbacks) and then does what it's
     * expected to do.
     */
    template <typename orig,
              typename = std::enable_if_t<utils::function_type<orig>>>
    hook& set_original(orig& original);

    /**
     * @brief Resets the original callback, that is setting the callback used to
     * invoke the original function to `nullptr`.
     * @returns `*this`
     * @par Exceptions
     * - @ref thread-freezer-exceptions (only if currently enabled)
     */
    hook& reset_original();

    /// @}

    /**
     * @name Comparison
     * @brief Compare two hook instances and determine equality if the target,
     * the detour and the status (i.e. enabled or disabled) compare equal.
     * @{
     */

    /// Return `true` if `*this` and `other` are equal, `false` otherwise.
    bool operator==(const hook& other) const noexcept;
    /// Return `true` if `*this` and `other` are not equal, `false` otherwise.
    bool operator!=(const hook& other) const noexcept;

    /// @}

  private:
    friend class hook_chain;
#ifdef __alterhook_expose_impl
    friend struct injectors;
#endif

    typedef std::array<std::byte, detail::constants::backup_size> backup_t;

    const std::byte*     pdetour = nullptr;
    bool                 enabled = false;
    backup_t             backup{};
    helpers::orig_buff_t original_buffer{};
    helpers::original*   original_wrap = nullptr;

    void set_detour(std::byte* detour);
    void set_original(helpers::orig_buff_t original);
  };

  template <typename dtr, typename orig, typename>
  hook::hook(std::byte* target, dtr&& detour, orig& original, bool enable_hook)
      : trampoline(target),
        pdetour(get_target_address<orig>(std::forward<dtr>(detour))),
        original_buffer(helpers::original_wrapper(original)),
        original_wrap(std::launder(
            reinterpret_cast<helpers::original*>(&original_buffer)))
  {
    helpers::assert_valid_detour_original_pair<dtr, orig>();
    helpers::make_backup(target, backup.data(), patch_above);
    original = function_cast<orig>(
        helpers::resolve_original(target, ptrampoline.get()));
    utils_assert(target != pdetour,
                 "hook::hook: detour & target have the same address");
    if (enable_hook)
      enable();
  }

  template <typename dtr, typename>
  hook::hook(std::byte* target, dtr&& detour, bool enable_hook)
      : trampoline(target),
        pdetour(get_target_address(std::forward<dtr>(detour)))
  {
    helpers::make_backup(target, backup.data(), patch_above);
    utils_assert(target != pdetour,
                 "hook::hook: detour & target have the same address");
    if (enable_hook)
      enable();
  }

  template <typename trg, typename dtr, typename orig, typename>
  hook::hook(trg&& target, dtr&& detour, orig& original, bool enable_hook)
      : hook(get_target_address(std::forward<trg>(target)),
             std::forward<dtr>(detour), original, enable_hook)
  {
    helpers::assert_valid_target_and_detour_pair<
        trg, utils::try_disambiguate_t<dtr, orig>>();
  }

  template <typename trg, typename dtr, typename>
  hook::hook(trg&& target, dtr&& detour, bool enable_hook)
      : hook(get_target_address(std::forward<trg>(target)),
             std::forward<dtr>(detour), enable_hook)
  {
    helpers::assert_valid_target_and_detour_pair<trg, dtr>();
  }

  template <typename dtr, typename>
  hook& hook::set_detour(dtr&& detour)
  {
    set_detour(get_target_address(std::forward<dtr>(detour)));
    return *this;
  }

  template <typename orig, typename>
  hook& hook::set_original(orig& original)
  {
    if (original_wrap && *original_wrap == original)
      return *this;
    set_original(helpers::original_wrapper(original));
    return *this;
  }
} // namespace alterhook
