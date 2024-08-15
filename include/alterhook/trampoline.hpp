/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include <memory>
#include <string>
#include "tools.h"

#if utils_msvc
  #pragma warning(push)
  #pragma warning(disable : 4251)
#else
  #pragma GCC diagnostic push
  #pragma GCC diagnostic ignored "-Wdeprecated-copy"
#endif

namespace alterhook
{
  /**
   * @brief The low level trampoline manager capable of relocating and
   * generating instructions as well as properly handle memory allocations.
   *
   * Its goal is to mimic the trampoline function that is used in order for
   * detours to properly pass control back to the original. It works by
   * allocating a small buffer from a large executable page (which was
   * allocated from system calls) and use it to relocate the target
   * instructions. The complexity of the relocation process varies based on the
   * target architecture and therefore an implementation of this class is
   * provided for each architecture supported by the library. It may also
   * involve dynamic assembly generation to properly handle some of the
   * relocated instructions without affecting the code's logic (e.g. for
   * pc-handling on the armv7 implementation).
   */
  class ALTERHOOK_API trampoline
  {
  public:
    /**
     * @brief Default constructs the trampoline class, leaving it target-less
     * and uninitialized.
     *
     * No executable buffer is allocated on default construction and it can
     * therefore be used to construct a global instance.
     */
    trampoline() noexcept {}

    /**
     * @name Initializers with Target
     * @{
     */

    /**
     * @param target a raw pointer to the target function from which the
     * instructions will be relocated (must point to executable memory)
     */
    trampoline(std::byte* target) { init(target); }

    /**
     * @tparam trg the callable type of the target (must satisfy
     * @ref alterhook::utils::callable_type)
     * @param target the target to use
     */
    template <typename trg,
              typename = std::enable_if_t<utils::callable_type<trg>>>
    trampoline(trg&& target)
        : trampoline(get_target_address(std::forward<trg>(target)))
    {
    }

    /// @}

    /**
     * @brief Allocates an executable buffer and copies all properties of
     * `other` to `*this`
     * @param other the trampoline to copy from
     * @par Exceptions
     * - @ref trampoline-copy-exceptions
     */
    trampoline(const trampoline& other);
    /**
     * @brief Moves all contents of `other` to `*this` leaving `other`
     * uninitialized.
     * @param other the trampoline to move from
     * @note `other` will be left completely empty which means no executable
     * buffer either, since now `*this` has claimed ownership of it. But can be
     * reused if needed by a subsequent call to any of the initializers.
     */
    trampoline(trampoline&& other) noexcept;
    /**
     * @brief Allocates an executable buffer (if needed) and replaces all
     * properties of `*this` with a copy of those of `other`.
     * @param other the trampoline to copy from
     * @returns `*this`
     * @par Exceptions
     * - @ref trampoline-copy-exceptions
     * @note If there is already an executable buffer allocated on `*this` it
     * will proceed to reuse it.
     */
    trampoline& operator=(const trampoline& other);
    /**
     * @brief Moves all contents of `other` to `*this` overriding the existing
     * ones and leaving `other` uninitialized.
     * @param other the trampoline to move from
     * @returns `*this`
     * @note If there is already an executable buffer allocated it will be
     * deallocated and the one from `other` will be used instead.
     */
    trampoline& operator=(trampoline&& other) noexcept;

    /// deallocates the executable buffer (if it exists).
    ~trampoline() noexcept {}

    /**
     * @name Initializers with Target
     * @brief Constructs and fully initializes a trampoline instance using
     * `target`.
     * @par Exceptions
     * - @ref trampoline-init-exceptions
     * @par Exception Guarantee
     * - strong: Only when the exception thrown is derived either from
     *   @ref alterhook::exceptions::misc_exception or
     *   @ref alterhook::exceptions::os_exception
     * - basic: On any other exception the trampoline instance is left
     *   uninitialized (but keeps the executable buffer to avoid future
     *   allocations)
     * @{
     */

    /**
     * @param target a raw pointer to the target function from which the
     * instructions will be relocated (must point to executable memory)
     */
    void init(std::byte* target);

    /**
     * @tparam trg the callable type of the target (must satisfy
     * @ref alterhook::utils::callable_type)
     * @param target the target to use
     */
    template <typename trg,
              typename = std::enable_if_t<utils::callable_type<trg>>>
    void init(trg&& target);

    /// @}

    /**
     * @brief Resets the state of the trampoline, leaving the instance
     * target-less and uninitialized. Does nothing if already uninitialized.
     * @note It does not deallocate the executable buffer (if it exists) but
     * instead keeps it to prevent future allocations.
     */
    void reset();

    /**
     * @brief Calls the underlying trampoline function with arg and return types
     * determined from the function type `fn`.
     * @tparam fn the function-like type of the trampoline function which will
     * be used to determine how it will be called (it can be anything that
     * satisfies @ref alterhook::utils::function_type)
     * @tparam types the types of the arguments the trampoline function will be
     * invoked with
     * @param values the arguments to invoke the trampoline function with
     * @returns The result of the trampoline invocation (nothing if the return
     * type is void)
     * @par Example
     * @snippet ARM/trampoline_target_tests.h trampoline::invoke example
     * @warning The trampoline class does NOT keep track of the underlying
     * function type of the target function. This means that if invoke is called
     * with an incorrect function type then the behaviour is undefined (most
     * likely crash).
     */
    template <typename fn, typename... types,
              typename = std::enable_if_t<utils::function_type<fn>>>
    auto invoke(types&&... values) const;

    /**
     * @brief A getter that returns a pointer to the trampoline executable
     * buffer.
     * @tparam fn the function-like type to which the pointer will be casted and
     * returned (it can be anything that satisfies
     * @ref alterhook::utils::function_type)
     * @returns A pointer to the underlying trampoline buffer obtained from a
     * call to @ref alterhook::function_cast with `fn` as its template
     * parameter.
     * @par Example
     * @snippet ARM/trampoline_target_tests.h trampoline::get_callback example
     */
    template <typename fn,
              typename = std::enable_if_t<utils::function_type<fn>>>
    auto get_callback() const;

    /// @brief Returns the target that the trampoline is initialized with.
    /// Returns `nullptr` if not initialized.
    std::byte* get_target() const noexcept { return ptarget; }

    /// @brief Returns the size (in bytes) of the instructions (and their
    /// associated data) currently stored in the trampoline buffer.
    size_t size() const noexcept { return tramp_size; }

    /// @brief Returns the number of instructions that were relocated from the
    /// target function.
    size_t count() const noexcept { return positions.size(); }

    /**
     * @brief Disassembles the entire trampoline buffer and returns the
     * stringified version of the instructions
     * @returns an instance of `std::string` with all the stringified
     * instructions of the trampoline buffer separated by newlines.
     *
     * This is intended to be used for debugging purposes, as it gives an idea
     * about how the trampoline function looks like. The output is architecture
     * dependent and the format is `<address>: <mnemonic> <operands>`. Under the
     * hood it just uses capstone to get the instruction strings and appends
     * them while also keeping track of any instruction set changes (e.g. arm to
     * thumb).
     * @par Possible Output
     * @code
     * 0xf75d7fc0: str r2, [sp, #-4]!
     * 0xf75d7fc4: ldr r2, [pc, #0x30]
     * 0xf75d7fc8: mov r1, r2
     * 0xf75d7fcc: add r2, r2, #4
     * 0xf75d7fd0: add r0, r0, r2
     * 0xf75d7fd4: pop {r2}
     * 0xf75d7fd8: ldr pc, [pc, #0x18]
     * @endcode
     */
    std::string str() const;

  protected:
#ifdef __alterhook_expose_impl
    friend uintptr_t process_frozen_threads(const trampoline& tramp,
                                            bool              enable_hook,
                                            uintptr_t         ip) noexcept;
#endif
    /// @brief the deleter specified in `std::unique_ptr` which uses the
    /// internal buffer deallocator.
    struct ALTERHOOK_API deleter
    {
      void operator()(std::byte* ptrampoline) const noexcept;
    };

    typedef utils::static_vector<std::pair<uint8_t, uint8_t>, 8> positions_t;
    typedef std::optional<uint8_t>                               pc_handling_t;
    typedef std::unique_ptr<std::byte, deleter>                  trampoline_ptr;
    std::byte*     ptarget = nullptr; ///< The pointer to the target function
    trampoline_ptr ptrampoline{};     ///< The pointer to the executable buffer
#if !utils_x86 || defined(RUNNING_DOXYGEN)
    /// The pointer to the relay function (not defined on 32-bit x86)
    std::byte* prelay = nullptr;
#endif
#if utils_arm || defined(RUNNING_DOXYGEN)
    /// @brief A bitset that tells the instruction set per position, where true
    /// is for thumb and false for arm (only defined on armv7)
    std::bitset<8> instruction_sets{};
#endif
    /// @brief Whether to use the *patch above* strategy, i.e. whether the
    /// target function is too small and an attempt should be made to use the
    /// preceding bytes when hooking.
    bool   patch_above = false;
    size_t tramp_size  = 0; ///< What @ref alterhook::trampoline::size returns
#if utils_arm || utils_aarch64 || defined(RUNNING_DOXYGEN)
    /// @brief If PC handling is activate on the trampoline, this tells the
    /// exact position where it starts (only defined on armv7 and aarch64)
    pc_handling_t pc_handling = std::nullopt;
#endif
#if utils_aarch64 || defined(RUNNING_DOXYGEN)
    uint8_t available_size = 0;
#endif
#if !utils_windows || defined(RUNNING_DOXYGEN)
    /// @brief Tells the protection of the target function (only defined on
    /// linux targets)
    protection_info old_protect{};
#endif
    /// @brief a collection of the positions of each instruction in the target
    /// function with its respective position in the executable buffer
    positions_t positions{};
  };

  template <typename trg, typename>
  void trampoline::init(trg&& target)
  {
    init(get_target_address(std::forward<trg>(target)));
  }

  template <typename fn, typename... types, typename>
  auto trampoline::invoke(types&&... args) const
  {
    utils_assert(
        ptarget,
        "trampoline::invoke: attempt to invoke an uninitialized trampoline");
    return std::invoke(function_cast<fn>(helpers::resolve_original(
                           ptarget, ptrampoline.get())),
                       std::forward<types>(args)...);
  }

  template <typename fn, typename>
  auto trampoline::get_callback() const
  {
    return function_cast<fn>(
        helpers::resolve_original(ptarget, ptrampoline.get()));
  }
} // namespace alterhook

#if utils_msvc
  #pragma warning(pop)
#else
  #pragma GCC diagnostic pop
#endif
