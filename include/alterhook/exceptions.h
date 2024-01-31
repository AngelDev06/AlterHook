/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include <system_error>
#include <array>
#include "detail/macros.h"
#if utils_msvc
  #pragma warning(push)
  #pragma warning(disable : 4275 4251)
#endif

namespace alterhook::exceptions
{
  template <size_t n>
  using byte_array = std::array<std::byte, n>;

  utils_generate_exception(alterhook_exception, std::exception,
                           stdattr(ALTERHOOK_API),
                           extra(virtual std::string info() const = 0;));

  utils_generate_exception(trampoline_exception, alterhook_exception,
                           stdattr(ALTERHOOK_API),
                           fields((const std::byte*, target)),
                           extra(virtual std::string info() const;));

  utils_generate_exception(
      disassembler_exception, alterhook_exception, stdattr(ALTERHOOK_API),
      fields((const std::byte*, target), (int, flag, hidden)),
      reason("An exception occurred with the disassembler"),
      extra(const char* get_error_string() const noexcept;
            std::string info() const override { return get_error_string(); }));

  utils_generate_exception(
      os_exception, alterhook_exception, stdattr(ALTERHOOK_API),
      fields((std::error_code, error_code)),
      extra(os_exception(int code)
            : m_error_code(code, std::system_category()) {} virtual std::string
                        error_function() const = 0;
            std::string info() const override;));

  utils_generate_exception(misc_exception, alterhook_exception,
                           stdattr(ALTERHOOK_API));

  inline namespace trampoline
  {
#if utils_arm
  #define __uih_thumb_field , (bool, thumb, hidden)
#else
  #define __uih_thumb_field
#endif

    utils_generate_exception(
        unsupported_instruction_handling, trampoline_exception,
        stdattr(ALTERHOOK_API),
        fields((byte_array<24>, instr, hidden)__uih_thumb_field),
        base_args((const std::byte*, target)),
        reason("Cannot handle a given instruction in the target function"),
        extra(std::string info() const override;));

#if utils_arm
    utils_generate_exception(
        it_block_exception, trampoline_exception, stdattr(ALTERHOOK_API),
        fields((byte_array<32>, buffer, hidden), (size_t, buffer_size, hidden),
               (const std::byte*, it_address),
               (size_t, remaining_instructions)),
        base_args((const std::byte*, target)),
        extra(std::string info() const override; std::string it_str() const;
              size_t instruction_count() const;));

    inline namespace it_block
    {
      utils_generate_exception(
          invalid_it_block, it_block_exception, stdattr(ALTERHOOK_API),
          base_args((const std::byte*, target), (byte_array<32>, buffer),
                    (size_t, buffer_size), (const std::byte*, it_address),
                    (size_t, remaining_instructions)),
          reason("An invalid IT block was encountered"));

      utils_generate_exception(
          incomplete_it_block, it_block_exception, stdattr(ALTERHOOK_API),
          base_args((const std::byte*, target), (byte_array<32>, buffer),
                    (size_t, buffer_size), (const std::byte*, it_address),
                    (size_t, remaining_instructions)),
          reason("A part of an IT block was cut off when completing the "
                 "trampoline function"));
    } // namespace it_block

    utils_generate_exception(
        pc_relative_handling_fail, trampoline_exception, stdattr(ALTERHOOK_API),
        fields((const std::byte*, instruction_address),
               (byte_array<24>, buffer, hidden), (bool, thumb, hidden)),
        base_args((const std::byte*, target)),
        reason("A PC relative instruction cannot be fixed"),
        extra(std::string info() const override;));

    utils_generate_exception(
        ambiguous_instruction_set, trampoline_exception, stdattr(ALTERHOOK_API),
        fields((byte_array<32>, buffer, hidden), (size_t, size, hidden),
               (std::bitset<32>, instruction_sets, hidden),
               (const std::byte*, branch_destination)),
        base_args((const std::byte*, target)),
        reason("More than one branch instruction lead to the same destination "
               "but with different instruction sets"),
        extra(std::string info() const override;));
#endif

#if utils_arm || utils_aarch64
    utils_generate_exception(
        unused_register_not_found, trampoline_exception, stdattr(ALTERHOOK_API),
        base_args((const std::byte*, target)),
        reason("Couldn't find a register suitable for handling "
               "PC relative instructions"));
#endif

    utils_generate_exception(bad_target, trampoline_exception,
                             stdattr(ALTERHOOK_API),
                             base_args((const std::byte*, target)),
                             reason("The target failed to be disassembled"));

    utils_generate_exception(
        instructions_in_branch_handling_fail, trampoline_exception,
        stdattr(ALTERHOOK_API), base_args((const std::byte*, target)),
        reason("An instruction in the middle of a branch cannot be altered "
               "without breaking the branch"));

    utils_generate_exception(trampoline_max_size_exceeded, trampoline_exception,
                             stdattr(ALTERHOOK_API),
                             fields((size_t, size), (size_t, max_size)),
                             base_args((const std::byte*, target)),
                             reason("Exceeded the trampoline's available size"),
                             extra(std::string info() const override;));

    utils_generate_exception(
        insufficient_function_size, trampoline_exception,
        stdattr(ALTERHOOK_API), fields((size_t, size), (size_t, needed_size)),
        base_args((const std::byte*, target)),
        reason("The original function isn't long enough to hook"),
        extra(std::string info() const override;));
  } // namespace trampoline

  inline namespace disassembler
  {
    utils_generate_exception(disassembler_init_fail, disassembler_exception,
                             stdattr(ALTERHOOK_API),
                             base_args((const std::byte*, target), (int, flag)),
                             reason("Disassembler failed to be initialized"));

    utils_generate_exception(
        disassembler_iter_init_fail, disassembler_exception,
        base_args((const std::byte*, target), (int, flag)),
        reason("Disassembler iterator failed to be initialized"));

    utils_generate_exception(
        disassembler_disasm_fail, disassembler_exception,
        base_args((const std::byte*, target), (int, flag)),
        reason(
            "Disassembler failed when trying to disassemble an instruction"));
  } // namespace disassembler

  inline namespace os
  {
#if utils_windows
    utils_generate_exception(
        virtual_alloc_exception, os_exception, stdattr(ALTERHOOK_API),
        fields((const std::byte*, target_address), (size_t, size),
               (uint64_t, allocation_type), (uint64_t, protection)),
        base_args((int, flag)),
        reason("An exception occurred when trying to allocate a memory block"),
        extra(std::string error_function() const override;));

    utils_generate_exception(
        thread_list_traversal_fail, os_exception, stdattr(ALTERHOOK_API),
        fields((const void*, handle), (uintptr_t, thread_entry_address)),
        base_args((int, flag)),
        reason(
            "Failed to traverse over the thread list of the current process"),
        extra(std::string error_function() const override;));

    utils_generate_exception(
        virtual_protect_exception, os_exception, stdattr(ALTERHOOK_API),
        fields((const std::byte*, address), (size_t, size),
               (size_t, protection), (uintptr_t, old_protection)),
        base_args((int, flag)),
        reason("An exception occurred when trying to the "
               "change the protection of the target function"),
        extra(std::string error_function() const override;));
#else
    utils_generate_exception(
        mmap_exception, os_exception, stdattr(ALTERHOOK_API),
        fields((const std::byte*, target_address), (size_t, size),
               (int, protection), (int, flags), (int, fd), (uint64_t, offset)),
        base_args((int, flag)),
        reason("An exception occurred when trying to allocate a memory block"),
        extra(std::string error_function() const override;));

    utils_generate_exception(
        sigaction_exception, os_exception, stdattr(ALTERHOOK_API),
        fields((int, signal), (const void*, action), (const void*, old_action)),
        base_args((int, flag)),
        reason("An exception occurred when trying to setup the signal handler"),
        extra(std::string error_function() const override;));

    utils_generate_exception(mprotect_exception, os_exception,
                             stdattr(ALTERHOOK_API),
                             fields((const std::byte*, address),
                                    (size_t, length), (int, protection)),
                             base_args((int, flag)),
                             reason("An exception occurred when changing the "
                                    "protection of a memory page"),
                             extra(std::string error_function()
                                       const override;));
#endif
  } // namespace os

  inline namespace misc
  {
#if !utils_windows
    utils_generate_exception(
        thread_process_fail, misc_exception, stdattr(ALTERHOOK_API),
        fields((const std::byte*, trampoline_address),
               (const std::byte*, target_address), (size_t, position)),
        reason(
            "A thread failed to be processed in order for the hooks to work"),
        extra(std::string info() const override;));
#endif

    utils_generate_exception(invalid_address, misc_exception,
                             stdattr(ALTERHOOK_API),
                             fields((const std::byte*, address)),
                             reason("A non-executable address was passed"),
                             extra(std::string info() const override;));
  } // namespace misc
} // namespace alterhook::exceptions

#if utils_msvc
  #pragma warning(pop)
#endif
