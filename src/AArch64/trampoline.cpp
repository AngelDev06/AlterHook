/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#include <pch.h>
#include "exceptions.h"
#include "disassembler.h"
#include "instructions.h"
#include "buffer.h"
#include "trampoline.h"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wrange-loop-construct"

namespace alterhook
{
  extern std::shared_mutex hook_lock;

  void trampoline::deleter::operator()(std::byte* ptrampoline) const noexcept
  {
    trampoline_buffer::deallocate(ptrampoline);
  }

  namespace
  {
    std::optional<aarch64::reg_t> map_cs_xreg(aarch64_reg reg) noexcept
    {
      using namespace aarch64;
      // clang-format off
      switch (reg)
      {
      case AArch64_REG_X0:  return X0;  case AArch64_REG_X1:  return X1;
      case AArch64_REG_X2:  return X2;  case AArch64_REG_X3:  return X3;
      case AArch64_REG_X4:  return X4;  case AArch64_REG_X5:  return X5;
      case AArch64_REG_X6:  return X6;  case AArch64_REG_X7:  return X7;
      case AArch64_REG_X8:  return X8;  case AArch64_REG_X9:  return X9;
      case AArch64_REG_X10: return X10; case AArch64_REG_X11: return X11;
      case AArch64_REG_X12: return X12; case AArch64_REG_X13: return X13;
      case AArch64_REG_X14: return X14; case AArch64_REG_X15: return X15;
      case AArch64_REG_X16: return X16; case AArch64_REG_X17: return X17;
      case AArch64_REG_X18: return X18; case AArch64_REG_X19: return X19;
      case AArch64_REG_X20: return X20; case AArch64_REG_X21: return X21;
      case AArch64_REG_X22: return X22; case AArch64_REG_X23: return X23;
      case AArch64_REG_X24: return X24; case AArch64_REG_X25: return X25;
      case AArch64_REG_X26: return X26; case AArch64_REG_X27: return X27;
      case AArch64_REG_X28: return X28; case AArch64_REG_X29: return X29;
      case AArch64_REG_X30: return X30; default: return std::nullopt;
      }
      // clang-format on
    }

    std::optional<uintptr_t> get_absolute_address(const cs_insn& instr) noexcept
    {
      const auto& detail = instr.detail->aarch64;
      const auto  begin =
                     std::reverse_iterator(detail.operands + detail.op_count),
                 end = std::reverse_iterator(detail.operands);
      auto result    = std::find_if(begin, end,
                                    [](const cs_aarch64_op& operand)
                                    { return operand.type == AArch64_OP_IMM; });
      if (result == end)
        return std::nullopt;
      return result->imm;
    }

    bool ldr_relative(const cs_insn& instr) noexcept
    {
      if (!utils::any_of(instr.id, AArch64_INS_LDR, AArch64_INS_LDRSW))
        return false;
      const auto *begin = instr.detail->aarch64.operands,
                 *end   = instr.detail->aarch64.operands +
                        instr.detail->aarch64.op_count;
      // the PC register is encoded implicitly on pc-relative loads and
      // therefore capstone does not include it in the operands list. so we
      // check if there is no memory operand provided
      return std::find_if(begin, end,
                          [](const cs_aarch64_op& operand)
                          { return operand.type == AArch64_OP_MEM; }) == end;
    }

    constexpr size_t max_branch_dests   = 5;
    constexpr size_t max_to_be_modified = 8;
    constexpr size_t erased_max         = 8;

    template <typename instr_t>
    constexpr bool any_custom_instruction =
        std::is_base_of_v<aarch64::INSTRUCTION,
                          utils::remove_cvref_t<instr_t>> ||
        aarch64::custom::all_custom::template has<
            utils::remove_cvref_t<instr_t>>;

    template <typename instr_t, typename reg_t, typename = void>
    constexpr bool can_set_register = false;
    template <typename instr_t, typename reg_t>
    constexpr bool can_set_register<
        instr_t, reg_t,
        std::void_t<decltype(std::declval<instr_t>().set_register(
            std::declval<reg_t>()))>> = true;

    template <typename instr_t, typename = void>
    constexpr bool has_getset_fetch_offset = false;
    template <typename instr_t>
    constexpr bool has_getset_fetch_offset<
        instr_t,
        std::void_t<decltype(std::declval<instr_t>().get_fetch_offset(),
                             std::declval<instr_t>().set_fetch_offset(
                                 std::declval<typename aarch64::LDR_LITERAL::
                                                  offset_t>()))>> =
        std::is_same_v<decltype(std::declval<instr_t>().get_fetch_offset()),
                       typename aarch64::LDR_LITERAL::offset_t>;

    using simple_branches =
        utils::type_sequence<aarch64::B, aarch64::B_cond, aarch64::BL,
                             aarch64::CBZ, aarch64::CBNZ, aarch64::TBZ,
                             aarch64::TBNZ>;
    using custom_far_branches = aarch64::custom::partial_absolute_branches;
    using all_branches =
        typename simple_branches::template merge<custom_far_branches>;
    using custom_far_loads = aarch64::custom::absolute_loads;
    using relative_loads =
        utils::type_sequence<aarch64::LDR_LITERAL, aarch64::LDRSW_LITERAL,
                             aarch64::LDRV_LITERAL>;
    using preindexed_loads =
        utils::type_sequence<aarch64::LDRu32, aarch64::LDRu64, aarch64::LDRSWu,
                             aarch64::LDRVu8, aarch64::LDRVu16,
                             aarch64::LDRVu32, aarch64::LDRVu64,
                             aarch64::LDRVu128>;
    using stack_manipulators = aarch64::custom::stack_manipulators;
    using state_updaters     = utils::type_sequence<aarch64::ADD, aarch64::SUB>;
    using instruction_tags   = aarch64::custom::tagged_instructions;
    using all_modifiables    = typename simple_branches::template merge<
        custom_far_branches, custom_far_loads, relative_loads, preindexed_loads,
        stack_manipulators, state_updaters, instruction_tags>;
    using modifiables_variant = typename all_modifiables::template apply<
        std::add_pointer_t>::template to<std::variant>;

    struct modifiable_instruction : modifiables_variant
    {
      using modifiables_variant::modifiables_variant;

      void patch_pc_register(aarch64::xregisters reg)
      {
        std::visit(
            [reg](auto* pinstr)
            {
              typedef std::remove_pointer_t<decltype(pinstr)> instr_t;
              if constexpr (can_set_register<instr_t, aarch64::xregisters>)
                pinstr->set_register(reg);
              else if constexpr (can_set_register<instr_t, aarch64::reg_t>)
                pinstr->set_register(static_cast<aarch64::reg_t>(reg));
              else if constexpr (preindexed_loads::template has<instr_t>)
                pinstr->set_base_register(static_cast<aarch64::reg_t>(reg));
              else
                static_assert(
                    std::is_same_v<instr_t, aarch64::custom::ERASED> ||
                        all_branches::template has<instr_t>,
                    "unhandled modifiable instruction");
            },
            *this);
      }

      [[noreturn]] static void raise_offset_fix_fail(std::byte* target,
                                                     std::byte* instr,
                                                     uint8_t    instr_size,
                                                     std::byte* address)
      {
        throw(exceptions::post_relocation_processing_fail(
            target,
            utils::to_array<exceptions::instruction_buffer_size>(
                instr, instr + instr_size),
            instr, address));
      }
    };

    struct branch_destination
    {
      static constexpr size_t max_references = 5;

      typedef std::reference_wrapper<modifiable_instruction>  reference;
      typedef utils::static_vector<reference, max_references> references_t;

      union
      {
        std::byte* const id = nullptr;
        const uintptr_t  uid; // no it's not a linux userid
      };

      union
      {
        std::byte* dest = nullptr;
        uintptr_t  udest;
      };

      references_t references{};

      branch_destination(std::byte* id, std::byte* dest = nullptr)
          : id(id), dest(dest)
      {
      }

      branch_destination(std::byte* id, uintptr_t dest) : id(id), udest(dest) {}
    };

    struct branch_destination_list
        : utils::static_vector<branch_destination, max_branch_dests>
    {
      iterator get_entry(std::byte* id) noexcept
      {
        return std::find_if(begin(), end(),
                            [id](const branch_destination& entry)
                            { return entry.id == id; });
      }

      void fix_moved_dests(std::byte* perased, std::byte* tramp_last)
      {
        for (branch_destination& entry : *this)
        {
          if (perased < entry.dest && entry.dest < tramp_last)
            entry.dest -= sizeof(aarch64::custom::ERASED);
        }
      }

      void process_all(std::byte* target)
      {
        for (branch_destination& entry : *this)
        {
          utils_assert(entry.dest,
                       "branch_destination_list::process: a branch destination "
                       "entry doesn't have its pointer set");

          for (auto ref : entry.references)
            std::visit(
                [target, address = entry.dest](auto* pinstr)
                {
                  typedef std::remove_pointer_t<decltype(pinstr)> instr_t;
                  if constexpr (simple_branches::template has<instr_t>)
                  {
                    auto* const raw_pinstr =
                        reinterpret_cast<std::byte*>(pinstr);
                    const ptrdiff_t relative_address = address - raw_pinstr;
                    if (!instr_t::offset_fits(relative_address))
                      modifiable_instruction::raise_offset_fix_fail(
                          target, raw_pinstr, sizeof(instr_t), address);
                    pinstr->set_offset(relative_address);
                  }
                  else
                    assert(!"a non-simple branch entry was spotted in the "
                            "reference table of a `branch_destination_list` "
                            "instance");
                },
                ref.get());
        }
      }

      void set_destination(std::byte* id, std::byte* dest)
      {
        auto entry = get_entry(id);
        if (entry != end())
          entry->dest = dest;
      }

      void insert_reference(std::byte* id, modifiable_instruction& instr,
                            std::byte* dest = nullptr)
      {
        auto entry = get_entry(id);
        if (entry != end())
          entry->references.emplace_back(instr);
        else
          emplace_back(id, dest).references.emplace_back(instr);
      }

      bool in_branch() const noexcept
      {
        // if an entry's destination is left as null it means that it's within
        // the overriden area of the target function and we haven't reached it
        // yet to set it. Therefore this determines whether there is a branch
        // destination ahead (inside the trampoline).
        return std::find_if(begin(), end(),
                            [](const branch_destination& entry)
                            { return !entry.dest; }) != end();
      }
    };

    struct modifiable_instruction_list
        : utils::static_vector<modifiable_instruction, max_to_be_modified>
    {
      [[nodiscard]] std::byte* erase_stack_manipulators_and_redundant_loads(
          branch_destination_list& branch_list, std::byte* target,
          std::byte* tramp_last)
      {
        using aarch64::custom::DATA_FETCH, aarch64::custom::ERASED;
        if (empty())
          return tramp_last;
        DATA_FETCH* prev_data_fetcher = nullptr;

        for (modifiable_instruction& entry : *this)
          std::visit(
              [&](auto* pinstr)
              {
                typedef std::remove_pointer_t<decltype(pinstr)> instr_t;
                if constexpr (stack_manipulators::template has<instr_t>)
                  entry = reinterpret_cast<ERASED*>(pinstr);
                else if constexpr (state_updaters::template has<instr_t>)
                  prev_data_fetcher = nullptr;
                else if constexpr (std::is_same_v<instr_t, DATA_FETCH>)
                {
                  const auto prevloc = reinterpret_cast<std::byte*>(
                                 prev_data_fetcher),
                             loc = reinterpret_cast<std::byte*>(pinstr);
                  if (!prevloc)
                    return;
                  auto offset =
                      std::exchange(prev_data_fetcher, pinstr)->get_offset();
                  if ((prevloc + offset) == (loc + pinstr->get_offset()))
                    entry = reinterpret_cast<ERASED*>(pinstr);
                }
              },
              entry);

        return collapse_all(branch_list, target, tramp_last);
      }

    private:
      std::byte* collapse_all(branch_destination_list& branch_list,
                              std::byte* target, std::byte* tramp_last)
      {
        using aarch64::custom::DATA_FETCH, aarch64::custom::ERASED;
        std::byte* prev_range_end    = nullptr;
        uint8_t    prev_erased_total = 0;

        for (modifiable_instruction& entry : *this)
        {
          if (auto** pperased =
                  reinterpret_cast<std::byte**>(std::get_if<ERASED*>(&entry)))
          {
            utils_assert(*pperased,
                         "erased instruction was already dealt with");
            if (prev_range_end)
              std::copy(prev_range_end, *pperased,
                        prev_range_end - prev_erased_total);
            branch_list.fix_moved_dests(*pperased, tramp_last);
            prev_range_end     = *pperased + sizeof(ERASED);
            prev_erased_total += sizeof(ERASED);
            *pperased          = nullptr;
            continue;
          }

          std::visit(
              [=, &prev_range_end](auto*& pinstr)
              {
                typedef std::remove_pointer_t<
                    std::remove_reference_t<decltype(pinstr)>>
                    instr_t;
                if (!prev_erased_total)
                  return;
                assert(prev_range_end);
                auto&      raw_pinstr = reinterpret_cast<std::byte*&>(pinstr);
                const auto range_end  = raw_pinstr + sizeof(instr_t);
                std::copy(prev_range_end, range_end,
                          prev_range_end - prev_erased_total);
                raw_pinstr     -= prev_erased_total;
                prev_range_end  = range_end;

                // branches are handled later on
                if constexpr (relative_loads::template has<instr_t> ||
                              std::is_same_v<instr_t, DATA_FETCH>)
                {
                  std::byte* const absolute_address =
                      (range_end - sizeof(instr_t)) + pinstr->get_offset();
                  const ptrdiff_t relative_address =
                      absolute_address - raw_pinstr;
                  if (!instr_t::offset_fits(relative_address))
                    modifiable_instruction::raise_offset_fix_fail(
                        target, raw_pinstr, sizeof(instr_t), absolute_address);
                  pinstr->set_offset(relative_address);
                }
                else if constexpr (has_getset_fetch_offset<instr_t>)
                {
                  std::byte* const absolute_address =
                      (range_end - sizeof(instr_t)) +
                      pinstr->get_fetch_offset();
                  pinstr->set_fetch_offset(absolute_address - raw_pinstr);
                }
              },
              entry);
        }

        if (prev_erased_total)
          std::copy(prev_range_end, tramp_last,
                    prev_range_end - prev_erased_total);

#ifndef NDEBUG
        std::fill(
            reinterpret_cast<aarch64::BRK*>(tramp_last - prev_erased_total),
            reinterpret_cast<aarch64::BRK*>(tramp_last), aarch64::BRK(0));
#endif

        return tramp_last - prev_erased_total;
      }
    };

    struct address_allocator
    {
      typedef std::bitset<memory_slot_size / sizeof(uintptr_t)> buffer_bitset_t;

      buffer_bitset_t bytes_used{};
      uint8_t         last_unused_pos = 0;
      uint8_t         available_size  = 0;

      address_allocator(uint8_t available_size = memory_slot_size)
          : available_size(available_size)
      {
      }

      uintptr_t allocate(uintptr_t trampoline, uintptr_t fill = 0) noexcept
      {
        utils_assert(!bytes_used.all(),
                     "address_allocator::allocate: run out of buffer");
        bytes_used.set(last_unused_pos++);
        available_size                         -= sizeof(uintptr_t);
        const uintptr_t dataloc                 = trampoline + available_size;
        *reinterpret_cast<uintptr_t*>(dataloc)  = fill;
        return dataloc;
      }
    };

    struct trampoline_context
    {
      struct session;
      typedef std::bitset<memory_slot_size> buffer_bitset_t;
      typedef std::optional<uint8_t>        pc_handling_begin_t,
          pc_handling_entry_index_t;
      typedef utils::static_vector<std::pair<uintptr_t*, uintptr_t>, 4>
          pc_handling_data_t;
      typedef utils::static_vector<std::pair<uint8_t, uint8_t>, 8> positions_t;

      bool                        finished    = false;
      const uint8_t               size_needed = 0;
      std::bitset<32>             registers_found{};
      address_allocator           allocator{};
      positions_t                 positions{};
      branch_destination_list     branch_list{};
      modifiable_instruction_list modifiable_list{};

      struct
      {
        pc_handling_begin_t       startup_location   = std::nullopt;
        pc_handling_entry_index_t active_entry_index = std::nullopt;
        pc_handling_data_t        data_addresses_and_values{};
      } pc_handling_context{};

      struct trampoline_t
      {
        union
        {
          std::byte* const begin = nullptr;
          const uintptr_t  ubegin;
        };

        union
        {
          std::byte* end = nullptr;
          uintptr_t  uend;
        };

        union
        {
          std::byte* const buffer_end = nullptr;
          const uintptr_t  ubuffer_end;
        };

        trampoline_t(std::byte* trampoline)
            : begin(trampoline), end(trampoline),
              buffer_end(trampoline + memory_slot_size)
        {
        }
      } trampoline;

      struct target_t
      {
        union
        {
          std::byte* const begin = nullptr;
          const uintptr_t  ubegin;
        };

        union
        {
          std::byte* end = nullptr;
          uintptr_t  uend;
        };

        target_t(std::byte* target) : begin(target), end(target) {}
      } target;

      trampoline_context(std::byte* target, std::byte* trampoline)
          : size_needed(static_cast<uint8_t>(
                utils::align_up(target + sizeof(aarch64::custom::FULL_JMP),
                                8u) -
                target)),
            trampoline(trampoline), target(target)
      {
      }

      static bool is_pad(const std::byte* address,
                         uint8_t          required_size) noexcept
      {
        auto* const u32address = reinterpret_cast<const uint32_t*>(address);
        return std::all_of(
            u32address, u32address + (utils::align_up(required_size, 4u) / 4u),
            [](const uint32_t data) { return data == aarch64::NOP::opcode; });
      }

      bool rest_is_pad(uint8_t required_size) const noexcept
      {
        return is_pad(target.end, required_size);
      }

      uintptr_t allocate_address(uintptr_t fill = 0) noexcept
      {
        return allocator.allocate(trampoline.ubegin, fill);
      }

      void must_fit(uint8_t copy_size)
      {
        const uint8_t tramp_pos = trampoline.end - trampoline.begin;
        if ((tramp_pos + copy_size) > allocator.available_size)
          throw(exceptions::trampoline_max_size_exceeded(
              target.begin, tramp_pos + copy_size, allocator.available_size));
      }

      bool is_in_overriden_area(uintptr_t branch_dest) const noexcept
      {
        return target.ubegin <= branch_dest &&
               branch_dest < (target.ubegin + size_needed);
      }

      bool is_in_overriden_area(std::byte* branch_dest) const
      {
        return is_in_overriden_area(reinterpret_cast<uintptr_t>(branch_dest));
      }

      aarch64::reg_t find_unused_register()
      {
        using namespace aarch64;
        for (int8_t reg = X15; reg != -1; --reg)
        {
          if (!registers_found[reg])
            return reg_t(reg);
        }

        throw(exceptions::unused_register_not_found(target.begin));
      }

      void cleanup()
      {
        if (!finished)
          throw(exceptions::bad_target(target.begin));
        if (pc_handling_context.startup_location)
        {
          auto reg = find_unused_register();
          // registers in range [X8, X15] are caller saved temporaries and
          // therefore we don't need to do manual backups so all push/pop and
          // extra loads are removed
          if (reg >= aarch64::X8)
            trampoline.end =
                modifiable_list.erase_stack_manipulators_and_redundant_loads(
                    branch_list, target.begin, trampoline.end);

          for (modifiable_instruction& entry : modifiable_list)
            entry.patch_pc_register(static_cast<aarch64::xregisters>(reg));
        }

        branch_list.process_all(target.begin);
      }

      session create_session(disassembler& aarch64, const cs_insn& instr);
    };

    struct trampoline_context::session
    {
      template <typename T>
      using instr_ptr_t = std::add_pointer_t<utils::remove_cvref_t<T>>;

      enum instruction_category
      {
        SIMPLE_BRANCH,
        MODIFIABLE,
        CUSTOM
      };

      template <typename T>
      static constexpr bool is_simple_branch =
          simple_branches::template has<utils::remove_cvref_t<T>>;
      template <typename T>
      static constexpr bool should_be_modified =
          !is_simple_branch<T> &&
          all_modifiables::template has<utils::remove_cvref_t<T>>;
      template <typename T>
      static constexpr bool is_custom_instruction =
          !is_simple_branch<T> && !should_be_modified<T> &&
          (std::is_base_of_v<aarch64::INSTRUCTION, utils::remove_cvref_t<T>> ||
           aarch64::custom::all_custom::template has<utils::remove_cvref_t<T>>);

      static constexpr size_t                    buffer_size = 32;
      typedef std::array<std::byte, buffer_size> buffer_t;

      disassembler&       aarch64;
      trampoline_context& ctx;
      buffer_t            buffer{};
      const std::byte*    copy_source = nullptr;
      uint8_t             copy_size   = 0;

      union
      {
        std::byte* const target_instruction_address = nullptr;
        const uintptr_t  utarget_instruction_address;
      };

      session(disassembler& aarch64, trampoline_context& ctx,
              const cs_insn& instr)
          : aarch64(aarch64), ctx(ctx),
            copy_source(reinterpret_cast<const std::byte*>(instr.bytes)),
            copy_size(instr.size), utarget_instruction_address(instr.address)
      {
        ctx.target.end += instr.size;
        ctx.branch_list.set_destination(target_instruction_address,
                                        ctx.trampoline.end);
        register_all_registers(instr);
      }

      session(const session&)            = delete;
      session& operator=(const session&) = delete;

      ~session()
      {
        const uint8_t target_pos =
                          target_instruction_address - ctx.target.begin,
                      tramp_pos = ctx.trampoline.end - ctx.trampoline.begin;
        ctx.must_fit(copy_size);
        ctx.positions.push_back({ target_pos, tramp_pos });
        memcpy(ctx.trampoline.end, copy_source, copy_size);
        ctx.trampoline.end += copy_size;
      }

      template <typename T,
                std::enable_if_t<is_simple_branch<T>, instruction_category> =
                    SIMPLE_BRANCH>
      void add_instruction(T&& instr, std::byte* id)
      {
        register_branch(add_instruction_impl(std::forward<T>(instr)), id);
      }

      template <typename T,
                std::enable_if_t<is_simple_branch<T>, instruction_category> =
                    SIMPLE_BRANCH>
      void add_instruction(T&& instr, uintptr_t id)
      {
        add_instruction(std::forward<T>(instr),
                        reinterpret_cast<std::byte*>(id));
      }

      template <typename T, std::enable_if_t<should_be_modified<T>,
                                             instruction_category> = MODIFIABLE>
      void add_instruction(T&& instr)
      {
        if constexpr (preindexed_loads::template has<utils::remove_cvref_t<T>>)
          use_pc_handling(utarget_instruction_address);
        ctx.modifiable_list.emplace_back(
            add_instruction_impl(std::forward<T>(instr)));
      }

      template <typename T, std::enable_if_t<is_custom_instruction<T>,
                                             instruction_category> = CUSTOM>
      void add_instruction(T&& instr)
      {
        add_instruction_impl(std::forward<T>(instr));
      }

      void add_instruction(const cs_insn& instr)
      {
        prepare_buffer();
        memcpy(&buffer[copy_size], instr.bytes, instr.size);
        copy_size += instr.size;
      }

      // this also adds the instruction but does not register it to any of the
      // special handlers (e.g. `modifiable_instruction_list`)
      template <typename T,
                std::enable_if_t<any_custom_instruction<T>, size_t> = 0>
      void add_unregistered_instruction(T&& instr)
      {
        add_instruction_impl(std::forward<T>(instr));
      }

      ptrdiff_t use_pc_handling(uintptr_t address)
      {
        if (!ctx.pc_handling_context.active_entry_index)
        {
          if (!ctx.pc_handling_context.startup_location)
            ctx.pc_handling_context.startup_location =
                next_reloc_address() - ctx.trampoline.ubegin;
          add_instruction(aarch64::custom::PUSH());
          return setup_data_fetching(address) - next_reloc_address();
        }

        auto& [data_address, data_current_value] =
            ctx.pc_handling_context.data_addresses_and_values
                [ctx.pc_handling_context.active_entry_index.value()];
        const ptrdiff_t offset = address - data_current_value;
        if (!aarch64::ADD::offset_fits(offset) &&
            !aarch64::SUB::offset_fits(abs(offset)))
          return setup_data_fetching(address) - next_reloc_address();

        increment_custom_register(offset);
        data_current_value += offset;
        return reinterpret_cast<uintptr_t>(data_address) - next_reloc_address();
      }

      void break_pc_handling()
      {
        if (!ctx.pc_handling_context.active_entry_index)
          return;
        add_instruction(aarch64::custom::POP());
        ctx.pc_handling_context.active_entry_index = std::nullopt;
      }

      uintptr_t next_reloc_address() const noexcept
      {
        if (copy_source != buffer.data())
          return ctx.trampoline.uend;
        return ctx.trampoline.uend + copy_size;
      }

      bool holds_instructions() const noexcept
      {
        return copy_source == buffer.data();
      }

    private:
      void prepare_buffer()
      {
        if (copy_source == buffer.data())
          return;
        copy_source = buffer.data();
        copy_size   = 0;
      }

      template <typename T>
      auto add_instruction_impl(T&& instr)
      {
        constexpr size_t instr_size = sizeof(utils::remove_cvref_t<T>);
        prepare_buffer();
        new (&buffer[copy_size]) auto(instr);
        const auto reloc_address =
            reinterpret_cast<instr_ptr_t<T>>(ctx.trampoline.end + copy_size);
        copy_size += instr_size;
        return reloc_address;
      }

      template <typename T>
      void register_branch(T* reloc_address, std::byte* id)
      {
        // destinations outside the overriden area are constant even after
        // allocation so `dest == id`. If in overriden area then the destination
        // will be relocated as well and will be different so we are passing
        // null for now.
        std::byte* const branch_dest =
            ctx.is_in_overriden_area(id) ? nullptr : id;
        ctx.branch_list.insert_reference(
            id, ctx.modifiable_list.emplace_back(reloc_address), branch_dest);
      }

      void increment_custom_register(const ptrdiff_t offset)
      {
        if (aarch64::ADD::offset_fits(offset))
          add_instruction(aarch64::ADD(aarch64::xregisters::X0,
                                       aarch64::xregisters::X0, offset));
        else
          add_instruction(aarch64::SUB(aarch64::xregisters::X0,
                                       aarch64::xregisters::X0, abs(offset)));
      }

      uintptr_t setup_data_fetching(const uintptr_t uaddress)
      {
        typedef typename pc_handling_data_t::reference reference;
        auto suitable_address = std::find_if(
            ctx.pc_handling_context.data_addresses_and_values.begin(),
            ctx.pc_handling_context.data_addresses_and_values.end(),
            [uaddress](reference data)
            {
              const auto* const data_address = data.first;
              const ptrdiff_t   offset       = uaddress - *data_address;
              return aarch64::ADD::offset_fits(offset) ||
                     aarch64::SUB::offset_fits(abs(offset));
            });

        if (suitable_address !=
            ctx.pc_handling_context.data_addresses_and_values.end())
        {
          auto& [data_address, data_current_value] = *suitable_address;
          add_instruction(aarch64::custom::DATA_FETCH(
              aarch64::xregisters::X0,
              reinterpret_cast<std::byte*>(data_address) -
                  (ctx.trampoline.end + copy_size)));
          const ptrdiff_t offset = uaddress - *data_address;
          ctx.pc_handling_context.active_entry_index =
              suitable_address -
              ctx.pc_handling_context.data_addresses_and_values.begin();
          data_current_value = *data_address + offset;
          if (offset)
            increment_custom_register(offset);
          return reinterpret_cast<uintptr_t>(data_address);
        }

        const auto new_data_address = ctx.allocate_address(uaddress);
        ctx.pc_handling_context.data_addresses_and_values.emplace_back(
            reinterpret_cast<uintptr_t*>(new_data_address), uaddress);
        ctx.pc_handling_context.active_entry_index =
            ctx.pc_handling_context.data_addresses_and_values.size() - 1;
        add_instruction(aarch64::custom::DATA_FETCH(
            aarch64::xregisters::X0,
            new_data_address - (ctx.trampoline.uend + copy_size)));
        return new_data_address;
      }

      // lol
      void register_all_registers(const cs_insn& instr) noexcept
      {
        auto regs = aarch64.get_all_registers(instr);
        for (auto itr = regs.read.begin(),
                  end = regs.read.begin() + regs.read_count;
             itr != end; ++itr)
        {
          if (auto regindex = map_cs_xreg(static_cast<aarch64_reg>(*itr)))
            ctx.registers_found.set(regindex.value());
        }

        for (auto itr = regs.write.begin(),
                  end = regs.write.begin() + regs.write_count;
             itr != end; ++itr)
        {
          if (auto regindex = map_cs_xreg(static_cast<aarch64_reg>(*itr)))
            ctx.registers_found.set(regindex.value());
        }
      }
    };

    typename trampoline_context::session
        trampoline_context::create_session(disassembler&  aarch64,
                                           const cs_insn& instr)
    {
      return { aarch64, *this, instr };
    }
  } // namespace

  void trampoline::init(std::byte* target)
  {
    if (ptarget == target)
      return;
    protection_info tmp_protinfo = get_protection(target);
    if (!tmp_protinfo.execute)
      throw(exceptions::invalid_address(target));
    if (!ptrampoline)
      ptrampoline = trampoline_ptr(trampoline_buffer::allocate(target));
    if (ptarget)
      reset();

    trampoline_context ctx{ target, ptrampoline.get() };
    disassembler       aarch64{ target };
    std::shared_lock   lock{ hook_lock };

#ifndef NDEBUG
    std::fill(reinterpret_cast<aarch64::BRK*>(ctx.trampoline.begin),
              reinterpret_cast<aarch64::BRK*>(ctx.trampoline.buffer_end),
              aarch64::BRK(0));
#endif

    for (const cs_insn& instr : aarch64.disasm(memory_slot_size))
    {
      auto session = ctx.create_session(aarch64, instr);

      if (aarch64.modifies_register(instr, AArch64_REG_SP) &&
          ctx.pc_handling_context.active_entry_index)
      {
        session.break_pc_handling();
        session.add_instruction(instr);
        utils_assert(aarch64.is_branch(instr),
                     "An instruction that modifies both the SP and the PC was "
                     "unexpected");
      }
      else if (aarch64.is_relative_branch(instr))
      {
        assert(get_absolute_address(instr));
        session.break_pc_handling();
        const auto      dest              = get_absolute_address(instr).value();
        const bool      in_overriden_area = ctx.is_in_overriden_area(dest);
        const uintptr_t reloc_address     = session.next_reloc_address();
        const ptrdiff_t relative_address =
            dest - (in_overriden_area ? instr.address : reloc_address);
        bool      is_conditional_or_call = false;
        uintptr_t dataloc                = 0;

        switch (instr.id)
        {
        case aarch64::B::id:
        {
          if (utils::any_of(instr.detail->aarch64.cc, AArch64CC_Invalid,
                            AArch64CC_AL))
          {
            if (aarch64::B::offset_fits(relative_address))
            {
              session.add_instruction(aarch64::B(relative_address), dest);
              break;
            }

            dataloc = ctx.allocate_address();
            session.add_instruction(
                aarch64::custom::JMP(dataloc - reloc_address));
            break;
          }

          is_conditional_or_call = true;
          if (aarch64::B_cond::offset_fits(relative_address))
          {
            session.add_instruction(
                aarch64::B_cond(relative_address, instr.detail->aarch64.cc),
                dest);
            break;
          }

          dataloc = ctx.allocate_address();
          session.add_instruction(aarch64::custom::CONDITIONAL_JMP(
              instr.detail->aarch64.cc, dataloc - reloc_address));
          break;
        }
        case aarch64::BL::id:
        {
          is_conditional_or_call = true;
          if (aarch64::BL::offset_fits(relative_address))
          {
            session.add_instruction(aarch64::BL(relative_address), dest);
            break;
          }

          dataloc = ctx.allocate_address();
          session.add_instruction(
              aarch64::custom::CALL(dataloc - reloc_address));
          break;
        }
        case aarch64::CBZ::id:
        {
          auto cbz = *reinterpret_cast<const aarch64::CBZ*>(instr.bytes);
          if (aarch64::CBZ::offset_fits(relative_address))
          {
            cbz.set_offset(relative_address);
            session.add_instruction(cbz, dest);
            break;
          }

          dataloc = ctx.allocate_address();
          session.add_instruction(
              aarch64::custom::JMP_IF_ZERO(cbz, dataloc - reloc_address));
          break;
        }
        case aarch64::CBNZ::id:
        {
          auto cbnz = *reinterpret_cast<const aarch64::CBNZ*>(instr.bytes);
          if (aarch64::CBNZ::offset_fits(relative_address))
          {
            cbnz.set_offset(relative_address);
            session.add_instruction(cbnz, dest);
            break;
          }

          dataloc = ctx.allocate_address();
          session.add_instruction(
              aarch64::custom::JMP_IF_NOT_ZERO(cbnz, dataloc - reloc_address));
          break;
        }
        case aarch64::TBZ::id:
        {
          auto tbz = *reinterpret_cast<const aarch64::TBZ*>(instr.bytes);
          if (aarch64::TBZ::offset_fits(relative_address))
          {
            tbz.set_offset(relative_address);
            session.add_instruction(tbz, dest);
            break;
          }

          dataloc = ctx.allocate_address();
          session.add_instruction(
              aarch64::custom::TEST_JMP_ON_ZERO(tbz, dataloc - reloc_address));
          break;
        }
        case aarch64::TBNZ::id:
        {
          auto tbnz = *reinterpret_cast<const aarch64::TBNZ*>(instr.bytes);
          if (aarch64::TBNZ::offset_fits(relative_address))
          {
            tbnz.set_offset(relative_address);
            session.add_instruction(tbnz, dest);
            break;
          }

          dataloc = ctx.allocate_address();
          session.add_instruction(aarch64::custom::TEST_JMP_ON_NON_ZERO(
              tbnz, dataloc - reloc_address));
          break;
        }
        default: assert(!"relative branch unhandled");
        }

        utils_assert(!in_overriden_area || !dataloc,
                     "target address of a branch is in overriden area but a "
                     "far branch was attempted");
        if (dataloc)
          *reinterpret_cast<uintptr_t*>(dataloc) = dest;

        if (!in_overriden_area && !is_conditional_or_call &&
            !ctx.branch_list.in_branch())
        {
          ctx.finished = true;
          break;
        }
      }
      else if (ldr_relative(instr))
      {
        assert(aarch64.get_immediate(instr.detail->aarch64).has_value());
        auto       raw = *reinterpret_cast<const uint32_t*>(instr.bytes);
        const auto load_address =
            aarch64.get_immediate(instr.detail->aarch64).value();
        const ptrdiff_t prev_relative_address = load_address - instr.address;
        ptrdiff_t new_relative_address = load_address - ctx.trampoline.uend;

        if ((raw & aarch64::LDRV_LITERAL::opcode) ==
            aarch64::LDRV_LITERAL::opcode)
        {
          auto ldrv =
              *reinterpret_cast<const aarch64::LDRV_LITERAL*>(instr.bytes);
          aarch64::reg_t reg{};

          if (aarch64::LDRV_LITERAL::offset_fits(new_relative_address))
          {
            ldrv.set_offset(new_relative_address);
            session.add_instruction(ldrv);
          }
          else
          {
            switch (ldrv.register_size())
            {
            case 4:
              reg = static_cast<aarch64::reg_t>(
                  ldrv.template get_register<aarch64::wregisters>());

              if (aarch64::LDRVu32::offset_fits(prev_relative_address))
                session.add_instruction(
                    aarch64::LDRVu32(reg, aarch64::X0, prev_relative_address));
              else
                session.add_instruction(aarch64::custom::LDRV32_ABS(
                    reg, aarch64::X0, session.use_pc_handling(load_address)));
              break;
            case 8:
              reg = static_cast<aarch64::reg_t>(
                  ldrv.template get_register<aarch64::xregisters>());

              if (aarch64::LDRVu64::offset_fits(prev_relative_address))
                session.add_instruction(
                    aarch64::LDRVu64(reg, aarch64::X0, prev_relative_address));
              else
                session.add_instruction(aarch64::custom::LDRV64_ABS(
                    reg, aarch64::X0, session.use_pc_handling(load_address)));
              break;
            case 16:
              reg = static_cast<aarch64::reg_t>(
                  ldrv.template get_register<aarch64::qregisters>());

              if (aarch64::LDRVu128::offset_fits(prev_relative_address))
                session.add_instruction(
                    aarch64::LDRVu128(reg, aarch64::X0, prev_relative_address));
              else
                session.add_instruction(aarch64::custom::LDRV128_ABS(
                    reg, aarch64::X0, session.use_pc_handling(load_address)));
              break;
            default: assert(!"unhandled relative simd ldr");
            }
          }
        }
        else if ((raw & aarch64::LDRSW_LITERAL::opcode) ==
                 aarch64::LDRSW_LITERAL::opcode)
        {
          auto ldrsw =
              *reinterpret_cast<const aarch64::LDRSW_LITERAL*>(instr.bytes);

          if (aarch64::LDRSW_LITERAL::offset_fits(new_relative_address))
          {
            ldrsw.set_offset(new_relative_address);
            session.add_instruction(ldrsw);
          }
          else
          {
            aarch64::reg_t reg = ldrsw.get_register();

            if (aarch64::LDRSWu::offset_fits(prev_relative_address))
              session.add_instruction(
                  aarch64::LDRSWu(reg, aarch64::X0, prev_relative_address));
            else
              session.add_instruction(aarch64::custom::LDRSW_ABS(
                  reg, aarch64::X0, session.use_pc_handling(load_address)));
          }
        }
        else
        {
          assert((raw & aarch64::LDR_LITERAL::opcode) ==
                 aarch64::LDR_LITERAL::opcode);
          auto ldr =
              *reinterpret_cast<const aarch64::LDR_LITERAL*>(instr.bytes);
          aarch64::reg_t reg{};

          if (aarch64::LDR_LITERAL::offset_fits(new_relative_address))
          {
            ldr.set_offset(new_relative_address);
            session.add_instruction(ldr);
          }
          else if (ldr.register_size() == 4)
          {
            reg = static_cast<aarch64::reg_t>(
                ldr.template get_register<aarch64::wregisters>());

            if (aarch64::LDRu32::offset_fits(prev_relative_address))
              session.add_instruction(
                  aarch64::LDRu32(reg, aarch64::X0, prev_relative_address));
            else
              session.add_instruction(aarch64::custom::LDR32_ABS(
                  reg, aarch64::X0, session.use_pc_handling(load_address)));
          }
          else
          {
            reg = static_cast<aarch64::reg_t>(
                ldr.template get_register<aarch64::xregisters>());

            if (aarch64::LDRu64::offset_fits(prev_relative_address))
              session.add_instruction(
                  aarch64::LDRu64(reg, aarch64::X0, prev_relative_address));
            else
              session.add_instruction(aarch64::custom::LDR64_ABS(
                  reg, aarch64::X0, session.use_pc_handling(load_address)));
          }
        }
      }
      else if (aarch64.is_return(instr) || aarch64.is_branch(instr))
      {
        session.break_pc_handling();
        if (!ctx.branch_list.in_branch())
        {
          ctx.finished = true;
          break;
        }
      }

      if (const uintptr_t relocated_size = ctx.target.end - ctx.target.begin;
          relocated_size >= ctx.size_needed)
      {
        ctx.finished = true;
        if (!session.holds_instructions())
          session.add_instruction(instr);
        session.break_pc_handling();

        const uintptr_t reloc_address    = session.next_reloc_address();
        const ptrdiff_t relative_address = ctx.target.uend - reloc_address;

        if (aarch64::B::offset_fits(relative_address))
        {
          session.add_unregistered_instruction(aarch64::B(relative_address));
          break;
        }

        const uintptr_t dataloc = ctx.allocate_address(ctx.target.uend);
        session.add_unregistered_instruction(
            aarch64::custom::JMP(dataloc - reloc_address));
        break;
      }
    }

    ctx.cleanup();
    const uintptr_t target_size = ctx.target.end - ctx.target.begin;

    if (target_size < ctx.size_needed &&
        !ctx.rest_is_pad(ctx.size_needed - target_size))
    {
      auto* relay_address = utils::align_up(ctx.trampoline.end,
                                            alignof(aarch64::custom::FULL_JMP));

      if (const ptrdiff_t relative_address = relay_address - ctx.target.begin;
          target_size >= sizeof(aarch64::B) &&
          aarch64::B::offset_fits(relative_address))
      {
        ctx.must_fit(sizeof(aarch64::custom::FULL_JMP) +
                     (relay_address - ctx.trampoline.end));
        new (relay_address) aarch64::custom::FULL_JMP();
        prelay = relay_address;
      }
      else if ((target_size >= sizeof(aarch64::custom::JMP) ||
                ctx.rest_is_pad(sizeof(aarch64::custom::JMP) - target_size)) &&
               ctx.is_pad(ctx.target.begin - sizeof(uintptr_t),
                          sizeof(uintptr_t)))
        patch_above = true;
      else
        throw(exceptions::insufficient_function_size(
            ctx.target.begin, target_size, ctx.size_needed));
    }

    ptarget        = target;
    tramp_size     = ctx.trampoline.end - ctx.trampoline.begin;
    available_size = ctx.allocator.available_size;
    pc_handling    = ctx.pc_handling_context.startup_location;
#if !utils_windows
    old_protect = tmp_protinfo;
#endif
    positions = ctx.positions;
  }

  // consists of updated properties of the destination trampoline which are [the
  // size, the available size, the positions]
  typedef std::tuple<size_t, uint8_t, typename trampoline_context::positions_t>
      trampcpy_ret_t;

  static trampcpy_ret_t
      trampcpy(std::byte* dest, const std::byte* src, const uint8_t size,
               const uint8_t                            available_size,
               typename trampoline_context::positions_t positions)
  {
    if (!size)
      return {};
    utils_assert(abs(dest - src) > size, "trampcpy: pointers overlap");

    typedef typename trampoline_context::session::buffer_t buffer_t;

    disassembler      aarch64{ src };
    address_allocator allocator{ available_size };

#ifndef NDEBUG
    std::fill(reinterpret_cast<aarch64::BRK*>(dest),
              reinterpret_cast<aarch64::BRK*>(dest + memory_slot_size),
              aarch64::BRK(0));
#endif

    const uintptr_t usrc           = reinterpret_cast<uintptr_t>(src);
    const uintptr_t udest          = reinterpret_cast<uintptr_t>(dest);
    uint8_t         position_index = 0;

    union
    {
      std::byte* dest_end;
      uintptr_t  udest_end;
    };

    dest_end = dest;

    for (const cs_insn& instr : aarch64.disasm(size))
    {
      buffer_t    buffer{};
      size_t      copy_size   = instr.size;
      const void* copy_source = instr.bytes;

      if (aarch64.is_relative_branch(instr))
      {
        assert(aarch64.get_immediate(instr.detail->aarch64).has_value());
        const uintptr_t branch_dest =
            aarch64.get_immediate(instr.detail->aarch64).value();
        if (branch_dest < usrc || (usrc + memory_slot_size) <= branch_dest)
        {
          const ptrdiff_t relative_address = branch_dest - udest_end;

          switch (instr.id)
          {
          case aarch64::B::id:
          {
            if (utils::any_of(instr.detail->aarch64.cc, AArch64CC_Invalid,
                              AArch64CC_AL))
            {
              if (aarch64::B::offset_fits(relative_address))
              {
                copy_source = new (buffer.data()) aarch64::B(relative_address);
                copy_size   = sizeof(aarch64::B);
                break;
              }

              const uintptr_t dataloc = allocator.allocate(udest, branch_dest);
              copy_source =
                  new (buffer.data()) aarch64::custom::JMP(dataloc - udest_end);
              copy_size = sizeof(aarch64::custom::JMP);
              break;
            }

            if (aarch64::B_cond::offset_fits(relative_address))
            {
              copy_source = new (buffer.data())
                  aarch64::B_cond(relative_address, instr.detail->aarch64.cc);
              copy_size = sizeof(aarch64::B_cond);
              break;
            }

            const uintptr_t dataloc = allocator.allocate(udest, branch_dest);
            copy_source = new (buffer.data()) aarch64::custom::CONDITIONAL_JMP(
                instr.detail->aarch64.cc, dataloc - udest_end);
            copy_size = sizeof(aarch64::custom::CONDITIONAL_JMP);
            break;
          }
          case aarch64::BL::id:
          {
            if (aarch64::BL::offset_fits(relative_address))
            {
              copy_source = new (buffer.data()) aarch64::BL(relative_address);
              copy_size   = sizeof(aarch64::BL);
              break;
            }

            const uintptr_t dataloc = allocator.allocate(udest, branch_dest);
            copy_source =
                new (buffer.data()) aarch64::custom::CALL(dataloc - udest_end);
            copy_size = sizeof(aarch64::custom::CALL);
            break;
          }
          case aarch64::CBZ::id:
          {
            auto cbz = *reinterpret_cast<const aarch64::CBZ*>(instr.bytes);
            if (aarch64::CBZ::offset_fits(relative_address))
            {
              cbz.set_offset(relative_address);
              copy_source = new (buffer.data()) auto(cbz);
              copy_size   = sizeof(cbz);
              break;
            }

            const uintptr_t dataloc = allocator.allocate(udest, branch_dest);
            copy_source             = new (buffer.data())
                aarch64::custom::JMP_IF_ZERO(cbz, dataloc - udest_end);
            copy_size = sizeof(aarch64::custom::JMP_IF_ZERO);
            break;
          }
          case aarch64::CBNZ::id:
          {
            auto cbnz = *reinterpret_cast<const aarch64::CBNZ*>(instr.bytes);
            if (aarch64::CBNZ::offset_fits(relative_address))
            {
              cbnz.set_offset(relative_address);
              copy_source = new (buffer.data()) auto(cbnz);
              copy_size   = sizeof(cbnz);
              break;
            }

            const uintptr_t dataloc = allocator.allocate(udest, branch_dest);
            copy_source             = new (buffer.data())
                aarch64::custom::JMP_IF_NOT_ZERO(cbnz, dataloc - udest_end);
            copy_size = sizeof(aarch64::custom::JMP_IF_NOT_ZERO);
            break;
          }
          case aarch64::TBZ::id:
          {
            auto tbz = *reinterpret_cast<const aarch64::TBZ*>(instr.bytes);
            if (aarch64::TBZ::offset_fits(relative_address))
            {
              tbz.set_offset(relative_address);
              copy_source = new (buffer.data()) auto(tbz);
              copy_size   = sizeof(tbz);
              break;
            }

            const uintptr_t dataloc = allocator.allocate(udest, branch_dest);
            copy_source             = new (buffer.data())
                aarch64::custom::TEST_JMP_ON_ZERO(tbz, dataloc - udest_end);
            copy_size = sizeof(aarch64::custom::TEST_JMP_ON_ZERO);
            break;
          }
          case aarch64::TBNZ::id:
          {
            auto tbnz = *reinterpret_cast<const aarch64::TBNZ*>(instr.bytes);
            if (aarch64::TBNZ::offset_fits(relative_address))
            {
              tbnz.set_offset(relative_address);
              copy_source = new (buffer.data()) auto(tbnz);
              copy_size   = sizeof(tbnz);
              break;
            }

            const uintptr_t dataloc = allocator.allocate(udest, branch_dest);
            copy_source             = new (buffer.data())
                aarch64::custom::TEST_JMP_ON_NON_ZERO(tbnz,
                                                      dataloc - udest_end);
            copy_size = sizeof(aarch64::custom::TEST_JMP_ON_NON_ZERO);
            break;
          }
          default: assert(!"unhandled relative branch instruction");
          }
        }
      }
      else if (ldr_relative(instr))
      {
        assert(aarch64.get_immediate(instr.detail->aarch64));
        auto      raw = *reinterpret_cast<const uint32_t*>(instr.bytes);
        uintptr_t load_address =
            aarch64.get_immediate(instr.detail->aarch64).value();
        if (usrc <= load_address && load_address < (usrc + memory_slot_size))
          load_address = udest + (load_address - usrc);
        ptrdiff_t relative_address = load_address - udest_end;

        if ((raw & aarch64::LDR_LITERAL::opcode) ==
            aarch64::LDR_LITERAL::opcode)
        {
          if (!aarch64::LDR_LITERAL::offset_fits(relative_address))
            throw(exceptions::unsupported_instruction_handling(
                src,
                utils::to_array<std::extent_v<decltype(cs_insn::bytes)>>(
                    reinterpret_cast<const std::byte*>(std::begin(instr.bytes)),
                    reinterpret_cast<const std::byte*>(
                        std::end(instr.bytes)))));

          auto ldr =
              *reinterpret_cast<const aarch64::LDR_LITERAL*>(instr.bytes);
          ldr.set_offset(relative_address);
          copy_source = new (buffer.data()) auto(ldr);
          copy_size   = sizeof(ldr);
        }
        else if ((raw & aarch64::LDRSW_LITERAL::opcode) ==
                 aarch64::LDRSW_LITERAL::opcode)
        {
          if (!aarch64::LDRSW_LITERAL::offset_fits(relative_address))
            throw(exceptions::unsupported_instruction_handling(
                src,
                utils::to_array<std::extent_v<decltype(cs_insn::bytes)>>(
                    reinterpret_cast<const std::byte*>(std::begin(instr.bytes)),
                    reinterpret_cast<const std::byte*>(
                        std::end(instr.bytes)))));

          auto ldrsw =
              *reinterpret_cast<const aarch64::LDRSW_LITERAL*>(instr.bytes);
          ldrsw.set_offset(relative_address);
          copy_source = new (buffer.data()) auto(ldrsw);
          copy_size   = sizeof(ldrsw);
        }
        else
        {
          utils_assert((raw & aarch64::LDRV_LITERAL::opcode) ==
                           aarch64::LDRV_LITERAL::opcode,
                       "unhandled relative load");
          if (!aarch64::LDRV_LITERAL::offset_fits(relative_address))
            throw(exceptions::unsupported_instruction_handling(
                src,
                utils::to_array<std::extent_v<decltype(cs_insn::bytes)>>(
                    reinterpret_cast<const std::byte*>(std::begin(instr.bytes)),
                    reinterpret_cast<const std::byte*>(
                        std::end(instr.bytes)))));

          auto ldrv =
              *reinterpret_cast<const aarch64::LDRV_LITERAL*>(instr.bytes);
          ldrv.set_offset(relative_address);
          copy_source = new (buffer.data()) auto(ldrv);
          copy_size   = sizeof(ldrv);
        }
      }

      if ((dest_end + copy_size) > (dest + allocator.available_size))
        throw(exceptions::trampoline_max_size_exceeded(
            src, (dest_end + copy_size) - dest, allocator.available_size));

      if (position_index != positions.size() &&
          positions[position_index].second ==
              static_cast<uint8_t>(instr.address - usrc))
        positions[position_index++].second =
            static_cast<uint8_t>(dest_end - dest);

      memcpy(dest_end, copy_source, copy_size);
      dest_end += copy_size;
    }

    return { dest_end - dest, allocator.available_size, positions };
  }

  trampoline::trampoline(const trampoline& other)
      : ptarget(other.ptarget),
        ptrampoline(other.ptarget
                        ? trampoline_buffer::allocate(__origin(other.ptarget))
                        : nullptr),
        patch_above(other.patch_above), pc_handling(other.pc_handling)
  {
    std::tie(tramp_size, available_size, positions) =
        trampcpy(ptrampoline.get(), other.ptrampoline.get(), other.tramp_size,
                 other.available_size, other.positions);
#if !utils_windows
    old_protect = other.old_protect;
#endif
    if (other.prelay)
    {
      prelay =
          utils::align_up(ptrampoline.get() + tramp_size, alignof(uintptr_t));
      if (prelay >= (ptrampoline.get() + available_size))
        throw(exceptions::trampoline_max_size_exceeded(
            ptarget, prelay - ptrampoline.get(), available_size));
      memcpy(prelay, other.prelay, sizeof(aarch64::custom::FULL_JMP));
    }
  }

  trampoline::trampoline(trampoline&& other) noexcept
      : ptarget(std::exchange(other.ptarget, nullptr)),
        ptrampoline(std::move(other.ptrampoline)),
        prelay(std::exchange(other.prelay, nullptr)),
        patch_above(std::exchange(other.patch_above, false)),
        tramp_size(std::exchange(other.tramp_size, 0)),
        pc_handling(std::exchange(other.pc_handling, std::nullopt)),
        available_size(std::exchange(other.available_size, 0)),
        positions(std::move(other.positions))
  {
#if !utils_windows
    old_protect = std::exchange(other.old_protect, protection_info{});
#endif
  }

  trampoline& trampoline::operator=(const trampoline& other)
  {
    if (this == &other)
      return *this;
    if (!other.ptarget)
    {
      reset();
      return *this;
    }

    if (!ptrampoline)
    {
      trampoline_ptr newbuff{ trampoline_buffer::allocate(
          __origin(other.ptarget)) };
      std::tie(tramp_size, available_size, positions) =
          trampcpy(newbuff.get(), other.ptrampoline.get(), other.tramp_size,
                   other.available_size, other.positions);
      ptrampoline = std::move(newbuff);
    }
    else
      std::tie(tramp_size, available_size, positions) =
          trampcpy(ptrampoline.get(), other.ptrampoline.get(), other.tramp_size,
                   other.available_size, other.positions);

    ptarget     = other.ptarget;
    patch_above = other.patch_above;
    pc_handling = other.pc_handling;
#if !utils_windows
    old_protect = other.old_protect;
#endif
    prelay = nullptr;

    if (other.prelay)
    {
      prelay =
          utils::align_up(ptrampoline.get() + tramp_size, alignof(uintptr_t));
      if (prelay >= (ptrampoline.get() + available_size))
        throw(exceptions::trampoline_max_size_exceeded(
            ptarget, prelay - ptrampoline.get(), available_size));
      memcpy(prelay, other.prelay, sizeof(aarch64::custom::FULL_JMP));
    }
    return *this;
  }

  trampoline& trampoline::operator=(trampoline&& other) noexcept
  {
    if (this == &other)
      return *this;
    if (!other.ptarget)
    {
      reset();
      return *this;
    }

    ptarget        = std::exchange(other.ptarget, nullptr);
    ptrampoline    = std::move(other.ptrampoline);
    prelay         = std::exchange(other.prelay, nullptr);
    patch_above    = std::exchange(other.patch_above, false);
    tramp_size     = std::exchange(other.tramp_size, 0);
    pc_handling    = std::exchange(other.pc_handling, std::nullopt);
    available_size = std::exchange(other.available_size, 0);
    positions      = std::move(other.positions);
#if !utils_windows
    old_protect = std::exchange(other.old_protect, protection_info{});
#endif
    return *this;
  }

  void trampoline::reset()
  {
    if (!ptarget)
      return;
    ptarget        = nullptr;
    prelay         = nullptr;
    patch_above    = false;
    tramp_size     = 0;
    pc_handling    = std::nullopt;
    available_size = 0;
    positions.clear();
#if !utils_windows
    old_protect = {};
#endif
  }

  std::string trampoline::str() const
  {
    utils_assert(ptarget,
                 "attempted to disassemble an uninitialized trampoline");
    std::stringstream stream;
    disassembler      aarch64{ ptrampoline.get(), false };
    stream << std::hex;

    for (const cs_insn& instr : aarch64.disasm(tramp_size))
    {
      if (instr.address != reinterpret_cast<uintptr_t>(ptrampoline.get()))
        stream << '\n';
      stream << "0x" << std::setfill('0') << std::setw(8) << instr.address
             << ": " << instr.mnemonic << '\t' << instr.op_str;
    }
    return stream.str();
  }
} // namespace alterhook

#pragma GCC diagnostic pop
