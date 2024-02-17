/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#include <pch.h>
#include "exceptions.h"
#include "disassembler.h"
#include "instructions.h"
#include "buffer.h"
#include "trampoline.h"

#if !utils_msvc
  #pragma GCC diagnostic push
  #pragma GCC diagnostic ignored "-Wswitch"
  #pragma GCC diagnostic ignored "-Wmissing-braces"
#endif

namespace alterhook
{
  extern std::shared_mutex hook_lock;

  void trampoline::deleter::operator()(std::byte* ptrampoline) const noexcept
  {
    trampoline_buffer::deallocate(ptrampoline);
  }

  namespace
  {
    constexpr size_t max_branch_dests = 5;

    namespace helpers
    {
      template <typename T, typename = void>
      constexpr bool has_custom_instruction_tag_impl = false;

      template <typename T>
      constexpr bool has_custom_instruction_tag_impl<
          T, std::void_t<typename T::custom_instruction_tag>> =
          std::is_base_of_v<typename T::custom_instruction_tag, T>;
    } // namespace helpers

    template <typename T>
    constexpr bool has_custom_instruction_tag =
        helpers::has_custom_instruction_tag_impl<T>;

    template <typename T>
    constexpr bool is_custom_instruction =
        utils::derived_from_any_of<utils::remove_cvref_t<T>, arm::INSTRUCTION<>,
                                   thumb2::INSTRUCTION<>,
                                   thumb::INSTRUCTION<>> ||
        has_custom_instruction_tag<utils::remove_cvref_t<T>>;

    static std::optional<uint8_t> cs_register_to_index(arm_reg reg) noexcept
    {
      switch (reg)
      {
      case ARM_REG_R0: return 0;
      case ARM_REG_R1: return 1;
      case ARM_REG_R2: return 2;
      case ARM_REG_R3: return 3;
      case ARM_REG_R4: return 4;
      case ARM_REG_R5: return 5;
      case ARM_REG_R6: return 6;
      case ARM_REG_R7: return 7;
      case ARM_REG_R8: return 8;
      case ARM_REG_SB: return 9;
      case ARM_REG_SL: return 10;
      case ARM_REG_FP: return 11;
      case ARM_REG_IP: return 12;
      case ARM_REG_SP: return 13;
      case ARM_REG_LR: return 14;
      case ARM_REG_PC: return 15;
      default: return std::nullopt;
      }
    }

    static constexpr uintptr_t arm_pc_align(uintptr_t address) noexcept
    {
      return utils::align(address, 4u);
    }

    static constexpr std::byte* arm_pc_align(std::byte* address) noexcept
    {
      return utils::align(address, 4u);
    }

    template <arm_op_type optype>
    static const cs_arm_op* get_operand(const cs_insn& instr) noexcept
    {
      const cs_arm& detail         = instr.detail->arm;
      const auto *  operands_begin = detail.operands,
                 *operands_end     = detail.operands + detail.op_count;
      return std::find_if(operands_begin, operands_end,
                          [](const cs_arm_op& operand)
                          { return operand.type == optype; });
    }

    static std::optional<int64_t> get_immediate(const cs_insn& instr) noexcept
    {
      auto result = get_operand<ARM_OP_IMM>(instr);
      if (!result)
        return std::nullopt;
      return result->imm;
    }

    static std::optional<uint8_t>
        get_register_as_index(const cs_insn& instr) noexcept
    {
      auto result = get_operand<ARM_OP_REG>(instr);
      if (!result)
        return std::nullopt;
      return cs_register_to_index(arm_reg(result->reg));
    }

    static std::optional<arm_op_mem>
        get_memory_operand(const cs_insn& instr) noexcept
    {
      auto result = get_operand<ARM_OP_MEM>(instr);
      if (!result)
        return std::nullopt;
      return result->mem;
    }

    template <arm_insn_group group>
    static bool is_of_group(const cs_insn& instr) noexcept
    {
      return memchr(instr.detail->groups, group, instr.detail->groups_count);
    }

    static instruction_set instruction_set_from(bool     thumb,
                                                uint16_t size) noexcept
    {
      return thumb
                 ? size == 4 ? instruction_set::THUMB2 : instruction_set::THUMB
                 : instruction_set::ARM;
    }

    template <typename T>
    static utils_consteval instruction_set instruction_set_from(T&&) noexcept
    {
      typedef utils::remove_cvref_t<T> clean_t;
      return clean_t::instr_set;
    }

    struct any_instruction
    {
      std::byte*          src       = nullptr;
      cs_operand_encoding encoding  = {};
      instruction_set     instr_set = instruction_set::UNKNOWN;

      any_instruction(std::byte* src, const cs_operand_encoding& encoding,
                      instruction_set instr_set)
          : src(src), encoding(encoding), instr_set(instr_set)
      {
      }

      void set_register(uint8_t reg) const noexcept
      {
        utils_assert(src && encoding.operand_pieces_count &&
                         instr_set != instruction_set::UNKNOWN,
                     "an instance of the handler for an unknown instruction is "
                     "left uninitialized");
        utils_assert(
            encoding.operand_pieces_count <= 2,
            "can't handle register that is encoded in more than 2 pieces");
        utils_assert(
            (encoding.sizes[0] + encoding.sizes[1]) == 4,
            "can't patch a register that is of size other than 4 bits");

        // safety measures
        if (instr_set == instruction_set::THUMB)
          do_patch(*reinterpret_cast<uint16_t*>(src), reg);
        else
          do_patch(*reinterpret_cast<uint32_t*>(src), reg);
      }

    private:
      template <typename instr_t>
      void do_patch(instr_t& instr, uint8_t reg) const noexcept
      {
        instr = patch_operand<2>(instr_set, encoding, instr, reg);
      }
    };

    struct patched_small_ldr : templates::custom_instruction<1>
    {
    public:
      typedef typename thumb2::LDR_IMM::offset_t offset_t;

      patched_small_ldr(uint8_t destreg, uint8_t patchedreg, offset_t offset)
          : instr(destreg, patchedreg, offset)
      {
      }

      void set_register(uint8_t reg) noexcept
      {
        instr.set_source_register(reg);
      }

    private:
      thumb2::LDR_IMM instr;
    };

    struct patched_adr : templates::custom_instruction<1>
    {
    public:
      typedef int16_t offset_t;

      patched_adr(uint8_t destreg, uint8_t patchedreg, offset_t offset);

      // encodings are identical so it doesn't matter whether we choose add or
      // sub here
      void set_register(uint8_t reg) { instr.add.set_source_register(reg); }

    private:
      union instr_t
      {
        thumb2::ADD add;
        thumb2::SUB sub;

        instr_t(thumb2::ADD add) : add(add) {}

        instr_t(thumb2::SUB sub) : sub(sub) {}
      } instr;
    };

    patched_adr::patched_adr(uint8_t destreg, uint8_t patchedreg,
                             offset_t offset)
        : instr(offset >= 0
                    ? instr_t(thumb2::ADD(destreg, patchedreg, offset))
                    : instr_t(thumb2::SUB(destreg, patchedreg, abs(offset))))
    {
    }

    template <typename instr_t>
    struct pc_handling_push
    {
      typedef std::variant<arm::PUSH_REGLIST*, thumb2::PUSH_REGLIST*,
                           thumb::PUSH_REGLIST*>
                                     original_push_t;
      instr_t*                       pinstr = nullptr;
      std::optional<original_push_t> original_push;

      pc_handling_push(instr_t* pinstr) : pinstr(pinstr) {}

      template <typename T>
      pc_handling_push(instr_t* pinstr, T&& value)
          : pinstr(pinstr), original_push(std::forward<T>(value))
      {
      }

      void patch(uint8_t reg) const noexcept
      {
        if (!original_push)
        {
          pinstr->set_register(reg);
          return;
        }

        std::visit(
            [&](auto* push)
            {
              typedef std::remove_pointer_t<decltype(push)> push_t;
              if (!push->greatest(reg))
              {
                pinstr->set_register(reg);
                return;
              }

              push->append(reg);
              if constexpr (push_t::instr_set != instruction_set::ARM)
                new (pinstr) thumb::NOP;
              else
                new (pinstr) arm::NOP;
            },
            original_push.value());
      }
    };

    struct to_be_modified
    {
      typedef std::variant<arm::PUSH_REGLIST*, thumb2::PUSH_REGLIST*,
                           thumb::PUSH_REGLIST*>
          original_push_t;
      typedef std::variant<any_instruction, pc_handling_push<thumb::PUSH>,
                           thumb::POP*, thumb::LDR_LITERAL*, thumb::PUSH*,
                           thumb::ADD*, patched_adr*, thumb2::ADD*,
                           patched_small_ldr*, pc_handling_push<arm::PUSH>,
                           arm::POP*, arm::LDR_LITERAL*, arm::ADD*>
          instr_t;

      instr_t instr;

      template <typename T>
      to_be_modified(T&& arg) : instr(std::forward<T>(arg))
      {
      }

      void modify(reg_t reg)
      {
#ifndef __INTELLISENSE__
        std::visit(
            utils::overloaded{
                [&](const any_instruction& instr) { instr.set_register(reg); },
                [&](auto* ptr) { ptr->set_register(reg); },
                [&](const auto& custom_push) { custom_push.patch(reg); } },
            instr);
#endif
      }
    };

    struct branch_destination
    {
      static constexpr size_t max_references = 5;

      struct reference
      {
        typedef std::variant<arm::B*, thumb2::B*, thumb2::B_cond*, arm::BL*,
                             thumb2::BL*, arm::BLX*, thumb2::BLX*,
                             arm::custom::BX_RELATIVE*>
              src_t;
        src_t src;

        template <typename T>
        reference(T&& arg) : src(std::forward<T>(arg))
        {
        }

        bool is_thumb()
        {
          return std::visit(
              [](auto* ptr)
              {
                typedef std::remove_pointer_t<decltype(ptr)> T;
                return T::instr_set == instruction_set::ARM;
              },
              src);
        }
      };

      typedef utils::static_vector<reference, max_references> references_t;

      uint8_t         id        = 0;
      std::byte*      dest      = nullptr;
      instruction_set instr_set = instruction_set::UNKNOWN;
      references_t    references{};

      branch_destination(uint8_t id) : id(id) {}
    };

    struct branch_destination_list
        : utils::static_vector<branch_destination, max_branch_dests>
    {
      iterator get_entry(uint8_t id) noexcept
      {
        return std::find_if(begin(), end(),
                            [=](const branch_destination& branch_dest)
                            { return branch_dest.id == id; });
      }

      void patch_offset(branch_destination&                     branch_entry,
                        typename branch_destination::reference& ref) noexcept
      {
        std::visit(
            [&](auto* psrc)
            {
              typedef std::remove_pointer_t<decltype(psrc)> instr_t;
              typedef typename instr_t::offset_t            offset_t;
              constexpr instruction_set instr_set = instr_t::instr_set;
              constexpr offset_t        pc_offset =
                  instr_set == instruction_set::ARM ? 8 : 4;
              const offset_t relative_address =
                  branch_entry.dest -
                  (reinterpret_cast<std::byte*>(psrc) + pc_offset);
              psrc->set_offset(relative_address);
            },
            ref.src);
      }

      void process(uint8_t id)
      {
        auto result = get_entry(id);
        if (result == end())
          return;
        utils_assert(result->dest,
                     "branch_destination_list::process: a branch destination "
                     "entry doesn't have its pointer set");

        for (auto& reference : result->references)
          patch_offset(*result, reference);

        erase(result);
      }

      void fix_leftover_branches(std::byte* target)
      {
        for (branch_destination& branch_dest : *this)
        {
          for (auto& ref : branch_dest.references)
          {
            std::visit(
                [&](auto* pinstr)
                {
                  typedef std::remove_pointer_t<decltype(pinstr)> instr_t;
                  constexpr uint8_t                               pc_offset =
                      instr_t::instr_set != instruction_set::ARM ? 4 : 8;
                  const intptr_t relative_address =
                      (target + branch_dest.id) -
                      arm_pc_align(reinterpret_cast<std::byte*>(pinstr) +
                                   pc_offset);
                  if (!instr_t::offset_fits(relative_address))
                    throw(exceptions::instructions_in_branch_handling_fail(
                        target));
                  pinstr->set_offset(relative_address);
                },
                ref.src);
          }
        }

        clear();
      }

      void set_new_location(uint8_t id, std::byte* dest)
      {
        auto result = get_entry(id);
        if (result == end())
          return;
        result->dest = dest;
      }

      [[noreturn]] void
          throw_ambiguous_instruction_set(std::byte*          target,
                                          branch_destination& entry)
      {
        exceptions::byte_array<32> buffer{};
        uint8_t                    pos = 0;
        std::bitset<32>            instruction_sets{};

        for (auto& reference : entry.references)
        {
          std::visit(
              [&](auto* ptr)
              {
                typedef std::remove_pointer_t<decltype(ptr)> T;
                assert((pos + sizeof(T)) < 32);
                new (&buffer[pos]) auto(*ptr);
                instruction_sets.set(pos, T::instr_set != instruction_set::ARM);
                pos += sizeof(T);
              },
              reference.src);
        }

        throw(exceptions::ambiguous_instruction_set(
            target, buffer, pos, instruction_sets, entry.dest));
      }

      template <typename T>
      void insert_or_add_reference(std::byte* target, uint8_t id,
                                   instruction_set instr_set, T&& reference)
      {
        auto result = get_entry(id);
        if (result != end())
        {
          if (result->instr_set != instruction_set::UNKNOWN)
          {
            if (result->instr_set != instr_set &&
                utils::any_of(instruction_set::ARM, instr_set,
                              result->instr_set))
              throw_ambiguous_instruction_set(target, *result);
          }
          result->instr_set = instr_set;
          result->references.emplace_back(std::forward<T>(reference));
          return;
        }

        auto& new_element     = emplace_back(id);
        new_element.instr_set = instr_set;
        new_element.references.emplace_back(std::forward<T>(reference));
      }
    };

    struct trampoline_context
    {
      struct session;
      typedef typename to_be_modified::original_push_t original_push_t;
      typedef std::optional<original_push_t>           optional_original_push_t;
      typedef std::optional<uint8_t>                   pc_handling_begin_t;
      typedef utils::static_vector<std::pair<uint8_t, uint8_t>, 8> positions_t;
      typedef utils::static_vector<to_be_modified, 16>             tbm_list_t;
      typedef std::bitset<memory_slot_size> buffer_bitset_t;

      bool                     finished    = false;
      bool                     thumb       = false;
      bool                     pc_handling = false;
      const uint8_t            size_needed = 0;
      std::bitset<8>           instruction_sets{};
      std::bitset<16>          registers_found{};
      buffer_bitset_t          bytes_used{};
      uint8_t                  last_unused_pos   = 0;
      uint8_t                  available_size    = memory_slot_size;
      uintptr_t                pc_val            = 0;
      pc_handling_begin_t      pc_handling_begin = std::nullopt;
      positions_t              positions{};
      tbm_list_t               tbm_list{};
      branch_destination_list  branch_list{};
      optional_original_push_t original_push = std::nullopt;

      struct
      {
        uint8_t remaining;

        union
        {
          std::byte* original_address;
          uintptr_t  uoriginal_address;
        };

        thumb::IT* pinstr;
      } it_context{};

      union
      {
        std::byte* custom_pc;
        uintptr_t  ucustom_pc;
      };

      struct trampoline_t
      {
        union
        {
          std::byte* const begin;
          const uintptr_t  ubegin;
        };

        union
        {
          std::byte* end;
          uintptr_t  uend;
        };

        union
        {
          std::byte* const buffer_end;
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
      public:
        union
        {
          std::byte* const begin;
          const uintptr_t  ubegin;
        };

        union
        {
          std::byte* end;
          uintptr_t  uend;
        };

        target_t(std::byte* target)
            : target_t(reinterpret_cast<uintptr_t>(target) & ~1u)
        {
        }

      private:
        target_t(uintptr_t target) : ubegin(target), uend(target) {}
      } target;

      trampoline_context(std::byte* target, std::byte* trampoline)
          : thumb(reinterpret_cast<uintptr_t>(target) & 1),
            size_needed(thumb && (reinterpret_cast<uintptr_t>(target) % 4)
                            ? sizeof(arm::custom::FULL_JMP) + 2
                            : sizeof(arm::custom::FULL_JMP)),
            custom_pc(nullptr), trampoline(trampoline), target(target)
      {
      }

      bool is_pad(const std::byte* address,
                  uint8_t          required_size) const noexcept
      {
        union
        {
          const uint32_t* u32;
          const uint16_t* u16;
        } src{ reinterpret_cast<const uint32_t*>(address) };

        if (thumb)
        {
          constexpr uint16_t tnop  = thumb::NOP::opcode;
          constexpr uint32_t t2nop = thumb2::NOP::opcode;
          required_size            = utils::align_up(required_size, 2u);
          if (*src.u16 == tnop || !(*src.u16))
            return std::all_of(src.u16 + 1, src.u16 + (required_size / 2u),
                               [x = *src.u16](const uint16_t value)
                               { return value == x; });
          required_size = utils::align_up(required_size, 4u);
          return std::all_of(src.u32, src.u32 + (required_size / 4u),
                             [](const uint32_t value)
                             { return value == t2nop; });
        }

        constexpr uint32_t nop     = arm::NOP::opcode;
        constexpr uint32_t nopmask = 0xF'FF'FF'FF;
        required_size              = utils::align_up(required_size, 4u);
        if ((*src.u32 & nopmask) == nop || !(*src.u32))
          return std::all_of(src.u32 + 1, src.u32 + (required_size / 4u),
                             [x = *src.u32](const uint32_t value)
                             { return value == x; });
        return false;
      }

      bool rest_is_pad(uint8_t required_size) const noexcept
      {
        return is_pad(target.end, required_size);
      }

      uintptr_t allocate_address(uintptr_t fill = 0) noexcept
      {
        const uintptr_t available_space  = trampoline.ubegin + available_size;
        uintptr_t       dataloc          = 0;
        bytes_used                      |= 0b1111 << last_unused_pos;
        last_unused_pos                 += sizeof(uintptr_t);
        dataloc         = trampoline.ubuffer_end - last_unused_pos;
        available_size -= available_space - dataloc;
        *reinterpret_cast<uintptr_t*>(dataloc) = fill;
        return dataloc;
      }

      void must_fit(size_t copy_size)
      {
        const uint8_t tramp_pos = trampoline.end - trampoline.begin;
        if ((tramp_pos + copy_size) > available_size)
          throw(exceptions::trampoline_max_size_exceeded(
              target.begin, tramp_pos + copy_size, available_size));
      }

      bool is_in_overriden_area(uintptr_t branch_dest) noexcept
      {
        return target.ubegin <= branch_dest &&
               branch_dest < (target.ubegin + size_needed);
      }

      template <typename T>
      static constexpr uint8_t size_of(T&& arg)
      {
        typedef utils::remove_cvref_t<T> clean_t;
        if constexpr (is_custom_instruction<clean_t>)
          return sizeof(clean_t);
        else
          return arg.size;
      }

      session create_session(disassembler& arm, const cs_insn& instr);
    };

    struct trampoline_context::session
    {
      static constexpr size_t                    buffer_size = 32;
      typedef std::array<std::byte, buffer_size> buffer_t;
      typedef typename disassembler::registers   registers_t;

      template <typename T>
      class reference
      {
      public:
        reference& register_as_to_be_modified()
        {
          ctx->tbm_list.emplace_back(ptr);
          return *this;
        }

        template <typename cls_t, typename... args>
        reference& register_as_to_be_modified(args&&... values)
        {
          ctx->tbm_list.emplace_back(
              cls_t{ ptr, std::forward<args>(values)... });
          return *this;
        }

        template <template <typename...> typename cls, typename... args>
        reference& register_as_to_be_modified(args&&... values)
        {
          ctx->tbm_list.emplace_back(cls{ ptr, std::forward<args>(values)... });
          return *this;
        }

        template <typename T2 = void>
        reference& register_as_branch(uint8_t id)
        {
          if constexpr (is_custom_instruction<T>)
            ctx->branch_list.insert_or_add_reference(
                ctx->target.begin, id, instruction_set_from(*ptr), ptr);
          else
            static_assert(utils::always_false<T2>,
                          "can't register as branch a non-custom instruction");
          return *this;
        }

      private:
        trampoline_context* ctx;
        T*                  ptr;

        reference(trampoline_context* ctx, T* ptr) : ctx(ctx), ptr(ptr) {}

        friend struct session;
      };

      template <typename T>
      using instr_ptr_t = std::add_pointer_t<utils::remove_cvref_t<T>>;

      disassembler&       arm;
      trampoline_context& ctx;
      registers_t         registers{};
      buffer_t            buffer{};
      const std::byte*    copy_source = nullptr;
      uint8_t             copy_size   = 0;

      union
      {
        std::byte* const target_instruction_address;
        const uintptr_t  utarget_instruction_address;
      };

      struct
      {
        bool is_branch             : 1;
        bool switches_to_thumb     : 1;
        bool is_call               : 1;
        bool must_be_patched       : 1;
        bool breaks_pc_handling    : 1;
        bool small_pc_relative_ldr : 1;
        bool thumb_ldr_like        : 1;
        bool has_reglist           : 1;
        bool is_thumb_adr          : 1;
        bool is_conditional        : 1;

        union
        {
          std::byte* branch_destination;
          uintptr_t  ubranch_destination;
        };

        cs_operand_encoding register_encoding;
      } instruction_info{};

      session(disassembler& arm, trampoline_context& ctx, const cs_insn& instr)
          : arm(arm), ctx(ctx), registers(arm.get_all_registers(instr)),
            copy_source(reinterpret_cast<const std::byte*>(instr.bytes)),
            copy_size(instr.size), utarget_instruction_address(instr.address)
      {
        ctx.target.end += instr.size;
        ctx.branch_list.set_new_location(instr.address - ctx.target.ubegin,
                                         ctx.trampoline.end);
        inspect(instr);
      }

      session(const session&)            = delete;
      session& operator=(const session&) = delete;

      ~session()
      {
        const uint8_t target_pos =
            target_instruction_address - ctx.target.begin;
        const uint8_t tramp_pos = ctx.trampoline.end - ctx.trampoline.begin;
        ctx.must_fit(copy_size);
        ctx.branch_list.process(target_pos);
        ctx.instruction_sets.set(ctx.positions.size(), ctx.thumb);
        ctx.positions.push_back({ target_pos, tramp_pos });
        if (ctx.it_context.remaining)
          --ctx.it_context.remaining;
        if (instruction_info.is_branch &&
            instruction_info.branch_destination == ctx.target.end &&
            ctx.thumb != instruction_info.switches_to_thumb)
        {
          arm.switch_instruction_set();
          ctx.thumb = instruction_info.switches_to_thumb;
        }
        memcpy(ctx.trampoline.end, copy_source, copy_size);
        ctx.trampoline.end += copy_size;
      }

      void inspect(const cs_insn& instr)
      {
        inspect_branch(instr);
        inspect_instructions(instr);
        inspect_operands(instr);
        check_it_block(instr);
      }

      template <typename T,
                std::enable_if_t<is_custom_instruction<T>, size_t> = 0>
      auto add_instruction(T&& instr)
      {
        constexpr uint8_t instr_size = sizeof(utils::remove_cvref_t<T>);
        prepare_buffer();
        handle_it_block<T>();
        new (&buffer[copy_size]) auto(instr);
        copy_size += instr_size;
        return reference(&ctx,
                         reinterpret_cast<instr_ptr_t<T>>(
                             ctx.trampoline.end + (copy_size - instr_size)));
      }

      auto add_instruction(const cs_insn& instr)
      {
        prepare_buffer();
        handle_it_block();
        memcpy(&buffer[copy_size], instr.bytes, instr.size);
        copy_size += instr.size;
        return reference(&ctx, ctx.trampoline.end + (copy_size - instr.size));
      }

      bool holds_instructions() const noexcept
      {
        return copy_source == buffer.data();
      }

      void break_pc_handling()
      {
        if (!ctx.pc_handling)
          return;
        if (ctx.thumb)
          add_instruction(thumb::POP(r7)).register_as_to_be_modified();
        else
          add_instruction(arm::POP(r7)).register_as_to_be_modified();
        ctx.pc_handling = false;
      }

    private:
      void prepare_buffer()
      {
        if (copy_source != buffer.data())
        {
          copy_source = buffer.data();
          copy_size   = 0;
        }
      }

      void check_it_block(const cs_insn& instr)
      {
        if (!ctx.it_context.remaining ||
            (instr.id != ARM_INS_IT &&
             (!instruction_info.is_branch || ctx.it_context.remaining == 1)))
          return;

        memcpy(ctx.trampoline.end, instr.bytes, instr.size);
        auto* const it_block =
            reinterpret_cast<const std::byte*>(ctx.it_context.pinstr);
        const size_t it_block_size =
            (ctx.trampoline.end + instr.size) - it_block;
        throw(exceptions::invalid_it_block(
            ctx.target.begin,
            utils::to_array<32>(it_block, it_block + it_block_size),
            it_block_size, ctx.it_context.original_address,
            ctx.it_context.remaining));
      }

      void move_it_block()
      {
        utils_assert(ctx.it_context.remaining == ctx.it_context.pinstr->count(),
                     "this method is meant to move an empty IT block");
        new (&buffer[copy_size]) auto(*ctx.it_context.pinstr);
        new (ctx.it_context.pinstr) thumb::NOP;
        ctx.it_context.pinstr =
            reinterpret_cast<thumb::IT*>(ctx.trampoline.end + copy_size);
        copy_size += sizeof(thumb::IT);
      }

      void split_it_block()
      {
        utils_assert(ctx.it_context.remaining != ctx.it_context.pinstr->count(),
                     "this method is meant to be used when at least one "
                     "instruction is relocated to the IT block");
        auto itr = ctx.it_context.pinstr->begin() +
                   (ctx.it_context.pinstr->count() - ctx.it_context.remaining);
        auto* newit = new (&buffer[copy_size]) thumb::IT(*(itr++));

        for (; itr != ctx.it_context.pinstr->end(); ++itr)
          newit->push(*itr);

        ctx.it_context.pinstr->pop(ctx.it_context.remaining);
        ctx.it_context.pinstr =
            reinterpret_cast<thumb::IT*>(ctx.trampoline.end + copy_size);
        copy_size += sizeof(thumb::IT);
      }

      template <typename T>
      auto handle_it_block() -> std::enable_if_t<
          has_custom_instruction_tag<utils::remove_cvref_t<T>>>
      {
        typedef utils::remove_cvref_t<T> clean_t;
        constexpr size_t instr_count = clean_t::instruction_count;
        if (!ctx.it_context.remaining)
          return;
        const uint8_t it_count = ctx.it_context.pinstr->count();

        if constexpr (instr_count != 1)
        {
          // these two assertions are assumptions made to simplify the
          // implementation as they are cases that don't need to be handled
          utils_assert(!copy_size,
                       "a mixed instruction is not expected to be followed by "
                       "any other instructions in the same session");
          utils_assert(ctx.it_context.remaining == 1,
                       "a mixed instruction is expected to be the last one in "
                       "the IT block");
          const CondCodes cond = (*ctx.it_context.pinstr)[it_count - 1];

          if ((it_count + (instr_count - 1)) <= 4)
          {
            for (uint8_t i = 0; i != (instr_count - 1); ++i)
              ctx.it_context.pinstr->push(cond);
            return;
          }

          auto* newit = new (buffer.data()) thumb::IT(cond);
          for (uint8_t i = 0; i != (instr_count - 1); ++i)
            newit->push(cond);
          ctx.it_context.pinstr->pop();
          ctx.it_context.pinstr =
              reinterpret_cast<thumb::IT*>(ctx.trampoline.end + copy_size);
          copy_size += sizeof(thumb::IT);
        }
        else
        {
          if (!copy_size)
            return;

          if (ctx.it_context.remaining == it_count)
          {
            move_it_block();
            return;
          }
          split_it_block();
        }
      }

      // no handling required for non-custom tagged instructions
      template <typename T>
      auto handle_it_block() -> std::enable_if_t<
          !has_custom_instruction_tag<utils::remove_cvref_t<T>>>
      {
      }

      void handle_it_block()
      {
        if (!ctx.it_context.remaining || !copy_size)
          return;
        if (ctx.it_context.remaining == ctx.it_context.pinstr->count())
        {
          move_it_block();
          return;
        }
        split_it_block();
      }

      void inspect_branch(const cs_insn& instr)
      {
        instruction_info.switches_to_thumb = ctx.thumb;
        if (inspect_branch_instruction(instr))
          return;
        if (ctx.thumb)
          inspect_thumb_branch();
        else
          inspect_arm_branch(instr);
      }

      bool inspect_branch_instruction(const cs_insn& instr)
      {
        if (!is_of_group<ARM_GRP_CALL>(instr) &&
            !is_of_group<ARM_GRP_JUMP>(instr))
          return false;
        instruction_info.is_branch = true;
        instruction_info.is_call   = is_of_group<ARM_GRP_CALL>(instr);

        if (utils::any_of(instr.id, ARM_INS_BX, ARM_INS_BLX))
          instruction_info.switches_to_thumb =
              !instruction_info.switches_to_thumb;

        if (!is_of_group<ARM_GRP_BRANCH_RELATIVE>(instr))
          return true;

        assert(get_immediate(instr).has_value());
        instruction_info.ubranch_destination = get_immediate(instr).value();
        return true;
      }

      void inspect_arm_branch(const cs_insn& instr)
      {
        if (!registers.modifies(ARM_REG_PC))
          return;
        instruction_info.is_branch = true;
        if (!registers.reads(ARM_REG_PC))
          return;

        typedef std::bitset<64> opcode_t;
        opcode_t                opcode = instr.detail->opcode_encoding.bits;

        // check if it belongs to Data-Processing immediate category
        // since it modifies the PC it can't belong to the other 3
        // with same bit pattern.
        // source:
        // https://developer.arm.com/documentation/ddi0406/c/Application-Level-Architecture/ARM-Instruction-Set-Encoding/Data-processing-and-miscellaneous-instructions?lang=en
        if ((opcode & opcode_t(0b111)) == 0b100)
        {
          assert(get_immediate(instr).has_value());
          uintptr_t imm = get_immediate(instr).value();
          uintptr_t src = instr.address + 8;

          switch (instr.id)
          {
          case ARM_INS_MOV: instruction_info.ubranch_destination = imm; break;
          case ARM_INS_ADC: [[fallthrough]];
          case ARM_INS_ADD:
            instruction_info.ubranch_destination = src + imm;
            break;
          case ARM_INS_AND:
            instruction_info.ubranch_destination = src & imm;
            break;
          case ARM_INS_BIC:
            instruction_info.ubranch_destination = src & ~imm;
            break;
          case ARM_INS_EOR:
            instruction_info.ubranch_destination = src ^ imm;
            break;
          case ARM_INS_MVN: instruction_info.ubranch_destination = ~imm; break;
          case ARM_INS_ORR:
            instruction_info.ubranch_destination = src | imm;
            break;
          case ARM_INS_RSB: [[fallthrough]];
          case ARM_INS_RSC:
            instruction_info.ubranch_destination = imm - src;
            break;
          case ARM_INS_SBC: [[fallthrough]];
          case ARM_INS_SUB:
            instruction_info.ubranch_destination = src - imm;
            break;
          default: assert(!"unhandled data processing instruction");
          }
        }
        // exceptions to the above
        else if ((opcode & opcode_t(0b1111111)) == 0b1011000 &&
                 instr.id != ARM_INS_MOV)
        {
          auto      imm     = get_immediate(instr);
          uintptr_t address = instr.address + 8;

          switch (instr.id)
          {
          case ARM_INS_LSL:
            assert(imm.has_value());
            instruction_info.ubranch_destination = address << imm.value();
            break;
            // the address is always positive so it doesn't matter whether an
            // arithmetic or logical shift occurs
          case ARM_INS_ASR: [[fallthrough]];
          case ARM_INS_LSR:
            assert(imm.has_value());
            instruction_info.ubranch_destination = address >> imm.value();
            break;
          case ARM_INS_ROR:
            assert(imm.has_value());
            instruction_info.ubranch_destination =
                utils::ror(address, imm.value());
            break;
          case ARM_INS_RRX:
            instruction_info.ubranch_destination = utils::ror(address, 1);
            break;
          }
        }
        else
          instruction_info.is_call = registers.modifies(ARM_REG_LR);

        if (instruction_info.ubranch_destination & 1)
        {
          instruction_info.switches_to_thumb    = true;
          instruction_info.ubranch_destination &= ~1;
        }
      }

      void inspect_thumb_branch()
      {
        if (!registers.modifies(ARM_REG_PC))
          return;
        instruction_info.is_branch = true;
        if (registers.modifies(ARM_REG_LR))
          instruction_info.is_call = true;
      }

      void inspect_instructions(const cs_insn& instr)
      {
        if (utils::any_of(instr.id, ARM_INS_PUSH, ARM_INS_POP))
          instruction_info.breaks_pc_handling = true;
        else if (instr.id == ARM_INS_ADR && ctx.thumb)
        {
          instruction_info.must_be_patched = true;
          instruction_info.is_thumb_adr    = true;
        }
      }

      void inspect_operands(const cs_insn& instr)
      {
        if (!utils::any_of(instr.detail->arm.cc, ARMCC_AL, ARMCC_UNDEF))
          instruction_info.is_conditional = true;

        for (uint8_t i = 0; i != instr.detail->arm.op_count; ++i)
        {
          const cs_arm_op& operand = instr.detail->arm.operands[i];

          if (operand.type == ARM_OP_REG)
          {
            constexpr uint8_t uint8_max = (std::numeric_limits<uint8_t>::max)();
            uint8_t           register_index =
                cs_register_to_index(static_cast<arm_reg>(operand.reg))
                    .value_or(uint8_max);
            if (register_index == uint8_max)
              continue;

            if (operand.reg == ARM_REG_PC && operand.access == CS_AC_READ &&
                !instruction_info.is_branch)
            {
              if (operand.encoding.operand_pieces_count == 1 &&
                  operand.encoding.sizes[0] == 1)
              {
                const std::byte* src =
                    reinterpret_cast<const std::byte*>(instr.bytes);
                throw(exceptions::unsupported_instruction_handling(
                    ctx.target.begin,
                    utils::to_array<24>(src, src + instr.size), ctx.thumb));
              }

              instruction_info.register_encoding = operand.encoding;
              instruction_info.must_be_patched   = true;
              continue;
            }

            if (operand.encoding.operand_pieces_count == 1 &&
                operand.encoding.sizes[0] == 1)
            {
              instruction_info.has_reglist        = true;
              instruction_info.breaks_pc_handling = true;
              continue;
            }

            ctx.registers_found.set(register_index);
            if (!instruction_info.breaks_pc_handling)
              instruction_info.breaks_pc_handling =
                  operand.reg == ARM_REG_SP && operand.access == CS_AC_WRITE;
          }
          else if (operand.type == ARM_OP_MEM)
          {
            utils_assert(operand.mem.index != ARM_REG_PC,
                         "The PC register can't be the index operand");
            if (operand.mem.base != ARM_REG_PC)
              continue;
            instruction_info.thumb_ldr_like = ctx.thumb;

            if (instr.id == ARM_INS_LDR && instr.size == 2)
              instruction_info.small_pc_relative_ldr = true;
            else
              set_base_memory_operand_encoding(operand);
            instruction_info.must_be_patched = true;
          }
        }
      }

      void set_base_memory_operand_encoding(const cs_arm_op& operand)
      {
        switch (operand.mem.format)
        {
        case ARM_MEM_U_REG_REG: [[fallthrough]];
        case ARM_MEM_IMM_REG: [[fallthrough]];
        case ARM_MEM_U_REG_IMM: [[fallthrough]];
        case ARM_MEM_U_REG_IMM2: [[fallthrough]];
        case ARM_MEM_U_REG_SHIFT_REG: [[fallthrough]];
        case ARM_MEM_IREG_BREG:
          instruction_info.register_encoding
              .indexes[instruction_info.register_encoding
                           .operand_pieces_count] = operand.encoding.indexes[1];
          instruction_info.register_encoding
              .sizes[instruction_info.register_encoding
                         .operand_pieces_count++] = operand.encoding.sizes[1];
          break;
        case ARM_MEM_REG_ALIGN_REG: [[fallthrough]];
        case ARM_MEM_REG_IMM: [[fallthrough]];
        case ARM_MEM_REG_U_IMM: [[fallthrough]];
        case ARM_MEM_REG_SHIFT_REG: [[fallthrough]];
        case ARM_MEM_REG_REG: [[fallthrough]];
        case ARM_MEM_REG:
          instruction_info.register_encoding
              .indexes[instruction_info.register_encoding
                           .operand_pieces_count] = operand.encoding.indexes[0];
          instruction_info.register_encoding
              .sizes[instruction_info.register_encoding
                         .operand_pieces_count++] = operand.encoding.sizes[0];
          break;
        }
      }
    };

    typename trampoline_context::session
        trampoline_context::create_session(disassembler&  arm,
                                           const cs_insn& instr)
    {
      return { arm, *this, instr };
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
      ptrampoline =
          trampoline_ptr(trampoline_buffer::allocate(__origin(target)));
    if (ptarget)
      reset();
    trampoline_context ctx{ target, ptrampoline.get() };
    disassembler       arm{ ctx.target.begin, ctx.thumb };
    std::shared_lock   lock{ hook_lock };

#ifndef NDEBUG
    // pre-fill the buffer with breakpoints for debugging purposes
    if (ctx.thumb)
      std::fill(reinterpret_cast<thumb::BKPT*>(ctx.trampoline.begin),
                reinterpret_cast<thumb::BKPT*>(ctx.trampoline.buffer_end),
                thumb::BKPT());
    else
      std::fill(reinterpret_cast<arm::BKPT*>(ctx.trampoline.begin),
                reinterpret_cast<arm::BKPT*>(ctx.trampoline.buffer_end),
                arm::BKPT());
#endif

    for (const cs_insn& instr : arm.disasm(memory_slot_size))
    {
      auto session = ctx.create_session(arm, instr);

      // when pc handling is activated we got to make sure we account for
      // instructions that interfere with the stack (such as push/pop) as they
      // can break the strategy. what we do in such cases is disable pc handling
      // and re-enable it if ever needed in the future
      if (session.instruction_info.breaks_pc_handling && ctx.pc_handling)
      {
        session.break_pc_handling();
        session.add_instruction(instr);

        // is it `pop { regs..., pc }` or similar? then exit
        if (session.instruction_info.is_branch && ctx.branch_list.empty())
        {
          ctx.finished = true;
          break;
        }
      }
      // handles all kinds of branch instructions. (including calls and those
      // who just modify the PC)
      else if (session.instruction_info.is_branch)
      {
        const uint8_t pc_offset = ctx.thumb ? 4 : 8;

        if (session.instruction_info.branch_destination)
        {
          typedef utils::type_sequence<
              arm::BL, arm::BLX, thumb2::BL, thumb2::BLX, arm::B, thumb2::B,
              thumb2::B_cond, arm::custom::BX_RELATIVE>::
              template apply<trampoline_context::session::template reference>::
                  template push_front<std::monostate>::template to<std::variant>
                      branch_ref_t;
          const bool  in_overriden_area = ctx.is_in_overriden_area(
              session.instruction_info.ubranch_destination);
          const intptr_t relative_address =
              session.instruction_info.ubranch_destination -
              arm_pc_align(
                  (in_overriden_area ? instr.address : ctx.trampoline.uend) +
                  pc_offset);
          branch_ref_t branch_ref{};

          if (ctx.thumb)
          {
            if (session.instruction_info.is_conditional &&
                !ctx.it_context.remaining)
            {
              assert(!session.instruction_info.is_call);
              if (thumb2::B_cond::offset_fits(relative_address))
                branch_ref = session.add_instruction(
                    thumb2::B_cond(relative_address, instr.detail->arm.cc));
            }
            else if (ctx.thumb != session.instruction_info.switches_to_thumb)
            {
              if (session.instruction_info.is_call &&
                  thumb2::BLX::offset_fits(relative_address))
                branch_ref =
                    session.add_instruction(thumb2::BLX(relative_address));
            }
            else if (thumb2::B::offset_fits(relative_address))
            {
              if (session.instruction_info.is_call)
                branch_ref =
                    session.add_instruction(thumb2::BL(relative_address));
              else
                branch_ref =
                    session.add_instruction(thumb2::B(relative_address));
            }
          }
          else
          {
            if (ctx.thumb != session.instruction_info.switches_to_thumb)
            {
              if (session.instruction_info.is_call &&
                  !session.instruction_info.is_conditional &&
                  arm::BLX::offset_fits(relative_address))
                branch_ref =
                    session.add_instruction(arm::BLX(relative_address));
              else if (!ctx.thumb &&
                       abs(relative_address) <=
                           std::numeric_limits<int16_t>::max() &&
                       arm::custom::BX_RELATIVE::offset_fits(relative_address))
                branch_ref = session.add_instruction(arm::custom::BX_RELATIVE(
                    relative_address, instr.detail->arm.cc));
            }
            else if (arm::B::offset_fits(relative_address))
            {
              if (session.instruction_info.is_call)
                branch_ref = session.add_instruction(arm::BL(relative_address));
              else
                branch_ref = session.add_instruction(arm::B(relative_address));
            }
          }

          if (in_overriden_area)
          {
            const uint8_t branch_dest_id =
                session.instruction_info.ubranch_destination -
                ctx.target.ubegin;
#ifndef __INTELLISENSE__
            std::visit(
                utils::overloaded{
                    [](std::monostate&)
                    {
                      assert(!"expected instruction variant to be "
                              "non-empty");
                    },
                    [=](auto& ref)
                    { ref.register_as_branch(branch_dest_id); } },
                branch_ref);
#endif
          }
          else
          {
            if (!session.instruction_info.is_call)
              session.break_pc_handling();

            if (std::holds_alternative<std::monostate>(branch_ref))
            {
              const uint8_t thumb_bit =
                  session.instruction_info.switches_to_thumb;
              const uintptr_t dataloc = ctx.allocate_address(
                  session.instruction_info.ubranch_destination | thumb_bit);
              const uint8_t ldr_relative_address =
                  dataloc - arm_pc_align(ctx.trampoline.uend + pc_offset);
              if (session.instruction_info.is_call)
              {
                if (ctx.thumb)
                  session.add_instruction(thumb2::custom::CALL(
                      ldr_relative_address, ctx.trampoline.uend % 4));
                else
                  session.add_instruction(arm::custom::CALL(
                      ldr_relative_address, instr.detail->arm.cc));
              }
              else
              {
                if (ctx.thumb)
                {
                  if (session.instruction_info.is_conditional &&
                      !ctx.it_context.remaining)
                    session.add_instruction(thumb::IT(instr.detail->arm.cc));
                  session.add_instruction(
                      thumb2::custom::JMP(ldr_relative_address));
                }
                else
                  session.add_instruction(arm::custom::JMP(
                      ldr_relative_address, instr.detail->arm.cc));
              }
            }

            if (!session.instruction_info.is_call && ctx.branch_list.empty() &&
                !session.instruction_info.is_conditional)
            {
              ctx.finished = true;
              break;
            }
          }
        }
        else if (!session.instruction_info.is_call)
        {
          if (session.instruction_info.must_be_patched)
          {
            auto *src     = reinterpret_cast<const std::byte*>(instr.bytes),
                 *address = reinterpret_cast<const std::byte*>(instr.address);
            throw(exceptions::pc_relative_handling_fail(
                ctx.target.begin, address,
                utils::to_array<24>(src, src + instr.size), ctx.thumb));
          }

          session.break_pc_handling();
          if (ctx.branch_list.empty() &&
              !session.instruction_info.is_conditional)
          {
            ctx.finished = true;
            break;
          }
        }
      }
      // collects some info about an IT block when an IT instruction is
      // encountered
      else if (instr.id == ARM_INS_IT)
      {
        ctx.it_context = {
          static_cast<uint8_t>(
              reinterpret_cast<thumb::IT*>(instr.address)->count() + 1),
          reinterpret_cast<std::byte*>(instr.address),
          reinterpret_cast<thumb::IT*>(ctx.trampoline.end)
        };
      }
      // if a push with reglist operand is encountered we cache for later use if
      // needed
      else if (instr.id == ARM_INS_PUSH &&
               session.instruction_info.has_reglist &&
               !ctx.it_context.remaining)
      {
        if (ctx.thumb)
        {
          if (instr.size == 4)
            ctx.original_push =
                reinterpret_cast<thumb2::PUSH_REGLIST*>(ctx.trampoline.end);
          else
            ctx.original_push =
                reinterpret_cast<thumb::PUSH_REGLIST*>(ctx.trampoline.end);
        }
        else
          ctx.original_push =
              reinterpret_cast<arm::PUSH_REGLIST*>(ctx.trampoline.end);
      }
      // other kind of pc-relative instructions that need to be modified in
      // order to function properly
      else if (session.instruction_info.must_be_patched)
      {
        const uint8_t   pc_offset = ctx.thumb ? 4 : 8;
        const uintptr_t pc_val =
            instr.id == ARM_INS_ADR || session.instruction_info.thumb_ldr_like
                ? arm_pc_align(instr.address + pc_offset)
                : instr.address + pc_offset;

        if (!ctx.pc_handling)
        {
          if (!ctx.pc_handling_begin.has_value())
            ctx.pc_handling_begin =
                static_cast<uint8_t>(ctx.trampoline.end - ctx.trampoline.begin);

          if (ctx.thumb)
            session.add_instruction(thumb::PUSH(r7))
                .template register_as_to_be_modified<pc_handling_push>(
                    ctx.original_push);
          else
            session.add_instruction(arm::PUSH(r7))
                .template register_as_to_be_modified<pc_handling_push>(
                    ctx.original_push);

          if (!ctx.custom_pc)
            ctx.ucustom_pc = ctx.allocate_address(pc_val);

          if (ctx.thumb)
            session
                .add_instruction(thumb::LDR_LITERAL(
                    r7, ctx.ucustom_pc -
                            arm_pc_align(ctx.trampoline.uend +
                                         sizeof(thumb::PUSH) + pc_offset)))
                .register_as_to_be_modified();
          else
            session
                .add_instruction(arm::LDR_LITERAL(
                    r7, ctx.ucustom_pc - (ctx.trampoline.uend +
                                          sizeof(arm::PUSH) + pc_offset)))
                .register_as_to_be_modified();

          if (!ctx.pc_val)
            ctx.pc_val = pc_val;
          else
          {
            const uint8_t offset  = pc_val - ctx.pc_val;
            ctx.pc_val           += offset;
            if (ctx.thumb)
              session.add_instruction(thumb2::ADD(r7, r7, offset))
                  .register_as_to_be_modified();
            else
              session.add_instruction(arm::ADD(r7, r7, offset))
                  .register_as_to_be_modified();
          }

          ctx.original_push = std::nullopt;
          ctx.pc_handling   = true;
        }
        else
        {
          const uint8_t offset = pc_val - ctx.pc_val;
          if (offset)
          {
            ctx.pc_val += offset;
            if (ctx.thumb)
              session.add_instruction(thumb2::ADD(r7, r7, offset))
                  .register_as_to_be_modified();
            else
              session.add_instruction(arm::ADD(r7, r7, offset))
                  .register_as_to_be_modified();
          }
        }

        // the PC is not encoded on thumb adr but it's instead implied to save
        // space. therefore it has got to be replaced by a full add to function
        // properly
        if (session.instruction_info.is_thumb_adr)
        {
          const auto imm = get_immediate(instr);
          const auto reg = get_register_as_index(instr);
          assert(imm.has_value() && reg.has_value());
          session.add_instruction(patched_adr(reg.value(), r7, imm.value()))
              .register_as_to_be_modified();
        }
        // same reason as the adr above. the pc here is implied not encoded
        else if (session.instruction_info.small_pc_relative_ldr)
        {
          const auto mem = get_memory_operand(instr);
          const auto reg = get_register_as_index(instr);
          assert(mem.has_value() && reg.has_value());
          session
              .add_instruction(
                  patched_small_ldr(reg.value(), r7, mem.value().disp))
              .register_as_to_be_modified();
        }
        else
          session.add_instruction(instr)
              .template register_as_to_be_modified<any_instruction>(
                  session.instruction_info.register_encoding,
                  instruction_set_from(ctx.thumb, instr.size));
      }

      if (((instr.address - ctx.target.ubegin) + instr.size) >= ctx.size_needed)
      {
        if (ctx.it_context.remaining > 1)
        {
          memcpy(ctx.trampoline.end, session.copy_source, session.copy_size);
          auto* const it_block =
              reinterpret_cast<const std::byte*>(ctx.it_context.pinstr);
          const size_t it_block_size =
              (ctx.trampoline.end + session.copy_size) - it_block;
          throw(exceptions::incomplete_it_block(
              ctx.target.begin,
              utils::to_array<32>(it_block, it_block + it_block_size),
              it_block_size, ctx.it_context.original_address,
              ctx.it_context.remaining));
        }

        // force setting it to 0 because we don't want to do any handling for
        // the custom instructions that are going to be inserted
        ctx.it_context.remaining = 0;
        ctx.finished             = true;

        if (!session.holds_instructions())
          session.add_instruction(instr);
        session.break_pc_handling();

        const uint8_t   pc_offset    = ctx.thumb ? 4 : 8;
        const uintptr_t current_last = ctx.trampoline.uend + session.copy_size;
        const uintptr_t final_dest   = ctx.target.uend;
        const ptrdiff_t relative_address =
            final_dest - arm_pc_align(current_last + pc_offset);

        if (ctx.thumb)
        {
          typedef typename thumb::B::offset_t thumb_offset_t;
          if (abs(relative_address) <=
                  (std::numeric_limits<thumb_offset_t>::max)() &&
              thumb::B::offset_fits(relative_address))
          {
            session.add_instruction(thumb::B(relative_address));
            break;
          }
          else if (thumb2::B::offset_fits(relative_address))
          {
            session.add_instruction(thumb2::B(relative_address));
            break;
          }
        }
        else if (arm::B::offset_fits(relative_address))
        {
          session.add_instruction(arm::B(relative_address));
          break;
        }

        const uintptr_t dataloc =
            ctx.allocate_address(final_dest | static_cast<uint8_t>(ctx.thumb));
        const uintptr_t ldr_relative_address =
            dataloc - arm_pc_align(current_last + pc_offset);

        if (ctx.thumb)
          session.add_instruction(thumb2::custom::JMP(ldr_relative_address));
        else
          session.add_instruction(arm::custom::JMP(ldr_relative_address));
        break;
      }
    }

    if (!ctx.finished)
      throw(exceptions::bad_target(target));

    if (ctx.tbm_list)
    {
      std::array regs = { r0, r1, r2, r3, r4, r5, r6, r7 };
      const auto search_result =
          std::find_if_not(regs.begin(), regs.end(),
                           [=](reg_t reg) { return ctx.registers_found[reg]; });
      if (search_result == regs.end())
        throw(exceptions::unused_register_not_found(target));
      for (to_be_modified& tbm : ctx.tbm_list)
        tbm.modify(*search_result);
    }

    ctx.branch_list.fix_leftover_branches(target);
    const uint8_t target_size = ctx.target.end - ctx.target.begin;

    if (target_size < ctx.size_needed &&
        !ctx.rest_is_pad(ctx.size_needed - target_size))
    {
      const uint8_t pc_offset = reinterpret_cast<uintptr_t>(target) & 1 ? 4 : 8;
      auto*         relay_address = utils::align_up(ctx.trampoline.end, 4u);

      if (const intptr_t relative_address =
              relay_address - arm_pc_align(ctx.target.begin + pc_offset);
          target_size >= sizeof(arm::B) &&
          arm::B::offset_fits(relative_address))
      {
        ctx.must_fit(sizeof(arm::custom::FULL_JMP) +
                     (relay_address - ctx.trampoline.end));

        if (ctx.thumb)
          new (relay_address) thumb2::custom::FULL_JMP(0);
        else
          new (relay_address) arm::custom::FULL_JMP(0);

        prelay = relay_address;
      }
      else if (target_size >= sizeof(arm::LDR_LITERAL) &&
               ctx.rest_is_pad(sizeof(arm::LDR_LITERAL)) &&
               ctx.is_pad(ctx.target.begin - sizeof(uint32_t),
                          sizeof(uint32_t)))
        patch_above = true;
      else
        throw(exceptions::insufficient_function_size(target, target_size,
                                                     ctx.size_needed));
    }

    ptarget          = target;
    positions        = ctx.positions;
    instruction_sets = ctx.instruction_sets;
    pc_handling      = ctx.pc_handling_begin;
    old_protect      = tmp_protinfo;
    tramp_size       = ctx.trampoline.end - ctx.trampoline.begin;
  }

  trampoline::trampoline(const trampoline& other)
      : ptarget(other.ptarget),
        ptrampoline(other.ptarget
                        ? trampoline_buffer::allocate(__origin(other.ptarget))
                        : nullptr),
        instruction_sets(other.instruction_sets),
        patch_above(other.patch_above), tramp_size(other.tramp_size),
        pc_handling(other.pc_handling), old_protect(other.old_protect),
        positions(other.positions)
  {
    memcpy(ptrampoline.get(), other.ptrampoline.get(), memory_slot_size);

    if (other.prelay)
    {
      prelay = ptrampoline.get() + utils::align_up(tramp_size, 4u);
      memcpy(prelay, other.prelay, sizeof(arm::custom::FULL_JMP));
    }
  }

  trampoline::trampoline(trampoline&& other) noexcept
      : ptarget(std::exchange(other.ptarget, nullptr)),
        ptrampoline(std::move(other.ptrampoline)),
        prelay(std::exchange(other.prelay, nullptr)),
        instruction_sets(other.instruction_sets),
        patch_above(std::exchange(other.patch_above, false)),
        tramp_size(std::exchange(other.tramp_size, 0)),
        pc_handling(std::exchange(other.pc_handling, std::nullopt)),
        old_protect(other.old_protect), positions(std::move(other.positions))
  {
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
      ptrampoline =
          trampoline_ptr(trampoline_buffer::allocate(__origin(other.ptarget)));
    ptarget          = other.ptarget;
    instruction_sets = other.instruction_sets;
    patch_above      = other.patch_above;
    tramp_size       = other.tramp_size;
    pc_handling      = other.pc_handling;
    positions        = other.positions;
    old_protect      = other.old_protect;
    memcpy(ptrampoline.get(), other.ptrampoline.get(), memory_slot_size);

    if (other.prelay)
    {
      prelay = ptrampoline.get() + utils::align_up(tramp_size, 4u);
      memcpy(prelay, other.prelay, sizeof(arm::custom::FULL_JMP));
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

    ptarget          = std::exchange(other.ptarget, nullptr);
    ptrampoline      = std::move(other.ptrampoline);
    prelay           = std::exchange(other.prelay, nullptr);
    instruction_sets = other.instruction_sets;
    patch_above      = std::exchange(other.patch_above, false);
    tramp_size       = std::exchange(other.tramp_size, 0);
    pc_handling      = std::exchange(other.pc_handling, std::nullopt);
    positions        = other.positions;
    old_protect      = other.old_protect;
    other.positions.clear();
    return *this;
  }

  std::string trampoline::str() const
  {
    utils_assert(ptarget, "Attempt to disassemble an uninitialized trampoline");
    std::stringstream stream;
    const bool        uses_thumb = instruction_sets[0];
    size_t            i          = 0;
    disassembler      arm{ ptrampoline.get(), uses_thumb, false };

    for (const cs_insn& instr : arm.disasm(tramp_size))
    {
      if (instr.address != reinterpret_cast<uintptr_t>(ptrampoline.get()))
        stream << '\n';
      stream << "0x" << std::hex << std::setfill('0') << std::setw(8)
             << instr.address << ": " << instr.mnemonic << '\t' << instr.op_str;

      if ((i + 1) != positions.size())
      {
        auto [oldpos, newpos] = positions[i + 1];
        if (newpos ==
            ((instr.address - reinterpret_cast<uintptr_t>(ptrampoline.get())) +
             instr.size))
        {
          if (instruction_sets[i + 1] != instruction_sets[i])
            arm.switch_instruction_set();
          ++i;
        }
      }
    }
    return stream.str();
  }

  void trampoline::reset()
  {
    if (!ptarget)
      return;
    ptarget     = nullptr;
    prelay      = nullptr;
    patch_above = false;
    tramp_size  = 0;
    pc_handling = std::nullopt;
    old_protect = {};
    positions.clear();
    instruction_sets.reset();
  }
} // namespace alterhook

#if !utils_msvc
  #pragma GCC diagnostic pop
#endif