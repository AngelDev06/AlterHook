/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#include <pch.h>
#include "exceptions.h"
#include "disassembler.h"
#include "arm_instructions.h"
#include "buffer.h"
#include "linux_thread_handler.h"
#define __alterhook_expose_impl
#include "trampoline.h"

namespace alterhook
{
  extern std::shared_mutex hook_lock;

  void trampoline::deleter::operator()(std::byte* ptrampoline) const noexcept
  {
    trampoline_buffer::deallocate(ptrampoline);
  }

  int get_protection(const std::byte* address);

  inline namespace init_impl
  {
    template <typename T>
    constexpr bool is_push_ptr_v =
        std::is_same_v<T, arm::PUSH*> || std::is_same_v<T, thumb::PUSH*>;
    template <typename T>
    constexpr bool is_thumb2_add_or_ldr_ptr_v =
        std::is_same_v<T, thumb2::ADD*> || std::is_same_v<T, thumb2::LDR_IMM*>;

    enum instruction_set
    {
      IS_ARM,
      IS_THUMB,
      IS_UNKNOWN
    };

    enum tbm_flags
    {
      M_BRANCH, // whether the instruction causes a branch i.e. modifies the PC
                // register
      M_LINK, // whether the instruction performs a call i.e. modifies the PC &
              // LR register
      M_TBM,  // whether the instruction needs to be modified to function i.e.
              // reads from PC
      M_REGLIST, // whether the instructions has a reglist
      M_PUSH,    // whether the current instruction is the push that starts pc
                 // handling
      M_LDR, // whether the current instruction is the ldr that loads a given
             // register with the value of PC
      M_POP, // whether the current instruction is the pop that finishes the PC
             // handling setup
      M_ADD, // whether the current instruction is the add instruction that
             // increments the value of the register representing the PC
      M_ADR, // whether the current instruction is an adr instruction
      M_SMALL_LDR,    // whether the current instruction is the small thumb ldr
                      // literal (this one doesn't encode the PC so it's an
                      // exception)
      M_ORIGINAL_PUSH // whether the current instruction is a push with reglist
                      // operand that was already part of the target
    };

#define __alterhook_reg_bitnum(reg)                                            \
  ((reg) == ARM_REG_R13  ? 13                                                  \
   : (reg) >= ARM_REG_R0 ? (reg)-ARM_REG_R0                                    \
                         : (reg) + 1)

    static std::optional<uint8_t> general_reg_to_n(arm_reg reg) noexcept
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
      default: return {};
      }
    }

    // determines whether the code in the range of [src, src + size) is padding
    // bytes. (size may have to be aligned up to the instruction set's
    // alignment)
    static bool is_pad(const std::byte* src, size_t size, bool thumb) noexcept
    {
      if (thumb)
      {
        constexpr uint16_t tnop  = 0xBF'00;
        constexpr uint32_t t2nop = 0xAF'F3'00'80;
        if (size % 2)
          ++size;
        if (*reinterpret_cast<const uint16_t*>(src) == tnop ||
            !(*reinterpret_cast<const uint16_t*>(src)))
        {
          size /= 2;
          for (size_t i = 1; i < size; ++i)
          {
            if (reinterpret_cast<const uint16_t*>(src)[i] !=
                *reinterpret_cast<const uint16_t*>(src))
              return false;
          }
          return true;
        }
        if (size % 4)
          size += 2;
        if (*reinterpret_cast<const uint32_t*>(src) == t2nop)
        {
          size /= 4;
          for (size_t i = 1; i < size; ++i)
          {
            if (reinterpret_cast<const uint32_t*>(src)[i] != t2nop)
              return false;
          }
          return true;
        }
        return false;
      }
      constexpr uint32_t nop = 0xE3'20'F0'00;
      if (size % 4)
        size = utils_align(size + 3, 4);
      if (*reinterpret_cast<const uint32_t*>(src) == nop)
      {
        size /= 4;
        for (size_t i = 1; i < size; ++i)
        {
          if (reinterpret_cast<const uint32_t*>(src)[i] != nop)
            return false;
        }
        return true;
      }
      return false;
    }

    static int64_t find_imm(const cs_insn& instr) noexcept
    {
      cs_arm_op* operands = instr.detail->arm.operands;

      for (uint8_t i = 0, count = instr.detail->arm.op_count; i != count; ++i)
      {
        if (operands[i].type == ARM_OP_IMM)
          return operands[i].imm;
      }
      return INT64_MAX;
    }

    struct ALTERHOOK_HIDDEN to_be_modified
    {
      typedef std::variant<std::byte*, thumb::POP*, thumb::LDR_LITERAL*,
                           thumb::PUSH*, thumb::ADD*, thumb2::ADD*,
                           thumb2::INCREMENTAL_ADD*, thumb2::LDR_IMM*,
                           arm::POP*, arm::LDR_LITERAL*, arm::ADD*, arm::PUSH*>
                                                  instr_t;
      typedef std::variant<arm::PUSH_REGLIST*, thumb2::PUSH_REGLIST*,
                           thumb::PUSH_REGLIST*>* orig_push_t;

      instr_t             instr;
      size_t              size;
      bool                thumb;
      cs_operand_encoding encoding;
      orig_push_t         orig_push;

      // patches instruction with given register at encoding.indexes[0] and
      // encoding.indexes[1] if needed
      void patch_reg(reg_t reg, uint32_t* instr_ptr)
      {
        utils_assert(encoding.operand_pieces_count <= 2,
                     "(unreachable) register encoding with more than 2 pieces");
        utils_assert(encoding.operand_pieces_count,
                     "(unreachable) empty register encoding");
        utils_assert(
            (encoding.operand_pieces_count == 1 && encoding.sizes[0] == 4) ||
                (encoding.operand_pieces_count == 2 &&
                 (encoding.sizes[0] + encoding.sizes[1]) == 4),
            "(unreachable) register field has more or less than 4 bits");

        // note that for thumb2 if index is smaller than 6 we add 16
        // otherwise we subtract 16 the reason is that thumb2 instructions
        // are not of type uint32_t by instead are of type struct {
        // uint16_t first, second; }
        const uint8_t    index0    = thumb && size == 4
                                         ? encoding.indexes[0] < 16
                                               ? encoding.indexes[0] + 16
                                               : encoding.indexes[0] - 16
                                         : encoding.indexes[0];
        const std::array bitseq    = { 0b1, 0b11, 0b111, 0b1111 };
        const uint32_t   reg_part1 = reg >> (4 - encoding.sizes[0]);

        *instr_ptr &= ~(bitseq[encoding.sizes[0] - 1] << index0);
        *instr_ptr |= reg_part1 << index0;

        if (encoding.operand_pieces_count == 2)
        {
          const uint8_t  index1    = thumb && size == 4
                                         ? encoding.indexes[1] < 16
                                               ? encoding.indexes[1] + 16
                                               : encoding.indexes[1] - 16
                                         : encoding.indexes[1];
          const uint32_t reg_part2 = reg & bitseq[encoding.sizes[1] - 1];

          *instr_ptr &= ~(bitseq[encoding.sizes[1] - 1] << index1);
          *instr_ptr |= reg_part2 << index1;
        }
      }

      void modify(reg_t reg)
      {
        std::visit(
            utils::overloaded{
                [&](std::byte* instr_ptr)
                { patch_reg(reg, reinterpret_cast<uint32_t*>(instr_ptr)); },
                [&](auto instr_ptr)
                    -> std::enable_if_t<is_push_ptr_v<decltype(instr_ptr)>>
                {
                  if (orig_push)
                  {
                    std::visit(
                        [&](auto push)
                        {
                          if (!push->greatest(reg))
                          {
                            instr_ptr->set_register(reg);
                            return;
                          }

                          push->append(reg);
                          if (thumb)
                            new (reinterpret_cast<void*>(instr_ptr)) thumb::NOP;
                          else
                            new (reinterpret_cast<void*>(instr_ptr)) arm::NOP;
                        },
                        *orig_push);
                  }
                  else
                    instr_ptr->set_register(reg);
                },
                [&](auto instr_ptr)
                    -> std::enable_if_t<
                        is_thumb2_add_or_ldr_ptr_v<decltype(instr_ptr)>>
                { instr_ptr->set_operand_register(reg); },
                [&](auto instr_ptr)
                    -> std::enable_if_t<
                        !is_thumb2_add_or_ldr_ptr_v<decltype(instr_ptr)> &&
                        !is_push_ptr_v<decltype(instr_ptr)>>
                { instr_ptr->set_register(reg); } },
            instr);
      }
    };

    struct ALTERHOOK_HIDDEN trampoline_instruction_entry
    {
      disassembler&       arm;
      const cs_insn&      instr;
      instruction_set     next_instr_set;
      uint64_t            branch_dest = 0;
      std::bitset<16>     flags{};
      std::bitset<16>&    encountered_reglist;
      cs_operand_encoding encoding{};

      void check_branch_instructions()
      {
        if (arm.has_group(instr, ARM_GRP_CALL) ||
            arm.has_group(instr, ARM_GRP_JUMP))
        {
          flags.set(M_BRANCH);
          if (arm.has_group(instr, ARM_GRP_CALL))
            flags.set(M_LINK);
          if (arm.has_group(instr, ARM_GRP_BRANCH_RELATIVE))
          {
            if (instr.id == ARM_INS_BX || instr.id == ARM_INS_BLX)
              next_instr_set = static_cast<instruction_set>(!next_instr_set);
            branch_dest = find_imm(instr);
          }
        }
      }

      /*
       * According to the armv7 documentation the only thumb/thumb2 instructions
       * that are allowed to modify the pc (causing a branch) are the following:
       * > ADD Rdn, Rm -> only encoding T2
       * > MOV Rd, Rm -> only encoding T1
       * > All simple branch instructions (obviously): B, BL, CBNZ, CBZ, CHKA,
       * HB, HBL, HBLP, HBP, TBB, TBH > All interworking branch instructions
       * (those change instruction set as well): BLX, BX, BXJ > LDR -> any
       * encoding (Rt has to be PC), causes interworking branch > POP {
       * registers..., PC } -> causes interworking branch > LDM Rn, {
       * registers..., PC } -> causes interworking branch source:
       * https://shorturl.at/gloG5
       */
      void thumb_calculate_branch_dest()
      {
        if (arm.modifies_reg(instr, ARM_REG_PC))
        {
          flags.set(M_BRANCH);
          if (arm.modifies_reg(instr, ARM_REG_LR))
            flags.set(M_LINK);
        }
        else
          check_branch_instructions();
      }

      /*
       * According to the armv7 documentation the only arm instructions that are
       * allowed to modify the PC (causing a branch) are all of the ones
       * mentioned for thumb except for ADD, MOV (thumb specific) and also the
       * following: > ADC -> any encoding > ADD -> any encoding > ADR -> any
       * encoding > AND -> any encoding > ASR -> immediate only > BIC -> any
       * encoding > EOR -> any encoding > LSL -> immediate only > MOV and MVN ->
       * any encoding > ORR -> any encoding > ROR -> immediate only > RRX -> any
       * encoding > RSB -> any encoding > RSC -> any encoding > SBC -> any
       * encoding > SUB -> any encoding Note: all the instructions mentioned
       * above need to have the PC as the Rd (destination operand) and in that
       * case the type of branch caused is interworking (so if the least
       * significant bit is set it switches or remains in thumb state etc.)
       * source: https://shorturl.at/gloG5
       */
      void arm_calculate_branch_dest()
      {
        if (arm.modifies_reg(instr, ARM_REG_PC))
        {
          flags.set(M_BRANCH);
          if (!arm.reads_reg(instr, ARM_REG_PC))
            return;
          typedef std::bitset<64> opcode_t;
          opcode_t                opcode = instr.detail->opcode_encoding.bits;

          // check if it belongs to Data-Processing immediate category
          // since it modifies the PC it can't belong to the other 3
          // with same bit pattern
          // source: https://shorturl.at/gluM6
          if ((opcode & opcode_t(0b111)) == 0b100)
          {
            uint64_t imm  = find_imm(instr);
            // when loading the PC on arm instruction set it always points 8
            // bytes after the current instruction. Also no alignment is needed
            // since the PC is always aligned to 4 bytes
            uint64_t addr = instr.address + 8;

            switch (instr.id)
            {
            case ARM_INS_MOV: branch_dest = imm; break;
            case ARM_INS_ADC: [[fallthrough]];
            case ARM_INS_ADD: branch_dest = addr + imm; break;
            case ARM_INS_AND: branch_dest = addr & imm; break;
            case ARM_INS_BIC: branch_dest = addr & ~imm; break;
            case ARM_INS_EOR: branch_dest = addr ^ imm; break;
            case ARM_INS_MVN: branch_dest = ~imm; break;
            case ARM_INS_ORR: branch_dest = addr | imm; break;
            case ARM_INS_RSB: [[fallthrough]];
            case ARM_INS_RSC: branch_dest = imm - addr; break;
            case ARM_INS_SBC: [[fallthrough]];
            case ARM_INS_SUB: branch_dest = addr - imm; break;
            default:
              utils_assert(false, "(unreachable) arm_calculate_branch_dest: "
                                  "unhandled data processing instruction");
            }
          }
          // a few exceptions that should have been part of the above category
          // but instead belong to its register version (even though they
          // clearly have an immediate operand)
          else if ((opcode & opcode_t(0b1111111)) == 0b1011000 &&
                   instr.id != ARM_INS_MOV)
          {
            uint64_t imm  = find_imm(instr);
            uint64_t addr = instr.address + 8;

            switch (instr.id)
            {
            case ARM_INS_LSL:
              branch_dest = addr << imm;
              break;
              // the address is always positive so it doesn't matter whether an
              // arithmetic or logical shift occurs
            case ARM_INS_ASR:
            case ARM_INS_LSR: branch_dest = addr >> imm; break;
            case ARM_INS_ROR: branch_dest = utils_ror(addr, imm); break;
            case ARM_INS_RRX: branch_dest = utils_ror(addr, 1); break;
            default:
              utils_assert(false, "(unreachable) arm_calculate_branch_dest: "
                                  "unhandled data processing instruction");
            }
          }
          else if (arm.modifies_reg(instr, ARM_REG_LR))
            flags.set(M_LINK);

          if (branch_dest & 1)
          {
            branch_dest    &= ~1;
            next_instr_set  = IS_THUMB;
          }
        }
        else
          check_branch_instructions();
      }

#if utils_clang
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wswitch"
#endif

      void add_mem_pc_encoding(cs_arm_op& operand)
      {
        switch (operand.mem.format)
        {
        case ARM_MEM_U_REG_REG: [[fallthrough]];
        case ARM_MEM_IMM_REG: [[fallthrough]];
        case ARM_MEM_U_REG_IMM: [[fallthrough]];
        case ARM_MEM_U_REG_IMM2: [[fallthrough]];
        case ARM_MEM_U_REG_SHIFT_REG: [[fallthrough]];
        case ARM_MEM_IREG_BREG:
          encoding.indexes[encoding.operand_pieces_count] =
              operand.encoding.indexes[1];
          encoding.sizes[encoding.operand_pieces_count++] =
              operand.encoding.sizes[1];
          break;
        case ARM_MEM_REG_ALIGN_REG: [[fallthrough]];
        case ARM_MEM_REG_IMM: [[fallthrough]];
        case ARM_MEM_REG_U_IMM: [[fallthrough]];
        case ARM_MEM_REG_SHIFT_REG: [[fallthrough]];
        case ARM_MEM_REG_REG: [[fallthrough]];
        case ARM_MEM_REG:
          encoding.indexes[encoding.operand_pieces_count] =
              operand.encoding.indexes[0];
          encoding.sizes[encoding.operand_pieces_count++] =
              operand.encoding.sizes[0];
          break;
        }
      }

#if utils_clang
  #pragma clang diagnostic pop
#endif

      void handle_pc_rel_instructions()
      {
        for (size_t begin = 0, end = instr.detail->arm.op_count; begin != end;
             ++begin)
        {
          cs_arm_op&       operand   = instr.detail->arm.operands[begin];
          constexpr size_t uint8_max = std::numeric_limits<uint8_t>::max();

          if (uint8_t reg_bit_num;
              operand.type == ARM_OP_REG &&
              (reg_bit_num = general_reg_to_n(static_cast<arm_reg>(operand.reg))
                                 .value_or(uint8_max)) != uint8_max)
          {
            if (operand.reg == ARM_REG_PC && operand.access == CS_AC_READ &&
                !flags[M_BRANCH])
            {
              // no support for reglist instructions that include the PC in the
              // reglist and read from it that is, push and stm
              if (operand.encoding.operand_pieces_count == 1 &&
                  operand.encoding.sizes[0] == 1)
                throw(exceptions::unsupported_instruction_handling(
                    reinterpret_cast<const std::byte*>(instr.bytes),
                    next_instr_set,
                    reinterpret_cast<std::byte*>(instr.address)));
              encoding = operand.encoding;
              flags.set(M_TBM);
            }
            else
            {
              if (operand.encoding.operand_pieces_count == 1 &&
                  operand.encoding.sizes[0] == 1)
                flags.set(M_REGLIST);
              else
                encountered_reglist.set(reg_bit_num);
            }
          }
          else if (operand.type == ARM_OP_MEM)
          {
            utils_assert(operand.mem.index != ARM_REG_PC,
                         "(unreachable) PC is index operand");
            if (operand.mem.base == ARM_REG_PC)
            {
              if (instr.id == ARM_INS_LDR && instr.size == 2)
                flags.set(M_SMALL_LDR);
              else
                add_mem_pc_encoding(operand);
              flags.set(M_TBM);
            }
          }
        }
      }

      trampoline_instruction_entry(disassembler& arm, const cs_insn& instr,
                                   std::bitset<16>& encountered_reglist,
                                   bool             thumb)
          : arm(arm), instr(instr),
            next_instr_set(static_cast<instruction_set>(thumb)),
            encountered_reglist(encountered_reglist)
      {
        if (thumb)
          thumb_calculate_branch_dest();
        else
          arm_calculate_branch_dest();
        handle_pc_rel_instructions();
      }
    };
  } // namespace init_impl

  void trampoline::init(std::byte* target)
  {
    if (ptarget == target)
      return;
    int tmp_protect = get_protection(target);
    if (!(tmp_protect & PROT_EXEC))
      throw(exceptions::invalid_address(target));
    if (!ptrampoline)
      ptrampoline = trampoline_ptr(trampoline_buffer::allocate());
    if (ptarget)
      reset();

    std::byte* const tmp_target = target;

#if !defined(NDEBUG) && utils_arm
    memset(ptrampoline.get(), 0, memory_slot_size);
#endif

    typedef std::variant<arm::PUSH_REGLIST*, thumb2::PUSH_REGLIST*,
                         thumb::PUSH_REGLIST*>
                                                     orig_push_t;
    typedef utils::static_vector<to_be_modified, 16> tbm_list_t;
    typedef utils::static_vector<std::pair<uintptr_t, bool>, 3>
        branch_addresses_t;

    bool            uses_thumb = reinterpret_cast<uintptr_t>(target) & 1;
    bool            should_setup_pc_handling = true;
    bool            finished                 = false;
    bool            push_found               = false;
    const uintptr_t tramp_begin =
        reinterpret_cast<uintptr_t>(ptrampoline.get());
    const uintptr_t tramp_end = tramp_begin + memory_slot_size;
    uintptr_t       pc_val    = 0;
    uintptr_t       pc_loc    = 0;
    const size_t    size_needed =
        uses_thumb && (reinterpret_cast<uintptr_t>(target) % 4)
               ? sizeof(arm::custom::FULL_JMP) + 2
               : sizeof(arm::custom::FULL_JMP);
    reinterpret_cast<uintptr_t&>(target) &= ~1;

    std::bitset<8>                tmp_instruction_sets{};
    std::bitset<16>               encountered_reglist{};
    std::bitset<memory_slot_size> used_locations{};
    size_t                        last_unused_pos = 0;
    uint8_t                       available_size  = memory_slot_size;
    pc_handling_t                 tmp_pc_handling{};
    positions_t                   tmp_positions{};
    orig_push_t                   orig_push{};
    std::array<std::byte, 16>     tmpbuff{};
    uint8_t                       tmpbuffpos          = 0;
    uint64_t                      addr                = 0;
    uint8_t                       tramp_pos           = 0;
    uint8_t                       it_remaining        = 0;
    uint64_t                      it_original_address = 0;
    thumb::IT*                    it_block            = nullptr;
    to_be_modified                tbm{};
    tbm_list_t                    tbm_list{};
    branch_addresses_t            branch_addresses{};
    disassembler                  arm{ target, uses_thumb };
    std::shared_lock              lock{ hook_lock };

    for (const cs_insn& instr : arm.disasm(memory_slot_size))
    {
      arm.set_reg_accesses(instr);
      size_t           copy_size = instr.size;
      const std::byte* copy_source =
          reinterpret_cast<const std::byte*>(instr.bytes);
      const uintptr_t tramp_addr =
          reinterpret_cast<uintptr_t>(ptrampoline.get()) + tramp_pos;
      tbm.instr                              = ptrampoline.get() + tramp_pos;
      tbm.thumb                              = uses_thumb;
      tbm.size                               = instr.size;
      addr                                   = instr.address + instr.size;
      tmpbuffpos                             = 0;
      std::byte*&                  tbm_instr = std::get<std::byte*>(tbm.instr);
      trampoline_instruction_entry entry{ arm, instr, encountered_reglist,
                                          uses_thumb };

      // a utility that generates a brand new IT block that can hold the
      // remaining instructions and also removes them from the previous one.
      // this is useful when we place a few unconditional instructions in the
      // middle such as those who are part of the PC handling setup.
      const auto update_it_block = [&]
      {
        const uint8_t old_it_inst_count = it_block->instruction_count();
        const uint8_t old_it_cond_pos   = old_it_inst_count - it_remaining + 1;

        if (it_block->get_condition(old_it_cond_pos) == thumb::IT::E)
        {
          thumb::IT it{ ARMCC_getOppositeCondition(it_block->get_condition()) };

          for (uint8_t i = old_it_cond_pos + 1, j = 2; i <= old_it_inst_count;
               ++i, ++j)
            it.set_condition(j, static_cast<thumb::IT::it_cond>(
                                    !it_block->get_condition(i)));

          new (&tmpbuff[tmpbuffpos]) auto(it);
        }
        else
        {
          thumb::IT it{ it_block->get_condition() };

          for (uint8_t i = old_it_cond_pos + 1, j = 2; i <= old_it_inst_count;
               ++i, ++j)
            it.set_condition(j, it_block->get_condition(i));

          new (&tmpbuff[tmpbuffpos]) auto(it);
        }
        it_block->pop(it_remaining);
        it_block    = reinterpret_cast<thumb::IT*>(tramp_addr + tmpbuffpos);
        tmpbuffpos += sizeof(thumb::IT);
        copy_size  += sizeof(thumb::IT);
        tbm_instr  += sizeof(thumb::IT);
      };
      // writes an instruction to the temporary buffer and updates tbm status
      const auto write_and_advance = [&](auto instr)
      {
        new (&tmpbuff[tmpbuffpos]) auto(instr);
        tmpbuffpos += sizeof(instr);
        copy_size  += sizeof(instr);
        tbm.size    = sizeof(instr);
        tbm.instr =
            reinterpret_cast<std::add_pointer_t<decltype(instr)>>(tbm_instr);
        tbm_list.push_back(tbm);
        tbm.instr = tbm_instr + sizeof(instr);
      };
      // allocates 4 bytes starting from the end of the trampoline to be used
      // for storing constant data
      const auto find_loc = [&]
      {
        const uintptr_t available_space  = tramp_begin + available_size;
        uintptr_t       dataloc          = 0;
        used_locations                  |= 0b1111 << last_unused_pos;
        dataloc                          = tramp_end - (last_unused_pos += 4);
        available_size                  -= available_space - dataloc;
        return dataloc;
      };
      // checks if it's a thumb instruction that uses the PC as a base register
      // (most likely ldr)
      const auto thumb_ldr_literal_like = [&]
      {
        const cs_arm&    detail   = instr.detail->arm;
        const cs_arm_op *op_begin = detail.operands,
                        *op_end   = detail.operands + detail.op_count;
        const auto result =
            std::find_if(op_begin, op_end,
                         [](const cs_arm_op& operand) {
                           return operand.type == ARM_OP_MEM &&
                                  operand.mem.base == ARM_REG_PC;
                         });
        return result != op_end;
      };

      // handles the situation where an instruction that has a reglist operand
      // is spotted and PC handling setup is currently active. we got to disable
      // PC handling setup for safety reasons. The same applies to single
      // register push/pop instructions as they interfere with the stack
      if ((entry.flags[M_REGLIST] || instr.id == ARM_INS_PUSH ||
           instr.id == ARM_INS_POP) &&
          !should_setup_pc_handling)
      {
        if (uses_thumb)
        {
          if (it_remaining)
          {
            if (entry.flags[M_BRANCH] && it_remaining > 1)
            {
              memcpy(reinterpret_cast<void*>(tramp_addr), copy_source,
                     copy_size);
              throw(exceptions::invalid_it_block(
                  reinterpret_cast<std::byte*>(it_block), it_original_address,
                  (tramp_addr + copy_size) -
                      reinterpret_cast<uintptr_t>(it_block),
                  it_remaining, target));
            }

            if (it_remaining == it_block->instruction_count())
            {
              new (tmpbuff.data()) auto(*it_block);
              tmpbuffpos += sizeof(*it_block);
              copy_size  += sizeof(*it_block);

              new (it_block) thumb::POP(r7);
              tbm_instr = reinterpret_cast<std::byte*>(it_block);
              tbm.size  = sizeof(thumb::POP);
              tbm.instr = reinterpret_cast<thumb::POP*>(tbm_instr);
              tbm_list.push_back(tbm);
              tbm_instr =
                  reinterpret_cast<std::byte*>(tramp_addr + sizeof(*it_block));
              it_block = reinterpret_cast<thumb::IT*>(tramp_addr);
            }
            else
            {
              write_and_advance(thumb::POP(r7));
              update_it_block();
            }
          }
          else
            write_and_advance(thumb::POP(r7));
        }
        else
          write_and_advance(arm::POP(r7));

        memcpy(&tmpbuff[tmpbuffpos], instr.bytes, instr.size);

        copy_source              = tmpbuff.data();
        should_setup_pc_handling = true;

        if (entry.flags[M_BRANCH])
          finished = true;
      }
      // handles all kinds of branch instructions. (including calls and those
      // who just modify the PC)
      else if (entry.flags[M_BRANCH])
      {
        if (it_remaining > 1)
        {
          memcpy(reinterpret_cast<void*>(tramp_addr), copy_source, copy_size);
          throw(exceptions::invalid_it_block(
              reinterpret_cast<std::byte*>(it_block), it_original_address,
              (tramp_addr + copy_size) - reinterpret_cast<uintptr_t>(it_block),
              it_remaining, target));
        }

        if (entry.flags[M_LINK])
        {
          if (entry.branch_dest)
          {
            if (reinterpret_cast<uintptr_t>(target) <= entry.branch_dest &&
                entry.branch_dest <
                    (reinterpret_cast<uintptr_t>(target) + size_needed))
            {
              if (entry.branch_dest > instr.address)
                branch_addresses.emplace_back(entry.branch_dest,
                                              entry.next_instr_set);
            }
            else
            {
              const uintptr_t dataloc = find_loc();
              *reinterpret_cast<uint32_t*>(dataloc) =
                  entry.branch_dest | entry.next_instr_set;

              if (uses_thumb)
              {
                copy_size = sizeof(thumb2::custom::CALL);

                if (it_remaining)
                {
                  switch (it_block->instruction_count())
                  {
                  case 1:
                    it_block->set_second_condition(thumb::IT::T);
                    goto PLACE_CALL;
                  case 2:
                    it_block->set_third_condition(
                        it_block->get_second_condition());
                    goto PLACE_CALL;
                  case 3:
                    it_block->set_fourth_condition(
                        it_block->get_third_condition());
                    goto PLACE_CALL;
                  case 4:
                    const ARMCC_CondCodes condition =
                        it_block->get_fourth_condition() == thumb::IT::T
                            ? it_block->get_condition()
                            : ARMCC_getOppositeCondition(
                                  it_block->get_condition());
                    new (tmpbuff.data()) thumb::IT(condition, thumb::IT::T);
                    tmpbuffpos  += sizeof(thumb::IT);
                    copy_size   += sizeof(thumb::IT);
                    copy_source  = tmpbuff.data();
                    tbm_instr   += sizeof(thumb::IT);
                    thumb2::custom::CALL tcall{};
                    tcall.set_offset(
                        dataloc -
                        utils_align(reinterpret_cast<uintptr_t>(tbm_instr) + 4,
                                    4));
                    if (reinterpret_cast<uintptr_t>(tbm_instr) % 4)
                      tcall.align();
                    new (&tmpbuff[tmpbuffpos]) auto(tcall);
                    it_block->pop_instruction();
                    break;
                  }
                }
                else
                {
                PLACE_CALL:
                  thumb2::custom::CALL tcall{};
                  tcall.set_offset(dataloc - utils_align(tramp_addr + 4, 4));
                  if (tramp_addr % 4)
                    tcall.align();
                  new (tmpbuff.data()) auto(tcall);
                  copy_source = tmpbuff.data();
                }
              }
              else
              {
                arm::custom::CALL_ABS call{};
                if (instr.detail->arm.cc != ARMCC_AL &&
                    instr.detail->arm.cc != ARMCC_UNDEF)
                  call.set_condition(instr.detail->arm.cc);
                call.set_offset(dataloc - (tramp_addr + 8));
                new (tmpbuff.data()) auto(call);
                copy_source = tmpbuff.data();
                copy_size   = sizeof(call);
              }
            }
          }
        }
        else
        {
          if (entry.branch_dest)
          {
            if (reinterpret_cast<uintptr_t>(target) <= entry.branch_dest &&
                entry.branch_dest <
                    (reinterpret_cast<uintptr_t>(target) + size_needed))
            {
              if (entry.branch_dest > instr.address)
                branch_addresses.emplace_back(entry.branch_dest,
                                              entry.next_instr_set);
            }
            else
            {
              finished =
                  (instr.detail->arm.cc == ARMCC_AL ||
                   instr.detail->arm.cc == ARMCC_UNDEF) &&
                  std::find_if(branch_addresses.begin(), branch_addresses.end(),
                               [&](std::pair<uintptr_t, bool>& element) {
                                 return instr.address < element.first;
                               }) == branch_addresses.end();

              const uintptr_t dataloc = find_loc();
              *reinterpret_cast<uint32_t*>(dataloc) =
                  entry.branch_dest | entry.next_instr_set;
              copy_size   = sizeof(arm::custom::JMP);
              copy_source = tmpbuff.data();

              if (uses_thumb)
              {
                if (finished && !should_setup_pc_handling)
                  write_and_advance(thumb::POP(r7));
                if (instr.detail->arm.cc != ARMCC_AL &&
                    instr.detail->arm.cc != ARMCC_UNDEF)
                {
                  new (&tmpbuff[tmpbuffpos]) thumb::IT(instr.detail->arm.cc);
                  tmpbuffpos += sizeof(thumb::IT);
                  copy_size  += sizeof(thumb::IT);
                  tbm_instr  += sizeof(thumb::IT);
                }
                thumb2::custom::JMP tjmp{};
                tjmp.set_offset(
                    dataloc -
                    utils_align(reinterpret_cast<uintptr_t>(tbm_instr) + 4, 4));
                new (&tmpbuff[tmpbuffpos]) auto(tjmp);
              }
              else
              {
                arm::custom::JMP jmp{};
                if (instr.detail->arm.cc != ARMCC_AL &&
                    instr.detail->arm.cc != ARMCC_UNDEF)
                  jmp.set_condition(instr.detail->arm.cc);
                if (finished && !should_setup_pc_handling)
                  write_and_advance(arm::POP(r7));
                jmp.set_offset(dataloc -
                               reinterpret_cast<uintptr_t>(tbm_instr + 8));
                new (&tmpbuff[tmpbuffpos]) auto(jmp);
              }
            }
          }
          else
          {
            if (entry.flags[M_TBM])
              throw(exceptions::pc_relative_handling_fail(
                  reinterpret_cast<std::byte*>(instr.address), target,
                  uses_thumb));
            if (!should_setup_pc_handling)
            {
              if (uses_thumb)
                write_and_advance(thumb::POP(r7));
              else
                write_and_advance(arm::POP(r7));
            }

            finished =
                (instr.detail->arm.cc == ARMCC_AL ||
                 instr.detail->arm.cc == ARMCC_UNDEF) &&
                std::find_if(branch_addresses.begin(), branch_addresses.end(),
                             [&](std::pair<uintptr_t, bool>& element) {
                               return instr.address < element.first;
                             }) == branch_addresses.end();
          }
        }
      }
      // collects some info about an IT block when an IT instruction is
      // encountered
      else if (instr.id == ARM_INS_IT)
      {
        if (it_remaining)
        {
          memcpy(reinterpret_cast<void*>(tramp_addr), instr.bytes, instr.size);
          throw(exceptions::invalid_it_block(
              reinterpret_cast<std::byte*>(it_block), it_original_address,
              (tramp_addr + copy_size) - reinterpret_cast<uintptr_t>(it_block),
              it_remaining, target));
        }
        it_original_address = instr.address;
        it_block            = reinterpret_cast<thumb::IT*>(tramp_addr);
        it_remaining =
            reinterpret_cast<thumb::IT*>(instr.address)->instruction_count() +
            1;
      }
      // if a push with reglist operand is encountered we cache for later use if
      // needed
      else if (instr.id == ARM_INS_PUSH && entry.flags[M_REGLIST] &&
               !it_remaining)
      {
        if (uses_thumb)
        {
          if (instr.size == 4)
            orig_push = reinterpret_cast<thumb2::PUSH_REGLIST*>(tramp_addr);
          else
            orig_push = reinterpret_cast<thumb::PUSH_REGLIST*>(tramp_addr);
        }
        else
          orig_push = reinterpret_cast<arm::PUSH_REGLIST*>(tramp_addr);
        push_found = true;
      }
      else if (entry.flags[M_TBM] || (instr.id == ARM_INS_ADR && uses_thumb))
      {
        copy_source = tmpbuff.data();

        if (should_setup_pc_handling)
        {
          if (!tmp_pc_handling.first)
            tmp_pc_handling = { true, tramp_pos };
          if (push_found)
          {
            tbm.orig_push = &orig_push;
            push_found    = false;
          }

          if (uses_thumb)
          {
            const auto prepare_pc_emulation = [&]
            {
              if (!pc_loc)
                pc_loc = find_loc();
              write_and_advance(thumb::LDR_LITERAL(
                  r7,
                  (pc_loc -
                   utils_align(reinterpret_cast<uintptr_t>(tbm_instr + 4), 4)) /
                      4));
              const uintptr_t new_pc_val =
                  instr.id == ARM_INS_ADR || thumb_ldr_literal_like()
                      ? utils_align(instr.address + 4, 4)
                      : instr.address + 4;
              uint32_t& old_pc_val = *reinterpret_cast<uint32_t*>(pc_loc);

              if (!pc_val)
                old_pc_val = pc_val = new_pc_val;
              else
              {
                const uint8_t offset = new_pc_val - old_pc_val;
                pc_val               = old_pc_val + offset;
                write_and_advance(thumb2::INCREMENTAL_ADD(r7, offset));
              }
            };

            if (it_remaining)
            {
              if (it_remaining == it_block->instruction_count())
              {
                prepare_pc_emulation();
                new (&tmpbuff[tmpbuffpos]) auto(*it_block);
                tmpbuffpos                     += sizeof(*it_block);
                copy_size                      += sizeof(*it_block);
                tbm_instr                      += sizeof(*it_block);
                std::byte* const current_instr  = tbm_instr;
                new (it_block) thumb::PUSH(r7);
                tbm.instr = reinterpret_cast<thumb::PUSH*>(it_block);
                tbm.size  = sizeof(thumb::PUSH);
                tbm_list.push_back(tbm);
                tbm.instr = current_instr;
                it_block =
                    reinterpret_cast<thumb::IT*>(tbm_instr - sizeof(*it_block));
              }
              else
              {
                write_and_advance(thumb::PUSH(r7));
                prepare_pc_emulation();
                update_it_block();
              }
            }
            else
            {
              write_and_advance(thumb::PUSH(r7));
              prepare_pc_emulation();
            }
          }
          else
          {
            if (!pc_loc)
              pc_loc = find_loc();
            write_and_advance(arm::PUSH(r7));
            write_and_advance(arm::LDR_LITERAL(
                r7, pc_loc - reinterpret_cast<uintptr_t>(tbm_instr + 8)));
            uint32_t& old_pc_val = *reinterpret_cast<uint32_t*>(pc_loc);

            if (!pc_val)
              old_pc_val = pc_val = instr.address + 8;
            else
            {
              const uint16_t offset = (instr.address + 8) - old_pc_val;
              pc_val                = old_pc_val + offset;
              write_and_advance(arm::ADD(r7, r7, offset));
            }
          }

          tbm.orig_push            = nullptr;
          should_setup_pc_handling = false;
        }
        else
        {
          if (uses_thumb)
          {
            const auto update_custom_pc = [&]
            {
              uintptr_t offset =
                  instr.id == ARM_INS_ADR || thumb_ldr_literal_like()
                      ? utils_align(instr.address + 4, 4)
                      : instr.address + 4;
              offset -= pc_val;

              if (offset)
              {
                pc_val += offset;
                write_and_advance(thumb2::INCREMENTAL_ADD(r7, offset));
                return true;
              }
              return false;
            };

            if (it_remaining)
            {
              if (it_remaining == it_block->instruction_count())
              {
                constexpr size_t instr_pc_pos = 4;
                uintptr_t        instr_pc_loc =
                    instr.id == ARM_INS_ADR
                               ? utils_align(instr.address + instr_pc_pos, 4)
                               : instr.address + instr_pc_pos;
                uint16_t offset = instr_pc_loc - pc_val;

                if (offset)
                {
                  thumb2::INCREMENTAL_ADD add{ r7, offset };
                  new (tmpbuff.data()) auto(add.operands);
                  new (tmpbuff.data() + sizeof(add.operands)) auto(*it_block);
                  tmpbuffpos += sizeof(add.operands) + sizeof(thumb::IT);
                  copy_size  += sizeof(add.operands) + sizeof(thumb::IT);
                  pc_val     += offset;
                  new (it_block) auto(add.opcode);
                  tbm.instr =
                      reinterpret_cast<thumb2::INCREMENTAL_ADD*>(it_block);
                  tbm.size = sizeof(thumb2::INCREMENTAL_ADD);
                  tbm_list.push_back(tbm);
                  tbm.instr = reinterpret_cast<std::byte*>(
                      tramp_addr + sizeof(add.operands) + sizeof(thumb::IT));
                  it_block = reinterpret_cast<thumb::IT*>(tramp_addr +
                                                          sizeof(add.operands));
                }
              }
              else if (update_custom_pc())
                update_it_block();
            }
            else
              update_custom_pc();
          }
          else
          {
            const uint16_t offset  = (instr.address + 8) - pc_val;
            pc_val                += offset;
            write_and_advance(arm::ADD(r7, r7, offset));
          }
        }

        // thumb adr is an exception
        if (instr.id == ARM_INS_ADR && uses_thumb)
        {
          copy_size -= instr.size;
          reg_t reg  = static_cast<reg_t>(
              __alterhook_reg_bitnum(instr.detail->regs_write[0]));
          uint64_t imm = instr.detail->arm.operands[1].imm;
          write_and_advance(thumb2::ADD(reg, r7, imm));
        }
        else if (entry.flags[M_SMALL_LDR])
        {
          copy_size -= instr.size;
          reg_t reg  = static_cast<reg_t>(
              __alterhook_reg_bitnum(instr.detail->regs_write[0]));
          uint32_t imm = instr.detail->arm.operands[1].mem.disp;
          write_and_advance(
              thumb2::LDR_IMM(reg, r7, static_cast<uint16_t>(imm)));
        }
        else
        {
          tbm.size     = instr.size;
          tbm.encoding = entry.encoding;
          memcpy(&tmpbuff[tmpbuffpos], instr.bytes, instr.size);
          tbm_list.push_back(tbm);
        }
      }

      if (std::find_if(branch_addresses.begin(), branch_addresses.end(),
                       [&](const std::pair<uintptr_t, bool>& element) {
                         return element.first > instr.address;
                       }) != branch_addresses.end() &&
          copy_size != instr.size)
        throw(exceptions::instructions_in_branch_handling_fail(target));

      if ((tramp_pos + copy_size) > available_size)
        throw(exceptions::trampoline_max_size_exceeded(
            target, tramp_pos + copy_size, available_size));

      if (it_remaining)
        --it_remaining;

      tmp_instruction_sets.set(tmp_positions.size(), uses_thumb);
      auto iter =
          std::find_if(branch_addresses.begin(), branch_addresses.end(),
                       [&](std::pair<uintptr_t, bool>& element) {
                         return element.first == (instr.address + instr.size);
                       });
      if (iter != branch_addresses.end())
      {
        // can't branch inside an IT block
        if (it_remaining)
        {
          memcpy(reinterpret_cast<void*>(tramp_addr), instr.bytes, instr.size);
          throw(exceptions::invalid_it_block(
              reinterpret_cast<std::byte*>(it_block), it_original_address,
              (tramp_addr + copy_size) - reinterpret_cast<uintptr_t>(it_block),
              it_remaining, target));
        }
        if (uses_thumb != iter->second)
          arm.switch_instruction_set();
        uses_thumb = iter->second;
        branch_addresses.erase(iter);
      }

      tmp_positions.push_back(
          { instr.address - reinterpret_cast<uintptr_t>(target), tramp_pos });
      memcpy(reinterpret_cast<void*>(tramp_addr), copy_source, copy_size);
      tramp_pos += copy_size;

      if (finished)
        break;
      if (((instr.address - reinterpret_cast<uintptr_t>(target)) +
           instr.size) >= size_needed)
      {
        if (it_remaining)
          throw(exceptions::incomplete_it_block(
              reinterpret_cast<std::byte*>(it_block), it_original_address,
              (tramp_addr + copy_size) - reinterpret_cast<uintptr_t>(it_block),
              it_remaining, target));
        tbm.instr       = reinterpret_cast<std::byte*>(tramp_addr + copy_size);
        void* copy_dest = reinterpret_cast<void*>(tramp_begin + tramp_pos);
        copy_size       = 0;
        tmpbuffpos      = 0;
        copy_source     = tmpbuff.data();

        if (!should_setup_pc_handling)
        {
          if (uses_thumb)
          {
            write_and_advance(thumb::POP(r7));

            if (reinterpret_cast<uintptr_t>(tbm_instr) % 4)
            {
              const uintptr_t dataloc = find_loc();
              *reinterpret_cast<uint32_t*>(dataloc) =
                  (instr.address + instr.size) | 1;
              thumb2::custom::JMP tjmp{};
              tjmp.set_offset(
                  dataloc -
                  utils_align(reinterpret_cast<uintptr_t>(tbm_instr + 4), 4));
              new (&tmpbuff[tmpbuffpos]) auto(tjmp);
              copy_size += sizeof(tjmp);
            }
            else
            {
              new (&tmpbuff[tmpbuffpos])
                  thumb2::custom::FULL_JMP((instr.address + instr.size) | 1);
              copy_size += sizeof(thumb2::custom::FULL_JMP);
            }
          }
          else
          {
            write_and_advance(arm::POP(r7));
            new (&tmpbuff[tmpbuffpos])
                arm::custom::FULL_JMP(instr.address + instr.size);
            copy_size += sizeof(arm::custom::FULL_JMP);
          }
        }
        else if (uses_thumb)
        {
          if (reinterpret_cast<uintptr_t>(tbm_instr) % 4)
          {
            const uintptr_t dataloc = find_loc();
            *reinterpret_cast<uint32_t*>(dataloc) =
                (instr.address + instr.size) | 1;
            thumb2::custom::JMP tjmp{};
            tjmp.set_offset(
                dataloc -
                utils_align(reinterpret_cast<uintptr_t>(tbm_instr + 4), 4));
            new (&tmpbuff[tmpbuffpos]) auto(tjmp);
            copy_size += sizeof(tjmp);
          }
          else
          {
            new (&tmpbuff[tmpbuffpos])
                thumb2::custom::FULL_JMP((instr.address + instr.size) | 1);
            copy_size += sizeof(thumb2::custom::FULL_JMP);
          }
        }
        else
        {
          new (&tmpbuff[tmpbuffpos])
              arm::custom::FULL_JMP(instr.address + instr.size);
          copy_size += sizeof(arm::custom::FULL_JMP);
        }

        if ((tramp_pos + copy_size) > available_size)
          throw(exceptions::trampoline_max_size_exceeded(
              target, tramp_pos + copy_size, available_size));

        memcpy(copy_dest, copy_source, copy_size);
        tmp_instruction_sets.set(tmp_positions.size(), uses_thumb);
        tmp_positions.push_back(
            { (instr.address - reinterpret_cast<uintptr_t>(target)) +
                  instr.size,
              tramp_pos });
        tramp_pos += copy_size;
        break;
      }
    }

    if (tbm_list)
    {
      std::array regs = { r0, r1, r2, r3, r4, r5, r6, r7 };
      const auto search_result =
          std::find_if_not(regs.begin(), regs.end(),
                           [=](reg_t reg) { return encountered_reglist[reg]; });
      if (search_result == regs.end())
        throw(exceptions::unused_register_not_found(target));
      for (to_be_modified& tbm : tbm_list)
        tbm.modify(*search_result);
    }

    const size_t origpos = addr - reinterpret_cast<uintptr_t>(target);
    if (origpos < size_needed &&
        !is_pad(target + origpos, size_needed - origpos, uses_thumb))
    {
      if ((origpos < sizeof(arm::LDR_LITERAL) &&
           !is_pad(target + origpos, sizeof(arm::LDR_LITERAL) - origpos,
                   uses_thumb)) ||
          !is_pad(target - sizeof(uint32_t), sizeof(uint32_t), uses_thumb))
        throw(exceptions::insufficient_function_size(target, origpos,
                                                     size_needed));

      patch_above = true;
    }

    ptarget          = tmp_target;
    positions        = tmp_positions;
    instruction_sets = tmp_instruction_sets;
    pc_handling      = tmp_pc_handling;
    old_protect      = tmp_protect;
    tramp_size       = tramp_pos;
  }

  trampoline::trampoline(const trampoline& other)
      : ptarget(other.ptarget),
        ptrampoline(other.ptarget ? trampoline_buffer::allocate() : nullptr),
        instruction_sets(other.instruction_sets),
        patch_above(other.patch_above), tramp_size(other.tramp_size),
        pc_handling(other.pc_handling), old_protect(other.old_protect),
        positions(other.positions)
  {
    memcpy(ptrampoline.get(), other.ptrampoline.get(), memory_slot_size);
  }

  trampoline::trampoline(trampoline&& other) noexcept
      : ptarget(std::exchange(other.ptarget, nullptr)),
        ptrampoline(std::move(other.ptrampoline)),
        instruction_sets(other.instruction_sets),
        patch_above(std::exchange(other.patch_above, false)),
        tramp_size(std::exchange(other.tramp_size, 0)),
        pc_handling(
            std::exchange(other.pc_handling, std::pair(false, uint8_t{}))),
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
      ptrampoline = trampoline_ptr(trampoline_buffer::allocate());
    ptarget          = other.ptarget;
    instruction_sets = other.instruction_sets;
    patch_above      = other.patch_above;
    tramp_size       = other.tramp_size;
    pc_handling      = other.pc_handling;
    positions        = other.positions;
    old_protect      = other.old_protect;
    memcpy(ptrampoline.get(), other.ptrampoline.get(), memory_slot_size);

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
    instruction_sets = other.instruction_sets;
    patch_above      = std::exchange(other.patch_above, false);
    tramp_size       = std::exchange(other.tramp_size, 0);
    pc_handling = std::exchange(other.pc_handling, std::pair(false, uint8_t{}));
    positions   = other.positions;
    old_protect = other.old_protect;
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
    patch_above = false;
    tramp_size  = 0;
    pc_handling = { false, 0 };
    old_protect = PROT_NONE;
    positions.clear();
    instruction_sets.reset();
  }
} // namespace alterhook
