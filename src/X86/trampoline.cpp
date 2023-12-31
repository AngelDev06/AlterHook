/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#include <pch.h>
#include "exceptions.h"
#include "disassembler.h"
#include "buffer.h"
#include "tools.h"
#include "trampoline.h"
#include "x86_instructions.h"

#if utils_64bit
  #define __alterhook_pass_alloc_arg(x) x
#else
  #define __alterhook_pass_alloc_arg(x)
#endif

#if utils_windows
  #define __alterhook_set_old_protect_or_validate_address(address)             \
    do                                                                         \
    {                                                                          \
      if (!is_executable_address(address))                                     \
        throw(exceptions::invalid_address(address));                           \
    } while (false)
  #define __alterhook_copy_old_protect(other) ((void)0)
#else
  #define __alterhook_set_old_protect_or_validate_address(address)             \
    int tmp_old_protect = PROT_NONE;                                           \
    do                                                                         \
    {                                                                          \
      if (!((tmp_old_protect = get_protection(address)) & PROT_EXEC))          \
        throw(exceptions::invalid_address(address));                           \
    } while (false)
  #define __alterhook_copy_old_protect(other) (old_protect = other.old_protect)
#endif

namespace alterhook
{
  void trampoline::deleter::operator()(std::byte* ptrampoline) const noexcept
  {
    trampoline_buffer::deallocate(ptrampoline);
  }

#if !utils_windows
  int ALTERHOOK_HIDDEN get_protection(const std::byte* address);
#endif

  extern std::shared_mutex hook_lock;

  static bool is_pad(const std::byte* target, size_t size) noexcept
  {
    if (target[0] != std::byte() && target[0] != std::byte(0x90) &&
        target[0] != std::byte(0xCC))
      return false;

    for (size_t i = 1; i < size; ++i)
    {
      if (target[i] != target[0])
        return false;
    }
    return true;
  }

#if !utils_windows && utils_x86
  static uint8_t x86_reg_bit_num(x86_reg reg)
  {
    switch (reg)
    {
    case X86_REG_EAX: return 0;
    case X86_REG_ECX: return 1;
    case X86_REG_EDX: return 2;
    case X86_REG_EBX: return 3;
    case X86_REG_ESP: return 4;
    case X86_REG_EBP: return 5;
    case X86_REG_ESI: return 6;
    case X86_REG_EDI: return 7;
    default: return 0xFF;
    }
  }
#endif

#if utils_msvc
  #pragma warning(push)
  #pragma warning(disable : 4244 4018 4267)
#else
  #pragma GCC diagnostic push
  #pragma GCC diagnostic ignored "-Wsign-compare"
  #pragma GCC diagnostic ignored "-Wstrict-overflow"
#endif

  void trampoline::init(std::byte* target)
  {
    if (ptarget == target)
      return;
    __alterhook_set_old_protect_or_validate_address(target);
    if (!ptrampoline)
      ptrampoline = trampoline_ptr(
          trampoline_buffer::allocate(__alterhook_pass_alloc_arg(target)));
    if (ptarget)
      reset();

    std::array<std::byte, 16> tmpbuff{};
    positions_t               tmp_positions{};
    size_t                    tramp_pos   = 0;
    bool                      finished    = false;
    uintptr_t                 branch_dest = 0;
    uint64_t                  addr        = 0;
    disassembler              x86{ target };

    for (const cs_insn& instr : x86.disasm(memory_slot_size))
    {
      size_t  copy_size = instr.size;
      auto    copy_src  = reinterpret_cast<const std::byte*>(instr.bytes);
      cs_x86& detail    = instr.detail->x86;
      const uintptr_t tramp_addr =
          reinterpret_cast<uintptr_t>(ptrampoline.get()) + tramp_pos;
      const cs_x86_op *operands_begin = detail.operands,
                      *operands_end   = detail.operands + detail.op_count;
      const size_t   instr_size       = instr.size;
      const uint64_t instr_address    = instr.address;
      addr                            = instr.address + instr.size;

#if utils_x64
      auto has_rip = std::find_if(operands_begin, operands_end,
                                  [](const cs_x86_op& element) {
                                    return element.type == X86_OP_MEM &&
                                           element.mem.base == X86_REG_RIP;
                                  });
      if (has_rip != operands_end)
      {
        memcpy(tmpbuff.data(), copy_src, copy_size);
        uint32_t* const dispaddr = reinterpret_cast<uint32_t*>(
            tmpbuff.data() + detail.encoding.disp_offset);
        *dispaddr = static_cast<uint32_t>(
            (instr.address + instr.size + has_rip->mem.disp) -
            (tramp_addr + instr.size));
        copy_src = tmpbuff.data();
        finished = instr.id == X86_INS_JMP;
      }
      // clang-format off
      else
#endif
      if (memchr(instr.detail->groups, X86_GRP_BRANCH_RELATIVE,
                 instr.detail->groups_count))
      {
        // clang-format on
        auto imm_op = std::find_if(operands_begin, operands_end,
                                   [](const cs_x86_op& element)
                                   { return element.type == X86_OP_IMM; });
        utils_assert(imm_op != operands_end,
                     "(unreachable) The immediate operand of a relative "
                     "branch instruction wasn't found");

        // clang-format on
        if (memchr(instr.detail->groups, X86_GRP_JUMP,
                   instr.detail->groups_count))
        {
          if (reinterpret_cast<uintptr_t>(target) <= imm_op->imm &&
              imm_op->imm < (reinterpret_cast<uintptr_t>(target) + sizeof(JMP)))
          {
            if (imm_op->imm > instr.address)
              branch_dest = imm_op->imm;
          }
          else
          {
            if (instr.id == X86_INS_JMP)
            {
#if utils_x64
              new (tmpbuff.data()) JMP_ABS(static_cast<uint64_t>(imm_op->imm));
              copy_size = sizeof(JMP_ABS);
#else
              new (tmpbuff.data()) JMP(static_cast<uint32_t>(
                  imm_op->imm - (tramp_addr + sizeof(JMP))));
              copy_size = sizeof(JMP);
#endif
              finished = instr.address >= branch_dest;
            }
            else if ((X86_INS_LOOP <= instr.id && instr.id <= X86_INS_LOOPNE) ||
                     instr.id == X86_INS_JRCXZ || instr.id == X86_INS_JECXZ)
              throw(exceptions::unsupported_instruction_handling(copy_src,
                                                                 target));
            else
            {
              uint8_t condition =
                  (detail.opcode[0] != 0x0F ? detail.opcode[0]
                                            : detail.opcode[1]) &
                  0x0F;
#if utils_x64
              // for x64 the condition should be inverted so that the big jump
              // is executed on false
              new (tmpbuff.data())
                  JCC_ABS(static_cast<uint8_t>(0x71 ^ condition),
                          static_cast<uint64_t>(imm_op->imm));
              copy_size = sizeof(JCC_ABS);
#else
              // turn any short jcc to big one
              new (tmpbuff.data())
                  JCC(static_cast<uint8_t>(0x80 | condition),
                      static_cast<uint32_t>(imm_op->imm -
                                            (tramp_addr + sizeof(JCC))));
              copy_size = sizeof(JCC);
#endif
            }

            copy_src = tmpbuff.data();
          }
        }
        else
        {
          utils_assert(memchr(instr.detail->groups, X86_GRP_CALL,
                              instr.detail->groups_count),
                       "(unreachable) An instruction of branch relative group "
                       "is neither a call nor a jump");
          const int64_t dest = imm_op->imm;

#if !utils_windows && utils_x86
          auto itr = x86.follow_instruction(instr, memory_slot_size);
          if (itr && instr.id == X86_INS_MOV && detail.op_count == 2 &&
              detail.operands[0].type == X86_OP_REG &&
              detail.operands[1].type == X86_OP_MEM &&
              detail.operands[1].mem.base == X86_REG_ESP &&
              detail.operands[1].mem.disp == 0)
          {
            uint8_t register_used = x86_reg_bit_num(detail.operands[0].reg);
            ++itr;
            if (itr->id == X86_INS_RET)
            {
              new (tmpbuff.data())
                  MOV(register_used,
                      static_cast<uint32_t>(instr_address + instr_size));
              copy_size = sizeof(MOV);
              goto CALL_HANDLING_END;
            }
          }
#endif

#if utils_x64
          new (tmpbuff.data()) CALL_ABS(static_cast<uint64_t>(dest));
          copy_size = sizeof(CALL_ABS);
#else
          new (tmpbuff.data())
              CALL(static_cast<uint32_t>(dest - (tramp_addr + sizeof(CALL))));
          copy_size = sizeof(CALL);
#endif
#if !utils_windows && utils_x86
        CALL_HANDLING_END:
#endif
          copy_src = tmpbuff.data();
        }
      }
      else if (memchr(instr.detail->groups, X86_GRP_RET,
                      instr.detail->groups_count))
        finished = instr_address >= branch_dest;

      if (instr_address < branch_dest && copy_size != instr_size)
        throw(exceptions::instructions_in_branch_handling_fail(target));
      if ((tramp_pos + copy_size) > memory_slot_size)
        throw(exceptions::trampoline_max_size_exceeded(
            target, tramp_pos + copy_size, memory_slot_size));

      tmp_positions.push_back(
          { instr_address - reinterpret_cast<uintptr_t>(target), tramp_pos });
      memcpy(reinterpret_cast<void*>(tramp_addr), copy_src, copy_size);
      tramp_pos += copy_size;

      if (finished)
        break;
      if (((instr_address + instr_size) -
           reinterpret_cast<uintptr_t>(target)) >= sizeof(JMP))
      {
#if utils_x64
        new (tmpbuff.data()) JMP_ABS(instr_address + instr_size);
        copy_size = sizeof(JMP_ABS);
#else
        new (tmpbuff.data())
            JMP(static_cast<uint32_t>((instr_address + instr_size) -
                                      (tramp_addr + copy_size + sizeof(JMP))));
        copy_size = sizeof(JMP);
#endif
        if ((tramp_pos + copy_size) > memory_slot_size)
          throw(exceptions::trampoline_max_size_exceeded(
              target, tramp_pos + copy_size, memory_slot_size));

        memcpy(ptrampoline.get() + tramp_pos, tmpbuff.data(), copy_size);
        tramp_pos += copy_size;
        break;
      }
    }

    const size_t origpos = addr - reinterpret_cast<uintptr_t>(target);
    if (origpos < sizeof(JMP) &&
        !is_pad(reinterpret_cast<std::byte*>(addr), sizeof(JMP) - origpos))
    {
      if ((origpos < sizeof(JMP_SHORT) &&
           !is_pad(reinterpret_cast<std::byte*>(addr),
                   sizeof(JMP_SHORT) - origpos)) ||
          !is_executable_address(target - sizeof(JMP)) ||
          !is_pad(target - sizeof(JMP), sizeof(JMP)))
        throw(exceptions::insufficient_function_size(target, origpos,
                                                     sizeof(JMP)));

      patch_above = true;
    }

    ptarget    = target;
    tramp_size = tramp_pos;
    positions  = tmp_positions;
#if !utils_windows
    old_protect = tmp_old_protect;
#endif

#if utils_x64
    // if prelay is already set, we don't touch it
    if (prelay)
      return;
    prelay = ptrampoline.get() + tramp_pos;
    new (prelay) JMP_ABS();
#endif
  }

  std::string trampoline::str() const
  {
    utils_assert(ptarget,
                 "trampoline::str: can't disassemble uninitialized trampoline");
    std::stringstream stream;
    disassembler      x86{ ptrampoline.get(), false };
    stream << std::hex;

    for (const cs_insn& instr : x86.disasm(tramp_size))
    {
      if (instr.address != reinterpret_cast<uintptr_t>(ptrampoline.get()))
        stream << '\n';
      stream << "0x" << std::setfill('0') << std::setw(8) << instr.address
             << ": " << instr.mnemonic << '\t' << instr.op_str;
    }
    return stream.str();
  }

  static void trampcpy(std::byte* dest, const std::byte* src, size_t size)
  {
    utils_assert(dest != src, "trampcpy: dest and source can't be the same");
    utils_assert(size, "trampcpy: size can't be 0");

    std::array<std::byte, 16> tmpbuff{};
    size_t                    tramp_pos = 0;
    disassembler              x86{ src };

    for (const cs_insn& instr : x86.disasm(size))
    {
      const uintptr_t tramp_addr =
          reinterpret_cast<uintptr_t>(dest + tramp_pos);
      auto    copy_src = reinterpret_cast<const std::byte*>(instr.bytes);
      cs_x86& detail   = instr.detail->x86;
      const cs_x86_op *operands_begin = detail.operands,
                      *operands_end   = detail.operands + detail.op_count;

      // note that for x64 the only relative addresses used are the displacement
      // in RIP relative instructions. for branch instructions the addresses are
      // always absolute.
#if utils_x64
      auto rip_op = std::find_if(operands_begin, operands_end,
                                 [](const cs_x86_op& element) {
                                   return element.type == X86_OP_MEM &&
                                          element.mem.base == X86_REG_RIP;
                                 });
      if (rip_op != operands_end)
      {
        memcpy(tmpbuff.data(), copy_src, instr.size);
        uint32_t* const dispaddr = reinterpret_cast<uint32_t*>(
            tmpbuff.data() + detail.encoding.disp_offset);
        *dispaddr = static_cast<uint32_t>(
            (instr.address + instr.size + rip_op->mem.disp) -
            (tramp_addr + instr.size));
        copy_src = tmpbuff.data();
      }
#else
      if (memchr(instr.detail->groups, X86_GRP_BRANCH_RELATIVE,
                 instr.detail->groups_count))
      {
        auto imm_op = std::find_if(operands_begin, operands_end,
                                   [](const cs_x86_op& element)
                                   { return element.type == X86_OP_IMM; });
        utils_assert(imm_op != operands_end,
                     "(unreachable) The immediate operand of a relative branch "
                     "instruction wasn't found");
        if (!memchr(instr.detail->groups, X86_GRP_JUMP,
                    instr.detail->groups_count) ||
            reinterpret_cast<uintptr_t>(src) > imm_op->imm ||
            imm_op->imm >= (reinterpret_cast<uintptr_t>(src) + sizeof(JMP)))
        {
          memcpy(tmpbuff.data(), copy_src, instr.size);
          uint32_t* const immaddr = reinterpret_cast<uint32_t*>(
              tmpbuff.data() + detail.encoding.imm_offset);
          *immaddr =
              static_cast<uint32_t>(imm_op->imm - (tramp_addr + instr.size));
          copy_src = tmpbuff.data();
        }
      }
#endif

      memcpy(reinterpret_cast<void*>(tramp_addr), copy_src, instr.size);
      tramp_pos += instr.size;
    }
  }

  trampoline::trampoline(const trampoline& other)
      : ptarget(other.ptarget),
        ptrampoline(other.ptarget
                        ? trampoline_buffer::allocate(
                              __alterhook_pass_alloc_arg(other.ptarget))
                        : nullptr),
        patch_above(other.patch_above), tramp_size(other.tramp_size),
        positions(other.positions)
  {
    trampcpy(ptrampoline.get(), other.ptrampoline.get(), tramp_size);
    __alterhook_copy_old_protect(other);
#if utils_x64
    prelay = ptrampoline.get() + tramp_size;
    memcpy(prelay, other.prelay, sizeof(JMP_ABS));
#endif
  }

  trampoline::trampoline(trampoline&& other) noexcept
      : ptarget(std::exchange(other.ptarget, nullptr)),
        ptrampoline(std::move(other.ptrampoline)),
        patch_above(std::exchange(other.patch_above, false)),
        tramp_size(std::exchange(other.tramp_size, 0)),
        positions(std::move(other.positions))
  {
    __alterhook_copy_old_protect(other);
#if utils_x64
    prelay = std::exchange(other.prelay, nullptr);
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
      // keeping new buffer to a temporary in case trampcpy throws (very
      // unlikely)
      trampoline_ptr newbuff{ trampoline_buffer::allocate(
          __alterhook_pass_alloc_arg(ptarget)) };
      trampcpy(newbuff.get(), other.ptrampoline.get(), other.tramp_size);
      ptrampoline = std::move(newbuff);
    }
    else
      trampcpy(ptrampoline.get(), other.ptrampoline.get(), other.tramp_size);

    ptarget     = other.ptarget;
    patch_above = other.patch_above;
    tramp_size  = other.tramp_size;
    positions   = other.positions;
    __alterhook_copy_old_protect(other);
#if utils_x64
    prelay = ptrampoline.get() + tramp_size;
    memcpy(prelay, other.prelay, sizeof(JMP_ABS));
#endif
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

    ptarget     = std::exchange(other.ptarget, nullptr);
    ptrampoline = std::move(other.ptrampoline);
    patch_above = std::exchange(other.patch_above, false);
    tramp_size  = std::exchange(other.tramp_size, 0);
    positions   = other.positions;
    other.positions.clear();
    __alterhook_copy_old_protect(other);
#if utils_x64
    prelay = std::exchange(other.prelay, nullptr);
#endif
    return *this;
  }

  void trampoline::reset()
  {
    if (!ptarget)
      return;
    ptarget     = nullptr;
    patch_above = false;
    tramp_size  = 0;
    positions.clear();
#if !utils_windows
    old_protect = PROT_NONE;
#endif
#if utils_x64
    prelay = nullptr;
#endif
  }

#if utils_msvc
  #pragma warning(pop)
#elif utils_gcc
  #pragma GCC diagnostic pop
#endif
} // namespace alterhook