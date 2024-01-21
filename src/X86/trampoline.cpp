/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#include <pch.h>
#include "exceptions.h"
#include "disassembler.h"
#include "buffer.h"
#include "tools.h"
#include "trampoline.h"
#include "x86_instructions.h"

namespace alterhook
{
  void trampoline::deleter::operator()(std::byte* src) const noexcept
  {
    trampoline_buffer::deallocate(src);
  }

  extern std::shared_mutex hook_lock;

#pragma GCC visibility push(hidden)

  static bool is_pad(const std::byte* target, size_t size) noexcept
  {
    if (!utils::any_of(target[0], std::byte(), std::byte(0x90),
                       std::byte(0xCC)))
      return false;
    return std::all_of(target + 1, target + size,
                       [x = target[0]](std::byte data) { return x == data; });
  }

  static bool in_overriden_area(const std::byte* target,
                                uintptr_t        address) noexcept
  {
#if utils_x64
    constexpr size_t max_range = sizeof(JMP_ABS);
#else
    constexpr size_t max_range = sizeof(JMP);
#endif
    return reinterpret_cast<uintptr_t>(target) <= address &&
           address < (reinterpret_cast<uintptr_t>(target) + max_range);
  }

  template <x86_insn_group group>
  static bool is_in_group(const cs_insn& instr) noexcept
  {
    return memchr(instr.detail->groups, group, instr.detail->groups_count);
  }

  static bool is_relative_branch(const cs_insn& instr) noexcept
  {
    return is_in_group<X86_GRP_BRANCH_RELATIVE>(instr);
  }

  static bool is_jump(const cs_insn& instr) noexcept
  {
    return is_in_group<X86_GRP_JUMP>(instr);
  }

  static bool is_return(const cs_insn& instr) noexcept
  {
    return is_in_group<X86_GRP_RET>(instr);
  }

  static void fits_in_trampoline(std::byte* target, size_t current_size)
  {
    if (current_size > memory_slot_size)
      throw(exceptions::trampoline_max_size_exceeded(target, current_size,
                                                     memory_slot_size));
  }

#if !utils_windows && utils_x86
  static bool is_linux_ip_thunk(const cs_insn& instr) noexcept
  {
    const cs_x86& detail = instr.detail->x86;
    return instr.id == X86_INS_MOV && detail.op_count == 2 &&
           detail.operands[0].type == X86_OP_REG &&
           detail.operands[1].type == X86_OP_MEM &&
           detail.operands[1].mem.base == X86_REG_ESP &&
           detail.operands[1].mem.disp == 0;
  }

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

#pragma warning(push)
#pragma warning(disable : 4244 4018 4267)
#pragma GCC diagnostic   push
#pragma GCC diagnostic   ignored "-Wsign-compare"
#pragma GCC diagnostic   ignored "-Wstrict-overflow"
#pragma clang diagnostic ignored "-Wshorten-64-to-32"

  inline namespace init_impl
  {
    constexpr size_t max_trampoline_entries = 5;

#if utils_x64
    constexpr size_t big_jump_size = sizeof(JMP_ABS);
    constexpr size_t big_call_size = sizeof(CALL_ABS);
    constexpr size_t big_jcc_size  = sizeof(JCC_ABS);

  #define BIG_JUMP(dest, src) JMP_ABS(dest)
  #define BIG_CALL(dest, src) CALL_ABS(dest)
  #define BIG_JCC(condition, dest, src)                                        \
    JCC_ABS(static_cast<uint8_t>(0x71 ^ condition), dest)
#else
    constexpr size_t big_jump_size = sizeof(JMP);
    constexpr size_t big_call_size = sizeof(CALL);
    constexpr size_t big_jcc_size  = sizeof(JCC);

  #define BIG_JUMP(dest, src) JMP((dest) - ((src) + sizeof(JMP)))
  #define BIG_CALL(dest, src) CALL((dest) - ((src) + sizeof(CALL)))
  #define BIG_JCC(condition, dest, src)                                        \
    JCC(static_cast<uint8_t>(0x80 | condition), (dest) - ((src) + sizeof(JCC)))
#endif

    struct trampoline_entry
    {
      static constexpr size_t max_references = 5;

      struct reference
      {
        std::byte* src;
        uint16_t   instruction_size;
        uint8_t    immediate_offset;
        uint8_t    immediate_size;
      };

      typedef utils::static_vector<reference, max_references> references_t;

      uint8_t      id    = 0;
      std::byte*   instr = nullptr;
      references_t references;

      trampoline_entry(uint8_t id) : id(id) {}
    };

    struct entry_list
        : utils::static_vector<trampoline_entry, max_trampoline_entries>
    {
      iterator get_entry(uint8_t id) noexcept
      {
        return std::find_if(begin(), end(),
                            [=](trampoline_entry& item)
                            { return item.id == id; });
      }

      void process(uint8_t id)
      {
        auto result = get_entry(id);
        if (result == end())
          return;
        utils_assert(result->instr, "entry_list::process: a trampoline entry "
                                    "doesn't have its new location set");

        for (auto& reference : result->references)
        {
          intptr_t relative_address =
              result->instr - (reference.src + reference.instruction_size);
          memcpy(reference.src + reference.immediate_offset, &relative_address,
                 reference.immediate_size);
        }

        erase(result);
      }

      void set_new_location(uint8_t id, std::byte* instr)
      {
        auto result = get_entry(id);
        if (result == end())
          return;
        result->instr = instr;
      }

      void insert_or_add_reference(
          uint8_t id, const typename trampoline_entry::reference& reference)
      {
        auto result = get_entry(id);
        if (result != end())
        {
          result->references.push_back(reference);
          return;
        }

        auto& new_element = emplace_back(id);
        new_element.references.push_back(reference);
      }

      void fix_leftover_branches(std::byte* target)
      {
        for (trampoline_entry& entry : *this)
        {
          for (auto& ref : entry.references)
          {
            const ptrdiff_t relative_address =
                (target + entry.id) - (ref.src + ref.instruction_size);
            constexpr std::array<int64_t, 4> maxes = {
              (std::numeric_limits<int8_t>::max)(),
              (std::numeric_limits<int16_t>::max)(),
              (std::numeric_limits<int32_t>::max)(),
              (std::numeric_limits<int64_t>::max)()
            };
            const intptr_t max =
                maxes[utils::bitscanf(ref.immediate_size).value()];
            if (llabs(relative_address) >= max)
              throw(exceptions::instructions_in_branch_handling_fail(target));

            memcpy(ref.src + ref.immediate_offset, &relative_address,
                   ref.immediate_size);
          }
        }

        clear();
      }
    };
  } // namespace init_impl

#pragma GCC visibility pop

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

    constexpr size_t max_tmp_buffer_size = 16;
#if !always_use_relay
    constexpr size_t size_needed = big_jump_size;
#else
    constexpr size_t size_needed = sizeof(JMP);
#endif

    const uintptr_t utarget = reinterpret_cast<uintptr_t>(target);

    typedef std::array<std::byte, max_tmp_buffer_size> tmpbuff_t;
    typedef typename trampoline_entry::reference       entry_reference;

    tmpbuff_t    tmpbuff{};
    entry_list   entries{};
    positions_t  tmp_positions{};
    size_t       tramp_pos    = 0;
    bool         finished     = false;
    size_t       current_size = 0;
    disassembler x86{ target };

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
      current_size                    = (instr.address + instr.size) - utarget;

      entries.set_new_location(static_cast<uint8_t>(instr.address - utarget),
                               ptrampoline.get() + tramp_pos);

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
      if (is_relative_branch(instr))
      {
        // clang-format on
        auto imm_op = std::find_if(operands_begin, operands_end,
                                   [](const cs_x86_op& element)
                                   { return element.type == X86_OP_IMM; });
        utils_assert(imm_op != operands_end,
                     "(unreachable) The immediate operand of a relative "
                     "branch instruction wasn't found");

        // clang-format on
        if (is_jump(instr))
        {
          if (in_overriden_area(target, imm_op->imm))
          {
            // on forward branch we save a reference to the destination for
            // later modification if needed
            if (imm_op->imm > instr.address)
              entries.insert_or_add_reference(
                  static_cast<uint8_t>(imm_op->imm - utarget),
                  entry_reference{
                      .src = reinterpret_cast<std::byte*>(instr.address),
                      .instruction_size = instr.size,
                      .immediate_offset = detail.encoding.imm_offset,
                      .immediate_size   = detail.encoding.imm_size });
          }
          else
          {
            if (instr.id == X86_INS_JMP)
            {
              new (tmpbuff.data())
                  BIG_JUMP(static_cast<uintptr_t>(imm_op->imm), tramp_addr);
              copy_size = big_jump_size;
              finished  = entries.empty();
            }
            else if ((X86_INS_LOOP <= instr.id && instr.id <= X86_INS_LOOPNE) ||
                     instr.id == X86_INS_JRCXZ || instr.id == X86_INS_JECXZ)
              throw(exceptions::unsupported_instruction_handling(
                  target, utils::to_array<24>(copy_src, copy_src + copy_size)));
            else
            {
              uint8_t condition =
                  (detail.opcode[0] != 0x0F ? detail.opcode[0]
                                            : detail.opcode[1]) &
                  0x0F;

              new (tmpbuff.data()) BIG_JCC(
                  condition, static_cast<uintptr_t>(imm_op->imm), tramp_addr);
              copy_size = big_jcc_size;
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
          // handling for linux binaries compiled with -fpic (it deals with the
          // call to the thunk that returns a relative address)
          auto itr = x86.follow_instruction(instr, memory_slot_size);
          if (itr && is_linux_ip_thunk(instr))
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

          new (tmpbuff.data())
              BIG_CALL(static_cast<uintptr_t>(dest), tramp_addr);
          copy_size = big_call_size;

#if !utils_windows && utils_x86
        CALL_HANDLING_END:
#endif
          copy_src = tmpbuff.data();
        }
      }
      else if (is_return(instr))
        finished = entries.empty();

      fits_in_trampoline(target, tramp_pos + copy_size);
      entries.process(static_cast<uint8_t>(instr_address - utarget));
      tmp_positions.push_back({ instr_address - utarget, tramp_pos });
      memcpy(reinterpret_cast<void*>(tramp_addr), copy_src, copy_size);
      tramp_pos += copy_size;

      if (finished)
        break;

      if (current_size >= size_needed)
      {
        fits_in_trampoline(target, tramp_pos + big_jump_size);
        new (ptrampoline.get() + tramp_pos)
            BIG_JUMP(instr_address + instr_size, tramp_addr + copy_size);
        tramp_pos += big_jump_size;
        finished   = true;
        break;
      }
    }

    if (!finished)
      throw(exceptions::bad_target(target));

    entries.fix_leftover_branches(target);

    const std::byte* current_target_address = target + current_size;
    if (current_size < size_needed &&
        !is_pad(current_target_address, size_needed - current_size))
    {
#if !always_use_relay && utils_x64
      if (current_size >= sizeof(JMP) ||
          is_pad(current_target_address, sizeof(JMP) - current_size))
      {
        fits_in_trampoline(target, tramp_pos + sizeof(JMP_ABS));
        prelay = ptrampoline.get() + tramp_pos;
        new (prelay) JMP_ABS();
      }
      else
#endif
      {
        if ((current_size < sizeof(JMP_SHORT) &&
             !is_pad(current_target_address,
                     sizeof(JMP_SHORT) - current_size)) ||
            !is_executable_address(target - sizeof(JMP)) ||
            !is_pad(target - sizeof(JMP), sizeof(JMP)))
          throw(exceptions::insufficient_function_size(target, current_size,
                                                       sizeof(JMP)));

        patch_above = true;
      }
    }

    ptarget    = target;
    tramp_size = tramp_pos;
    positions  = tmp_positions;
#if !utils_windows
    old_protect = tmp_protinfo;
#endif

#if always_use_relay
    fits_in_trampoline(target, tramp_size + sizeof(JMP_ABS));
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
      if (is_relative_branch(instr))
      {
        auto imm_op = std::find_if(operands_begin, operands_end,
                                   [](const cs_x86_op& element)
                                   { return element.type == X86_OP_IMM; });
        utils_assert(imm_op != operands_end,
                     "(unreachable) The immediate operand of a relative branch "
                     "instruction wasn't found");
        if (!is_jump(instr) || !in_overriden_area(src, imm_op->imm))
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
                        ? trampoline_buffer::allocate(__origin(other.ptarget))
                        : nullptr),
        patch_above(other.patch_above), tramp_size(other.tramp_size),
        positions(other.positions)
  {
    trampcpy(ptrampoline.get(), other.ptrampoline.get(), tramp_size);
#if !utils_windows
    old_protect = other.old_protect;
#endif
#if utils_x64
    if (other.prelay)
    {
      prelay = ptrampoline.get() + tramp_size;
      memcpy(prelay, other.prelay, sizeof(JMP_ABS));
    }
#endif
  }

  trampoline::trampoline(trampoline&& other) noexcept
      : ptarget(std::exchange(other.ptarget, nullptr)),
        ptrampoline(std::move(other.ptrampoline)),
        patch_above(std::exchange(other.patch_above, false)),
        tramp_size(std::exchange(other.tramp_size, 0)),
        positions(std::move(other.positions))
  {
#if !utils_windows
    old_protect = other.old_protect;
#endif
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
          __origin(other.ptarget)) };
      trampcpy(newbuff.get(), other.ptrampoline.get(), other.tramp_size);
      ptrampoline = std::move(newbuff);
    }
    else
      trampcpy(ptrampoline.get(), other.ptrampoline.get(), other.tramp_size);

    ptarget     = other.ptarget;
    patch_above = other.patch_above;
    tramp_size  = other.tramp_size;
    positions   = other.positions;
#if !utils_windows
    old_protect = other.old_protect;
#endif
#if utils_x64
    prelay = nullptr;

    if (other.prelay)
    {
      prelay = ptrampoline.get() + tramp_size;
      memcpy(prelay, other.prelay, sizeof(JMP_ABS));
    }
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
#if !utils_windows
    old_protect = other.old_protect;
#endif
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
    old_protect = {};
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
