/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#pragma GCC visibility push(hidden)

namespace alterhook
{
#if utils_arm
  #define __usethumb(...) __VA_ARGS__
#else
  #define __usethumb(...)
#endif

  class disassembler
  {
  public:
    class weak_iterator;
    class iterator;

    struct registers
    {
      std::array<uint16_t, MAX_IMPL_R_REGS> read{};
      std::array<uint16_t, MAX_IMPL_W_REGS> write{};
      uint8_t                               read_count  = 0;
      uint8_t                               write_count = 0;

      bool reads(uint16_t reg) const
      {
        const auto read_begin = read.begin(),
                   read_end   = read.begin() + read_count;
        return std::find(read_begin, read_end, reg) != read_end;
      }

      bool modifies(uint16_t reg) const
      {
        const auto write_begin = write.begin(),
                   write_end   = write.begin() + write_count;
        return std::find(write_begin, write_end, reg) != write_end;
      }
    };

#if utils_x86 || utils_x64
    static constexpr cs_arch architecture = CS_ARCH_X86;
    typedef cs_x86           arch_t;
    typedef cs_x86_op        operand_t;
    typedef x86_reg          register_t;
#elif utils_aarch64
    static constexpr cs_arch architecture = CS_ARCH_AARCH64;
    typedef cs_aarch64       arch_t;
    typedef cs_aarch64_op    operand_t;
    typedef aarch64_reg      register_t;
#elif utils_arm
    static constexpr cs_arch architecture = CS_ARCH_ARM;
    typedef cs_arm           arch_t;
    typedef cs_arm_op        operand_t;
    typedef arm_reg          register_t;
#endif

    constexpr cs_mode mode() const noexcept
    {
#if utils_x64
      return CS_MODE_64;
#elif utils_x86
      return CS_MODE_32;
#elif utils_aarch64
      return CS_MODE_ARM;
#elif utils_arm
      return thumb ? CS_MODE_THUMB : CS_MODE_ARM;
#endif
    }

    disassembler(const std::byte*  src,
                 uintptr_t address __usethumb(, bool thumb), bool detail = true)
        : src(src), address(address) __usethumb(, thumb(thumb))
    {
      if (cs_err error = cs_open(architecture, mode(), &handle))
        throw(exceptions::disassembler_init_fail(src, error));
      if (!detail)
        return;
      if (cs_err error = cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON))
        throw(exceptions::disassembler_init_fail(src, error));
    }

    disassembler(const std::byte* src __usethumb(, bool thumb),
                 bool                 detail = true)
        : disassembler(
              src, reinterpret_cast<uintptr_t>(src) __usethumb(, thumb), detail)
    {
    }

    disassembler(const disassembler&)            = delete;
    disassembler& operator=(const disassembler&) = delete;

    // not checking for errors on close to keep this noexcept
    ~disassembler() noexcept { cs_close(&handle); }

    disassembler& disasm(size_t size) noexcept
    {
      disasm_size = size;
      return *this;
    }
#if utils_arm
    // changes from ARM to THUMB & vice versa
    void switch_instruction_set()
    {
      thumb = !thumb;
      cs_option(handle, CS_OPT_MODE, thumb ? CS_MODE_THUMB : CS_MODE_ARM);
    }
#endif

    registers get_all_registers(const cs_insn& instr) const noexcept
    {
      registers result{};
      cs_regs_access(handle, &instr, result.read.data(), &result.read_count,
                     result.write.data(), &result.write_count);
      return result;
    }

    bool modifies_register(const cs_insn& instr, uint16_t reg) const
    {
      return get_all_registers(instr).modifies(reg);
    }

    bool reads_register(const cs_insn& instr, uint16_t reg) const
    {
      return get_all_registers(instr).reads(reg);
    }

    static bool has_group(const cs_insn& instr, uint8_t group)
    {
      return memchr(instr.detail->groups, group, instr.detail->groups_count);
    }

    static bool is_branch(const cs_insn& instr) noexcept
    {
      return has_group(instr, CS_GRP_JUMP) || has_group(instr, CS_GRP_CALL);
    }

    static bool is_call(const cs_insn& instr) noexcept
    {
      return has_group(instr, CS_GRP_CALL);
    }

    static bool is_relative_branch(const cs_insn& instr) noexcept
    {
      return has_group(instr, CS_GRP_BRANCH_RELATIVE);
    }

    static bool is_return(const cs_insn& instr) noexcept
    {
      return has_group(instr, CS_GRP_RET);
    }

    static std::optional<int64_t> get_immediate(const arch_t& instr) noexcept
    {
      const auto *operands_begin = instr.operands,
                 *operands_end   = instr.operands + instr.op_count;
      const auto result          = std::find_if(
          operands_begin, operands_end,
          [](const operand_t& operand)
          { return static_cast<cs_op_type>(operand.type) == CS_OP_IMM; });
      if (result != operands_end)
        return result->imm;
      return std::nullopt;
    }

    static std::optional<register_t> get_register(const arch_t& instr) noexcept
    {
      const auto *operands_begin = instr.operands,
                 *operands_end   = instr.operands + instr.op_count;
      const auto result          = std::find_if(
          operands_begin, operands_end,
          [](const operand_t& operand)
          { return static_cast<cs_op_type>(operand.type) == CS_OP_REG; });
      if (result != operands_end)
        return static_cast<register_t>(result->reg);
      return std::nullopt;
    }

    iterator begin() const noexcept;

    std::nullptr_t end() const noexcept { return nullptr; }

    const void* get_address() const noexcept { return src; }

    csh get_handle() const noexcept { return handle; }
#if utils_arm
    bool is_thumb() const noexcept { return thumb; }
#endif

    weak_iterator follow_instruction(const cs_insn& instr, size_t size);

    void set_source(const std::byte* new_src) noexcept { src = new_src; }

    void set_address(uintptr_t new_address) noexcept { address = new_address; }

  private:
    const std::byte* src     = nullptr;
    uintptr_t        address = 0;
#if utils_arm
    bool thumb;
#endif
    csh    handle      = CS_ERR_OK;
    size_t disasm_size = 0;
  };

  class disassembler::weak_iterator
  {
  public:
    weak_iterator() {}

    const cs_insn* operator->() const noexcept
    {
      utils_assert(instr,
                   "Attempt to dereference an uninitialized instruction");
      return instr;
    }

    const cs_insn& operator*() const noexcept { return *operator->(); }

    weak_iterator& operator++()
    {
      utils_assert(
          instr, "Attempt to increment an uninitialized instruction iterator");
      status = cs_disasm_iter(handle, reinterpret_cast<const uint8_t**>(&code),
                              &size, &address, instr);
      if (cs_err error = cs_errno(handle))
        throw(exceptions::disassembler_disasm_fail(code, error));
      return *this;
    }

    explicit operator bool() const noexcept { return status; }

    bool operator==(std::nullptr_t) const noexcept { return !status; }

    bool operator!=(std::nullptr_t) const noexcept { return status; }

  private:
    csh              handle  = 0;
    const std::byte* code    = nullptr;
    uint64_t         address = 0;
    size_t           size    = 0;
    cs_insn*         instr   = nullptr;
    bool             status  = false;

    weak_iterator(cs_insn* instr, csh handle, const std::byte* src,
                  uintptr_t original_address, size_t code_size)
        : handle(handle), code(src), address(original_address), size(code_size),
          instr(instr)
    {
      if (!code_size)
        return;
      if (!instr)
        throw(exceptions::disassembler_iter_init_fail(code, cs_errno(handle)));
      status = cs_disasm_iter(handle, reinterpret_cast<const uint8_t**>(&code),
                              &size, &address, instr);
      if (cs_err error = cs_errno(handle))
        throw(exceptions::disassembler_disasm_fail(code, error));
    }

    friend class disassembler;
    friend class iterator;
  };

  class disassembler::iterator : public disassembler::weak_iterator
  {
  public:
    typedef typename disassembler::weak_iterator base;

    iterator() {}

    ~iterator() noexcept
    {
      if (instr)
        cs_free(instr, 1);
    }

    iterator& operator++()
    {
      base::operator++();
      return *this;
    }

  private:
    iterator(csh handle, const std::byte* src, uintptr_t original_address,
             size_t code_size)
        : base(cs_malloc(handle), handle, src, original_address, code_size)
    {
    }

    friend class disassembler;
  };

  inline typename disassembler::iterator disassembler::begin() const noexcept
  {
    return { handle, src, address, disasm_size };
  }

#if utils_x86 || utils_x64
  inline typename disassembler::weak_iterator
      disassembler::follow_instruction(const cs_insn& instr, size_t size)
  {
    utils_assert(memchr(instr.detail->groups, X86_GRP_BRANCH_RELATIVE,
                        instr.detail->groups_count),
                 "Tried to follow a non-branch relative instruction");
    cs_x86&          detail         = instr.detail->x86;
    const cs_x86_op *operands_begin = detail.operands,
                    *operands_end   = detail.operands + detail.op_count;
    const cs_x86_op* result         = std::find_if(
        operands_begin, operands_end,
        [](const cs_x86_op& operand) { return operand.type == X86_OP_IMM; });
    if (result == operands_end)
      return {};

    return { const_cast<cs_insn*>(&instr), handle,
             reinterpret_cast<std::byte*>(result->imm),
             static_cast<uintptr_t>(result->imm), size };
  }
#endif
} // namespace alterhook

#pragma GCC visibility pop
