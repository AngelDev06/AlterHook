/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#if !utils_windows
  #pragma GCC visibility push(hidden)
#endif

namespace alterhook
{
#if utils_arm
  #define __usethumb(...) __VA_ARGS__
#else
  #define __usethumb(...)
#endif

#if utils_x86 || utils_x64
  constexpr cs_arch disasm_arch = CS_ARCH_X86;
  #if utils_x64
    #define disasm_mode(unused) CS_MODE_64
  #else
    #define disasm_mode(unused) CS_MODE_32
  #endif
#elif utils_arm64
  constexpr cs_arch disasm_arch = CS_ARCH_ARM64;
  #define disasm_mode(unused) CS_MODE_ARM
#else
  constexpr cs_arch disasm_arch = CS_ARCH_ARM;
  #define disasm_mode(thumb) (thumb ? CS_MODE_THUMB : CS_MODE_ARM)
#endif

  class disassembler
  {
  public:
    class weak_iterator;
    class iterator;

    disassembler(const std::byte*  src,
                 uintptr_t address __usethumb(, bool thumb), bool detail = true)
        : src(src), address(address) __usethumb(, thumb(thumb))
    {
      if (cs_err error = cs_open(disasm_arch, disasm_mode(thumb), &handle))
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
    void set_reg_accesses(const cs_insn& instr) const
    {
      instr.detail->regs_read_count  = 0;
      instr.detail->regs_write_count = 0;
      cs_regs_access(handle, &instr, instr.detail->regs_read,
                     &instr.detail->regs_read_count, instr.detail->regs_write,
                     &instr.detail->regs_write_count);
    }

    bool modifies_reg(const cs_insn& instr, uint32_t reg) const
    {
      return cs_reg_write(handle, &instr, reg);
    }

    bool reads_reg(const cs_insn& instr, uint32_t reg) const
    {
      return cs_reg_read(handle, &instr, reg);
    }

    bool has_group(const cs_insn& instr, uint8_t group) const
    {
      return memchr(instr.detail->groups, group, instr.detail->groups_count);
    }

    iterator begin() const noexcept;

    std::nullptr_t end() const noexcept { return nullptr; }

    const void* get_address() const noexcept { return src; }

    csh get_handle() const noexcept { return handle; }
#if utils_arm
    bool is_thumb() const noexcept { return thumb; }
#endif

    weak_iterator follow_instruction(const cs_insn& instr, size_t size);

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

#if !utils_windows
  #pragma GCC visibility pop
#endif