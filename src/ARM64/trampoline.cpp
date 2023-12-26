/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#include <pch.h>
#include "exceptions.h"
#include "disassembler.h"
#include "arm64_instructions.h"
#include "buffer.h"
#include "linux_thread_handler.h"
#include "trampoline.h"

namespace alterhook
{
  extern std::shared_mutex hook_lock;

  void trampoline::deleter::operator()(std::byte* ptrampoline) const noexcept
  {
    trampoline_buffer::deallocate(ptrampoline);
  }

  inline namespace init_impl
  {
    struct trampoline_entry
    {

    };
  }

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

#ifndef NDEBUG
    // fill the buffer with debug breakpoints (BRK #0)
    std::fill_n(reinterpret_cast<uint32_t*>(ptrampoline.get()),
                memory_slot_size, 0xD4'20'00'00);
#endif

    size_t       tramp_pos = 0;
    disassembler aarch64{ target };

    for (const cs_insn& instr : aarch64.disasm(memory_slot_size))
    {

    }
  }
} // namespace alterhook