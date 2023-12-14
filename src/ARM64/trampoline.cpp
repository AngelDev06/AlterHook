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

  int get_protection(const std::byte* address);

  void trampoline::init(std::byte* target) 
  { 
    if (ptarget == target)
      return;

  }
} // namespace alterhook