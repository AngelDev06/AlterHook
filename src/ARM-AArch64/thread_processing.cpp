/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#include <pch.h>
#include "trampoline.h"
#pragma GCC visibility push(hidden)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wrange-loop-construct"

namespace alterhook
{
  void report_error(std::byte* tramp, std::byte* target, uint8_t pos) noexcept;

  uintptr_t process_frozen_threads(const trampoline& tramp, bool enable_hook,
                                   uintptr_t pc) noexcept
  {
    const uintptr_t utarget = reinterpret_cast<uintptr_t>(tramp.ptarget),
                    utrampoline =
                        reinterpret_cast<uintptr_t>(tramp.ptrampoline.get());

    if (enable_hook)
    {
      for (const auto [oldpos, newpos] : tramp.positions)
      {
        if (pc != (utarget + oldpos))
          continue;
        const uintptr_t dest = utrampoline + newpos;

        if (!tramp.pc_handling)
          return dest;
        const uintptr_t pushloc = utrampoline + tramp.pc_handling.value();

        if (dest > pushloc)
        {
          report_error(tramp.ptrampoline.get(), tramp.ptarget, oldpos);
          return 0;
        }

        return dest;
      }
      return 0;
    }

    uint8_t prevpos = 0;

    for (const auto [oldpos, newpos] : tramp.positions)
    {
      const uintptr_t dest = utarget + oldpos, src = utrampoline + newpos,
                      prevsrc = utrampoline + prevpos;

      if (prevsrc > pc || pc > src)
      {
        prevpos = newpos;
        continue;
      }

      if (!tramp.pc_handling.has_value())
        return dest;
      const uintptr_t pushloc = utrampoline + tramp.pc_handling.value();

      if (pc < src || pc > pushloc)
      {
        report_error(tramp.ptrampoline.get(), tramp.ptarget,
                     static_cast<uint8_t>(pc - utrampoline));
        return 0;
      }

      return dest;
    }

    return 0;
  }
} // namespace alterhook

#pragma GCC diagnostic pop
#pragma GCC visibility pop
