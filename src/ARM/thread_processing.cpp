#include <pch.h>
#include "trampoline.h"

#if !utils_msvc
  #pragma GCC diagnostic push
  #pragma GCC diagnostic ignored "-Wrange-loop-construct"
#endif

namespace alterhook
{
  void report_error(std::byte* tramp, std::byte* target, uint8_t pos) noexcept;

  ALTERHOOK_HIDDEN uintptr_t process_frozen_threads(const trampoline& tramp,
                                                    bool      enable_hook,
                                                    uintptr_t pc) noexcept
  {
    const uintptr_t target = reinterpret_cast<uintptr_t>(tramp.ptarget) & ~1,
                    tramp_buffer =
                        reinterpret_cast<uintptr_t>(tramp.ptrampoline.get());

    if (enable_hook)
    {
      for (const auto [oldpos, newpos] : tramp.positions)
      {
        if (pc != (target + oldpos))
          continue;

        const uintptr_t dest    = tramp_buffer + newpos;
        const uintptr_t pushloc = tramp_buffer + tramp.pc_handling.second;

        if (tramp.pc_handling.first && dest > pushloc)
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
      const uintptr_t dest = target + oldpos, src = tramp_buffer + newpos,
                      prevsrc = tramp_buffer + prevpos,
                      pushloc = tramp_buffer + tramp.pc_handling.second;

      if (prevsrc > pc || pc > src)
      {
        prevpos = newpos;
        continue;
      }

      if (pc < src || tramp.pc_handling.first && pc > pushloc)
      {
        report_error(tramp.ptrampoline.get(), tramp.ptarget,
                     static_cast<uint8_t>(pc - tramp_buffer));
        return 0;
      }

      return dest;
    }

    return 0;
  }
} // namespace alterhook

#if !utils_msvc
  #pragma GCC diagnostic pop
#endif