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

  namespace
  {
    constexpr size_t max_branch_dests = 5;

    typedef utils::type_sequence<aarch64::B, aarch64::BL, aarch64::BL,
                                 aarch64::CBZ, aarch64::CBNZ, aarch64::TBZ,
                                 aarch64::TBNZ>
        all_branches;

    typedef std::variant<aarch64::LDR_LITERAL*, aarch64::LDRSW_LITERAL*,
                         aarch64::LDRV_LITERAL*>
        tbm_base_t;

    struct to_be_modified : tbm_base_t
    {
      typedef tbm_base_t base;
      using base::base;
    };

    struct branch_destination
    {
      static constexpr size_t max_references = 5;

      struct reference
      {
        typedef all_branches::template apply<std::add_pointer_t>::template to<
            std::variant>
            src_t;

        src_t src;

        template <typename T>
        reference(T&& arg) : src(std::forward<T>(arg))
        {
        }
      };

      typedef utils::static_vector<reference, max_references> references_t;

      union
      {
        std::byte* const id = nullptr;
        const uintptr_t  uid; // no it's not a linux userid
      };

      union
      {
        std::byte* dest = nullptr;
        uintptr_t  udest;
      };

      references_t references{};

      branch_destination(std::byte* id, std::byte* dest = nullptr)
          : id(id), dest(dest)
      {
      }

      branch_destination(std::byte* id, uintptr_t dest) : id(id), udest(dest) {}
    };

    struct branch_destination_list
        : utils::static_vector<branch_destination, max_branch_dests>
    {
      iterator get_entry(std::byte* id) noexcept
      {
        return std::find_if(begin(), end(),
                            [id](const branch_destination& entry)
                            { return entry.id == id; });
      }

      template <typename instr_t>
      static void patch_offset(std::byte* target, std::byte* dest,
                               instr_t* pinstr)
      {
        typedef typename instr_t::offset_t offset_t;
        const ptrdiff_t                    relative_address =
            dest - reinterpret_cast<std::byte*>(pinstr);
        if (abs(relative_address) > (std::numeric_limits<offset_t>::max)() ||
            !instr_t::offset_fits(relative_address))
          throw(exceptions::instructions_in_branch_handling_fail(target));
        pinstr->set_offset(relative_address);
      }

      // accepts `{ start_address, erased_size }` pairs
      void fix_moved_references(
          std::byte*                                            trampoline,
          std::initializer_list<std::pair<std::byte*, uint8_t>> pairs)
      {
        for (branch_destination& entry : *this)
        {
          std::byte* dest = entry.dest;

          for (const auto [start_address, erased_size] : pairs)
          {
            if (utils::in_between(trampoline, entry.dest,
                                  trampoline + memory_slot_size,
                                  std::less_equal<>{}) &&
                entry.dest > start_address)
              dest -= erased_size;
          }

          entry.dest = dest;

          for (auto& ref : entry.references)
          {
            std::visit(
                [&](auto*& pinstr)
                {
                  typedef std::remove_pointer_t<
                      utils::remove_cvref_t<decltype(pinstr)>>
                                                     instr_t;
                  typedef typename instr_t::offset_t offset_t;
                  auto* instr_address = reinterpret_cast<std::byte*>(pinstr);

                  for (const auto [start_address, erased_size] : pairs)
                  {
                    if (reinterpret_cast<std::byte*>(pinstr) > start_address)
                      instr_address -= erased_size;
                  }

                  pinstr = reinterpret_cast<instr_t*>(instr_address);
                },
                ref.src);
          }
        }
      }

      void process_all(std::byte* target)
      {
        for (branch_destination& entry : *this)
        {
          utils_assert(entry.dest,
                       "branch_destination_list::process: a branch destination "
                       "entry doesn't have its pointer set");

          for (auto& ref : entry.references)
            std::visit([&](auto* pinstr)
                       { patch_offset(target, entry.dest, pinstr); },
                       ref.src);
        }
      }

      void set_destination(std::byte* id, std::byte* dest)
      {
        auto entry = get_entry(id);
        if (entry != end())
          entry->dest = dest;
      }

      template <typename T>
      void insert_reference(std::byte* id, T* instr_ref,
                            std::byte* dest = nullptr)
      {
        auto entry = get_entry(id);
        if (entry != end())
          entry->references.emplace_back(instr_ref);
        else
          emplace_back(id, dest).references.emplace_back(instr_ref);
      }
    };

    struct trampoline_context
    {
      struct session;
      typedef std::bitset<memory_slot_size> buffer_bitset_t;
      typedef std::pair<bool, uintptr_t>    pc_handling_begin_t;
      typedef utils::static_vector<std::pair<uint8_t, uint8_t>, 8> positions_t;

      bool                    finished    = false;
      bool                    pc_handling = false;
      const uint8_t           size_needed = 0;
      std::bitset<32>         registers_found{};
      buffer_bitset_t         bytes_used{};
      uint8_t                 last_unused_pos = 0;
      uint8_t                 available_size  = memory_slot_size;
      pc_handling_begin_t     pc_handling_begin{};
      positions_t             positions{};
      branch_destination_list branch_list{};

      struct
      {
        bool active     = false;
        bool uses_stack = false;

        union
        {
          std::byte* pc_location = nullptr;
          uintptr_t  upc_location;
        };

        union
        {
          std::byte* pc_value = nullptr;
          uintptr_t  upc_value;
        };
      } pc_handling_context{};

      struct trampoline_t
      {
        union
        {
          std::byte* const begin = nullptr;
          const uintptr_t  ubegin;
        };

        union
        {
          std::byte* end = nullptr;
          uintptr_t  uend;
        };

        union
        {
          std::byte* const buffer_end = nullptr;
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
        union
        {
          std::byte* const begin = nullptr;
          const uintptr_t  ubegin;
        };

        union
        {
          std::byte* end = nullptr;
          uintptr_t  uend;
        };

        target_t(std::byte* target) : begin(target), end(target) {}
      } target;

      trampoline_context(std::byte* target, std::byte* trampoline)
          : size_needed(static_cast<uint8_t>(
                utils::align_up(target + sizeof(aarch64::custom::FULL_JMP),
                                8u) -
                target)),
            trampoline(trampoline), target(target)
      {
      }

      static bool is_pad(const std::byte* address,
                         uint8_t          required_size) noexcept
      {
        auto* const u32address = reinterpret_cast<const uint32_t*>(address);
        return std::all_of(
            u32address, u32address + (utils::align_up(required_size, 4u) / 4u),
            [](const uint32_t data) { return data == aarch64::NOP::opcode; });
      }

      bool rest_is_pad(uint8_t required_size) const noexcept
      {
        return is_pad(target.end, required_size);
      }

      uintptr_t allocate_address(uint8_t size, uintptr_t fill = 0) noexcept
      {
        assert(utils::any_of(size, 4u, 8u));
        const buffer_bitset_t mask = utils::bitsfill<uintptr_t>(size);
        for (uint8_t i = 0; i != memory_slot_size; i += size)
        {
          if (((bytes_used >> i) & mask).any())
            continue;
          bytes_used              |= (mask << i);
          i                       += size;
          const uintptr_t dataloc  = trampoline.ubuffer_end - i;
          if (i > last_unused_pos)
          {
            i              = last_unused_pos;
            available_size = memory_slot_size - i;
          }
          memcpy(reinterpret_cast<void*>(dataloc), &fill, size);
          return dataloc;
        }

        assert(!"allocate_address: exceeded the limits of the available space "
                "in which an address can be allocated");
      }

      void must_fit(uint8_t copy_size)
      {
        const uint8_t tramp_pos = trampoline.end - trampoline.begin;
        if ((tramp_pos + copy_size) > available_size)
          throw(exceptions::trampoline_max_size_exceeded(
              target.begin, tramp_pos + copy_size, available_size));
      }

      bool is_in_overriden_area(uintptr_t branch_dest) const noexcept
      {
        return target.ubegin <= branch_dest &&
               branch_dest < (target.ubegin + size_needed);
      }

      session create_session(disassembler& aarch64, const cs_insn& instr);
    };

    struct trampoline_context::session
    {
      template <typename T>
      using instr_ptr_t = std::add_pointer_t<utils::remove_cvref_t<T>>;
      template <typename T>
      static constexpr bool is_branch =
          all_branches::template has<utils::remove_cvref_t<T>>;
      template <typename T>
      static constexpr bool is_custom_instruction =
          std::is_base_of_v<aarch64::INSTRUCTION, utils::remove_cvref_t<T>>;

      static constexpr size_t                    buffer_size = 32;
      typedef std::array<std::byte, buffer_size> buffer_t;

      disassembler&       aarch64;
      trampoline_context& ctx;
      buffer_t            buffer{};
      const std::byte*    copy_source = nullptr;
      uint8_t             copy_size   = 0;

      union
      {
        std::byte* const target_instruction_address = nullptr;
        const uintptr_t  utarget_instruction_address;
      };

      session(disassembler& aarch64, trampoline_context& ctx,
              const cs_insn& instr)
          : aarch64(aarch64), ctx(ctx),
            copy_source(reinterpret_cast<const std::byte*>(instr.bytes)),
            copy_size(instr.size), utarget_instruction_address(instr.address)
      {
        ctx.target.end += instr.size;
        aarch64.set_reg_accesses(instr);
        ctx.branch_list.set_destination(target_instruction_address,
                                        ctx.trampoline.end);
      }

      session(const session&)            = delete;
      session& operator=(const session&) = delete;

      ~session()
      {
        const uint8_t target_pos =
                          target_instruction_address - ctx.target.begin,
                      tramp_pos = ctx.trampoline.end - ctx.trampoline.begin;
        ctx.must_fit(copy_size);
        ctx.positions.push_back({ target_pos, tramp_pos });
        memcpy(ctx.trampoline.end, copy_source, copy_size);
        ctx.trampoline.end += copy_size;
      }

      template <typename T, std::enable_if_t<is_branch<T>, size_t> = 0>
      void add_instruction(T&& instr, std::byte* id)
      {
        prepare_buffer();
        new (&buffer[copy_size]) auto(instr);
        // if the id (refers to the destination) is in the overriden area then
        // the destination will be relocated to the trampoline so we put null as
        // of now. otherwise we just pass id as the destination
        std::byte* const branch_dest =
            ctx.is_in_overriden_area(id) ? nullptr : id;
        ctx.branch_list.insert_reference(
            id,
            reinterpret_cast<instr_ptr_t<T>>(ctx.trampoline.end + copy_size),
            branch_dest);
        copy_size += sizeof(aarch64::INSTRUCTION);
      }

      template <typename T,
                std::enable_if_t<is_custom_instruction<T> && !is_branch<T>,
                                 size_t> = 0>
      void add_instruction(T&& instr)
      {
        constexpr auto instr_size = sizeof(utils::remove_cvref_t<T>);
        prepare_buffer();
        new (&buffer[copy_size]) auto(instr);
        copy_size += instr_size;
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
    };

    typename trampoline_context::session
        trampoline_context::create_session(disassembler&  aarch64,
                                           const cs_insn& instr)
    {
      return { aarch64, *this, instr };
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
      ptrampoline = trampoline_ptr(trampoline_buffer::allocate(target));
    if (ptarget)
      reset();

    trampoline_context ctx{ target, ptrampoline.get() };
    disassembler       aarch64{ target };

#ifndef NDEBUG
    std::fill(reinterpret_cast<aarch64::BRK*>(ctx.trampoline.begin),
              reinterpret_cast<aarch64::BRK*>(ctx.trampoline.buffer_end),
              aarch64::BRK());
#endif

    for (const cs_insn& instr : aarch64.disasm(memory_slot_size))
    {
    }
  }
} // namespace alterhook