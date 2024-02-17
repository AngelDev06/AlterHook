/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#include <pch.h>
#include "exceptions.h"
#include "disassembler.h"
#include "instructions.h"
#include "buffer.h"
#include "trampoline.h"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wrange-loop-construct"

namespace alterhook
{
  extern std::shared_mutex hook_lock;

  void trampoline::deleter::operator()(std::byte* ptrampoline) const noexcept
  {
    trampoline_buffer::deallocate(ptrampoline);
  }

  namespace
  {
    constexpr size_t max_branch_dests   = 5;
    constexpr size_t max_to_be_modified = 8;

    template <typename instr_t, typename reg_t, typename = void>
    constexpr bool can_set_register = false;
    template <typename instr_t, typename reg_t>
    constexpr bool can_set_register<
        instr_t, reg_t,
        std::void_t<decltype(std::declval<instr_t>().set_register(
            std::declval<reg_t>()))>> = true;

    template <typename instr_t, typename = void>
    constexpr bool has_getset_fetch_offset = false;
    template <typename instr_t>
    constexpr bool has_getset_fetch_offset<
        instr_t,
        std::void_t<decltype(std::declval<instr_t>().get_fetch_offset(),
                             std::declval<instr_t>().set_fetch_offset(
                                 std::declval<typename aarch64::LDR_LITERAL::
                                                  offset_t>()))>> =
        std::is_same_v<decltype(std::declval<instr_t>().get_fetch_offset()),
                       typename aarch64::LDR_LITERAL::offset_t>;

    typedef std::initializer_list<std::pair<std::byte*, uint8_t>> move_info_t;
    typedef utils::type_sequence<aarch64::B, aarch64::BL, aarch64::BL,
                                 aarch64::CBZ, aarch64::CBNZ, aarch64::TBZ,
                                 aarch64::TBNZ>
        all_branches;
    typedef utils::type_sequence<
        aarch64::custom::LDR_ABS, aarch64::custom::LDRSW_ABS,
        aarch64::custom::LDRV32_ABS, aarch64::custom::LDRV64_ABS,
        aarch64::custom::LDRV128_ABS>
        custom_far_loads;
    typedef utils::type_sequence<
        aarch64::LDR_LITERAL, aarch64::LDRSW_LITERAL, aarch64::LDRV_LITERAL,
        aarch64::custom::PUSH,
        aarch64::custom::POP>::template merge<custom_far_loads>
        all_to_be_modified;
    template <typename seq>
    using pointer_variant_t = typename seq::template apply<
        std::add_pointer_t>::template to<std::variant>;

    struct to_be_modified : pointer_variant_t<all_to_be_modified>
    {
      typedef pointer_variant_t<all_to_be_modified> base;
      using base::base;

      void patch_register(aarch64::xregisters reg)
      {
        std::visit(
            [reg](auto* pinstr)
            {
              typedef std::remove_pointer_t<decltype(pinstr)> instr_t;

              if constexpr (can_set_register<instr_t, aarch64::xregisters>)
                pinstr->set_register(reg);
              else if constexpr (can_set_register<instr_t, aarch64::reg_t>)
                pinstr->set_register(static_cast<aarch64::reg_t>(reg));
              else
                static_assert(utils::always_false<instr_t>,
                              "invalid \"to be modified\" instruction");
            },
            *this);
      }

      void move_back(move_info_t pairs)
      {
        std::visit(
            [&pairs](auto*& pinstr)
            {
              typedef std::remove_reference_t<decltype(pinstr)> instr_ptr;
              typedef std::remove_pointer_t<instr_ptr>          instr_t;
              auto* instr_address = reinterpret_cast<std::byte*>(pinstr);

              for (const auto [start_address, erased_size] : pairs)
              {
                if (reinterpret_cast<std::byte*>(pinstr) > start_address)
                  instr_address -= erased_size;
              }

              if constexpr (has_getset_fetch_offset<instr_t>)
              {
                const ptrdiff_t distance =
                    reinterpret_cast<std::byte*>(pinstr) - instr_address;
                pinstr = reinterpret_cast<instr_ptr>(instr_address);
                pinstr->set_fetch_offset(pinstr->get_fetch_offset() - distance);
              }
              else
                pinstr = reinterpret_cast<instr_ptr>(instr_address);
            },
            *this);
      }
    };

    struct to_be_modified_list
        : utils::static_vector<to_be_modified, max_to_be_modified>
    {
      std::bitset<32> registers_found{};

      void fix_moved(move_info_t pairs)
      {
        for (to_be_modified& tbm : *this)
          tbm.move_back(pairs);
      }

      std::optional<aarch64::xregisters> process_all(std::byte* target)
      {
        using namespace aarch64;
        if (empty())
          return std::nullopt;
        // note: the order is intentional. We start off with the caller-saved
        // temporary registers and if we find an unused one we may remove the
        // extra push/pop for PC handling as its saved by the caller. Otherwise
        // we fallback to the callee saved register where we manually backup the
        // original value.
        const std::array available_registers = { X9,  X10, X11, X12, X13,
                                                 X14, X15, X0,  X1,  X2,
                                                 X3,  X4,  X5,  X6,  X7 };
        const auto       result              = std::find_if_not(
            available_registers.begin(), available_registers.end(),
            [this](reg_t reg) { return registers_found[reg]; });
        if (result == available_registers.end())
          throw(exceptions::unused_register_not_found(target));
        for (to_be_modified& tbm : *this)
          tbm.patch_register(static_cast<xregisters>(*result));
        return static_cast<xregisters>(*result);
      }
    };

    struct branch_destination
    {
      static constexpr size_t max_references = 5;

      struct reference : pointer_variant_t<all_branches>
      {
        typedef pointer_variant_t<all_branches> base;
        using base::base;

        void move_back(
            std::initializer_list<std::pair<std::byte*, uint8_t>> pairs)
        {
          std::visit(
              [&pairs](auto*& pinstr)
              {
                typedef std::remove_reference_t<decltype(pinstr)> instr_ptr;
                auto* instr_address = reinterpret_cast<std::byte*>(pinstr);

                for (const auto [start_address, erased_size] : pairs)
                {
                  if (reinterpret_cast<std::byte*>(pinstr) > start_address)
                    instr_address -= erased_size;
                }

                pinstr = reinterpret_cast<instr_ptr>(instr_address);
              },
              *this);
        }

        void patch_offset(std::byte* target, std::byte* dest)
        {
          std::visit(
              [target, dest](auto* pinstr)
              {
                typedef std::remove_pointer_t<decltype(pinstr)> instr_t;
                typedef typename instr_t::offset_t              offset_t;
                const ptrdiff_t relative_address =
                    dest - reinterpret_cast<std::byte*>(pinstr);
                if (abs(relative_address) >
                        (std::numeric_limits<offset_t>::max)() ||
                    !instr_t::offset_fits(relative_address))
                  throw(
                      exceptions::instructions_in_branch_handling_fail(target));
                pinstr->set_offset(relative_address);
              },
              *this);
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

      // accepts `{ start_address, erased_size }` pairs
      void fix_moved_references(std::byte* trampoline, move_info_t pairs)
      {
        for (branch_destination& entry : *this)
        {
          std::byte* dest = entry.dest;

          for (const auto [start_address, erased_size] : pairs)
          {
            if (trampoline <= entry.dest &&
                entry.dest < (trampoline + memory_slot_size) &&
                entry.dest > start_address)
              dest -= erased_size;
          }

          entry.dest = dest;

          for (auto& ref : entry.references)
            ref.move_back(pairs);
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
            ref.patch_offset(target, entry.dest);
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

      bool in_branch() const noexcept
      {
        // if an entry's destination is left as null it means that it's within
        // the overriden area of the target function and we haven't reached it
        // yet to set it. Therefore this determines whether there is a branch
        // destination ahead (inside the trampoline).
        return std::find_if(begin(), end(),
                            [](const branch_destination& entry)
                            { return !entry.dest; }) != end();
      }
    };

    struct trampoline_context
    {
      struct session;
      typedef std::bitset<memory_slot_size> buffer_bitset_t;
      typedef std::optional<uint8_t>        pc_handling_begin_t;
      typedef utils::static_vector<std::pair<uint8_t, uint8_t>, 8> positions_t;

      bool                    finished    = false;
      const uint8_t           size_needed = 0;
      std::bitset<32>         registers_found{};
      buffer_bitset_t         bytes_used{};
      uint8_t                 last_unused_pos = 0;
      uint8_t                 available_size  = memory_slot_size;
      positions_t             positions{};
      branch_destination_list branch_list{};
      to_be_modified_list     tbm_list{};

      struct
      {
        pc_handling_begin_t startup_location = std::nullopt;
        bool                active           = false;

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

      bool is_in_overriden_area(std::byte* branch_dest) const
      {
        return is_in_overriden_area(reinterpret_cast<uintptr_t>(branch_dest));
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
      static constexpr bool should_be_modified =
          all_to_be_modified::template has<utils::remove_cvref_t<T>>;
      template <typename T>
      static constexpr bool is_custom_instruction =
          std::is_base_of_v<aarch64::INSTRUCTION, utils::remove_cvref_t<T>> &&
          !is_branch<T> && !should_be_modified<T>;

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

      template <typename T, std::enable_if_t<should_be_modified<T>, size_t> = 0>
      void add_instruction(T&& instr)
      {
        prepare_buffer();
        new (&buffer[copy_size]) auto(instr);
        ctx.tbm_list.emplace_back(
            reinterpret_cast<instr_ptr_t<T>>(ctx.trampoline.end + copy_size));
        copy_size += sizeof(utils::remove_cvref_t<T>);
      }

      template <typename T,
                std::enable_if_t<is_custom_instruction<T>, size_t> = 0>
      void add_instruction(T&& instr)
      {
        constexpr auto instr_size = sizeof(utils::remove_cvref_t<T>);
        prepare_buffer();
        new (&buffer[copy_size]) auto(instr);
        copy_size += instr_size;
      }

      void add_instruction(const cs_insn& instr)
      {
        prepare_buffer();
        memcpy(&buffer[copy_size], instr.bytes, instr.size);
        copy_size += instr.size;
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
      auto session = ctx.create_session(aarch64, instr);

      if (aarch64.modifies_register(instr, AArch64_REG_SP) &&
          ctx.pc_handling_context.active)
      {
        session.add_instruction(aarch64::custom::POP());
        session.add_instruction(instr);
        utils_assert(aarch64.is_branch(instr),
                     "An instruction that modifies both the SP and the PC was "
                     "unexpected");
      }
      else if (aarch64.is_relative_branch(instr))
      {
        assert(aarch64.get_immediate(instr.detail->aarch64).has_value());
        const auto imm = aarch64.get_immediate(instr.detail->aarch64).value();
        const ptrdiff_t relative_address = imm - ctx.trampoline.uend;
      }
    }
  }
} // namespace alterhook

#pragma GCC diagnostic pop
