/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#pragma GCC visibility push(hidden)

#define add_asserter_impl(expr, optype, bitcount, enumval)                     \
  if constexpr (optype##_format == enumval)                                    \
    utils_assert(expr, #optype " too large to fit in " #bitcount " bits");

#define add_asserter(pair, extradata)                                          \
  __utils_call(add_asserter_impl, (utils_expand extradata, utils_expand pair))

#define generate_asserters(expr, optype, ...)                                  \
  utils_map_ud(add_asserter, (expr, optype), __VA_ARGS__)

namespace alterhook::aarch64
{
  // clang-format off
  enum reg_t
  {
    W0  = 0,  W1  = 1,  W2  = 2,  W3  = 3,  W4  = 4,
    W5  = 5,  W6  = 6,  W7  = 7,  W8  = 8,  W9  = 9,
    W10 = 10, W11 = 11, W12 = 12, W13 = 13, W14 = 14,
    W15 = 15, W16 = 16, W17 = 17, W18 = 18, W19 = 19,
    W20 = 20, W21 = 21, W22 = 22, W23 = 23, W24 = 24,
    W25 = 25, W26 = 26, W27 = 27, W28 = 28, W29 = 29,
    W30 = 30,
    X0 = W0, X1 = W1, X2 = W2, X3 = W3, X4 = W4,
    X5 = W5, X6 = W6, X7 = W7, X8 = W8, X9 = W9,
    X10 = W10, X11 = W11, X12 = W12, X13 = W13, X14 = W14,
    X15 = W15, X16 = W16, X17 = W17, X18 = W18, X19 = W19,
    X20 = W20, X21 = W21, X22 = W22, X23 = W23, X24 = W24,
    X25 = W25, X26 = W26, X27 = W27, X28 = W28, X29 = W29,
    X30 = W30
  };

  enum class offset_type
  {
    imm26_0, imm19_5, imm14_5
  };

  enum class register_type
  {
    reg5_0, reg5_5
  };

  enum class size_type
  {
    size_31, size_30, size2_30
  };

  enum class offset_pad_type
  {
    none, twelve
  };

  enum class register_size
  {
    word, dword, qword
  };

  // clang-format on

  struct INSTRUCTION
  {
    uint32_t instr = 0;

    INSTRUCTION() = default;

    INSTRUCTION(uint32_t instr) : instr(instr) {}
  };

  namespace templates
  {
    template <typename offset_format_t, typename base = INSTRUCTION>
    struct offset_operand : base
    {
      static constexpr offset_type offset_format = offset_format_t::value;
      static constexpr uint32_t    offset_mask =
          offset_format == offset_type::imm26_0   ? 0x3'FF'FF'FF
             : offset_format == offset_type::imm19_5 ? 0x7'FF'FF
             : offset_format == offset_type::imm14_5 ? 0x3F'FF
                                                     : 0;
      static constexpr uint32_t offset_shift =
          offset_format == offset_type::imm19_5 ||
                  offset_format == offset_type::imm14_5
              ? 5
              : 0;
      typedef std::conditional_t<offset_format == offset_type::imm26_0 ||
                                     offset_format == offset_type::imm19_5,
                                 int32_t, int16_t>
          offset_t;

      template <typename... types>
      offset_operand(uint32_t opcode, offset_t offset, types&&... args)
          : base(opcode | (static_cast<uint32_t>(offset >> 2) << offset_shift),
                 std::forward<types>(args)...)
      {
        offset_assert(offset);
      }

      static void offset_assert(offset_t offset)
      {
        generate_asserters(llabs(offset >> 2) < (offset_mask >> 1), offset,
                           (26, offset_type::imm26_0),
                           (19, offset_type::imm19_5),
                           (14, offset_type::imm14_5));
      }

      void set_offset(offset_t offset)
      {
        offset_assert(offset);
        base::instr &= ~(offset_mask << offset_shift);
        base::instr |= ((offset >> 2) << offset_shift);
      }
    };

    template <typename base = INSTRUCTION>
    struct condition_operand : base
    {
      static constexpr uint32_t condition_mask = 0xF;

      template <typename... types>
      condition_operand(uint32_t opcode, uint8_t cond, types&&... args)
          : base(opcode | static_cast<uint32_t>(cond),
                 std::forward<types>(args)...)
      {
        utils_assert(cond <= condition_mask,
                     "condition value too large to fit in 4 bits");
      }

      void set_condition(uint8_t cond)
      {
        utils_assert(cond <= condition_mask,
                     "condition value too large to fit in 4 bits");
        base::instr &= ~condition_mask;
        base::instr |= cond;
      }
    };

    template <typename register_format_t, typename base = INSTRUCTION>
    struct register_operand : base
    {
      static constexpr register_type register_format = register_format_t::value;
      static constexpr uint32_t      register_mask   = 0x1F;
      static constexpr uint32_t      register_shift =
          register_format == register_type::reg5_5 ? 5 : 0;

      template <typename... types>
      register_operand(uint32_t opcode, uint8_t reg, types&&... args)
          : base(opcode | (static_cast<uint32_t>(reg) << register_shift),
                 std::forward<types>(args)...)
      {
        utils_assert(reg < register_mask,
                     "register value too large to fit in 5 bits");
      }

      void set_register(uint8_t reg)
      {
        utils_assert(reg < register_mask,
                     "register value too large to fit in 5 bits");
        base::instr &= ~(register_mask << register_shift);
        base::instr |= (static_cast<uint32_t>(reg) << register_shift);
      }
    };

    template <typename size_format_t, typename base = INSTRUCTION>
    struct size_operand : base
    {
      static constexpr size_type size_format = size_format_t::value;
      static constexpr uint32_t  size_mask =
          size_format == size_type::size2_30 ? 0b11 : 1;
      static constexpr uint32_t size_shift =
          size_format == size_type::size_31 ? 31 : 30;

      template <typename... types>
      size_operand(uint32_t opcode, register_size size, types&&... args)
          : base(opcode | (static_cast<uint32_t>(size) << size_shift),
                 std::forward<types>(args)...)
      {
        if constexpr (size_mask == 1)
          utils_assert(size != register_size::qword,
                       "size cannot be qword on this instruction");
      }

      void set_size(register_size size)
      {
        if constexpr (size_mask == 1)
          utils_assert(size != register_size::qword,
                       "size cannot be qword on this instruction");

        base::instr &= ~(size_mask << size_shift);
        base::instr |= (static_cast<uint32_t>(size) << size_shift);
      }
    };

    template <typename base = INSTRUCTION>
    struct bit_pos_operand : base
    {
      static constexpr uint32_t bit_pos_mask1  = 0x1F;
      static constexpr uint32_t bit_pos_mask2  = 1;
      static constexpr uint32_t bit_pos_shift1 = 19;
      static constexpr uint32_t bit_pos_shift2 = 31;

      template <typename... types>
      bit_pos_operand(uint32_t opcode, uint8_t pos, types&&... args)
          : base(opcode | ((pos & bit_pos_mask1) << bit_pos_shift1) |
                     ((pos >> 5) << bit_pos_shift2),
                 std::forward<types>(args)...)
      {
        utils_assert(pos <= 0x3F, "bit position too large to fit in 6 bits");
      }

      void set_bit_position(uint8_t pos)
      {
        utils_assert(pos <= 0x3F, "bit position too large to fit in 6 bits");
        base::instr &= ~((bit_pos_mask1 << bit_pos_shift1) |
                         (bit_pos_mask2 << bit_pos_shift2));
        base::instr |= (((pos & bit_pos_mask1) << bit_pos_shift1) |
                        ((pos >> 5) << bit_pos_shift2));
      }
    };

    template <typename offset_pad_num_t, typename base = INSTRUCTION>
    struct splited_offset_operand : base
    {
      static constexpr offset_pad_type offset_pad_num = offset_pad_num_t::value;
      static constexpr uint32_t        offset_max     = 0x1F'FF'FF;
      static constexpr uint32_t        offset_maskhi  = 0x7'FF'FF;
      static constexpr uint32_t        offset_masklo  = 0b11;
      static constexpr uint32_t        offset_shifthi = 5;
      static constexpr uint32_t        offset_shiftlo = 29;
      static constexpr uint32_t        offset_pad =
          offset_pad_num == offset_pad_type::twelve ? 12 : 0;

      template <typename... types>
      splited_offset_operand(uint32_t opcode, int32_t offset, types&&... args)
          : base(opcode |
                     ((static_cast<uint32_t>(offset >> offset_pad) &
                       offset_masklo)
                      << offset_shiftlo) |
                     (static_cast<uint32_t>(offset >> (offset_pad + 2))
                      << offset_shifthi),
                 std::forward<types>(args)...)
      {
        utils_assert(llabs(offset >> offset_pad) < (offset_max >> 1),
                     "offset too large to fit in 21 bits");
      }

      void set_offset(int32_t offset)
      {
        utils_assert(llabs(offset >> offset_pad) < (offset_max >> 1),
                     "offset too large to fit in 21 bits");
        base::instr &= ~((offset_masklo << offset_shiftlo) |
                         (offset_maskhi << offset_shifthi));
        base::instr |=
            (((static_cast<uint32_t>(offset >> offset_pad) & offset_masklo)
              << offset_shiftlo) |
             (static_cast<uint32_t>(offset >> (offset_pad + 2))
              << offset_shifthi));
      }
    };
  } // namespace templates

  struct B
      : utils::properties<utils::property<templates::offset_operand,
                                          utils::val<offset_type::imm26_0>>>
  {
    static constexpr uint32_t opcode = 0x14'00'00'00;

    B(int32_t offset = 0) : base(opcode, offset) {}
  };

  struct BL
      : utils::properties<utils::property<templates::offset_operand,
                                          utils::val<offset_type::imm26_0>>>
  {
    static constexpr uint32_t opcode = 0x94'00'00'00;

    BL(int32_t offset = 0) : base(opcode, offset) {}
  };

  struct B_cond
      : utils::properties<utils::property<templates::condition_operand>,
                          utils::property<templates::offset_operand,
                                          utils::val<offset_type::imm19_5>>>
  {
    static constexpr uint32_t opcode = 0x54'00'00'00;

    B_cond(int32_t offset = 0, uint8_t cond = 0) : base(opcode, offset, cond) {}
  };

  struct CBZ
      : utils::properties<utils::property<templates::size_operand,
                                          utils::val<size_type::size_31>>,
                          utils::property<templates::register_operand,
                                          utils::val<register_type::reg5_0>>,
                          utils::property<templates::offset_operand,
                                          utils::val<offset_type::imm19_5>>>
  {
    static constexpr uint32_t opcode = 0x34'00'00'00;

    CBZ(int32_t offset = 0, reg_t reg = W0,
        register_size size = register_size::word)
        : base(opcode, offset, reg, size)
    {
    }
  };

  struct CBNZ
      : utils::properties<utils::property<templates::size_operand,
                                          utils::val<size_type::size_31>>,
                          utils::property<templates::register_operand,
                                          utils::val<register_type::reg5_0>>,
                          utils::property<templates::offset_operand,
                                          utils::val<offset_type::imm19_5>>>
  {
    static constexpr uint32_t opcode = 0x35'00'00'00;

    CBNZ(int32_t offset = 0, reg_t reg = W0,
         register_size size = register_size::word)
        : base(opcode, offset, reg, size)
    {
    }
  };

  struct TBZ
      : utils::properties<utils::property<templates::bit_pos_operand>,
                          utils::property<templates::register_operand,
                                          utils::val<register_type::reg5_0>>,
                          utils::property<templates::offset_operand,
                                          utils::val<offset_type::imm14_5>>>
  {
    static constexpr uint32_t opcode = 0x36'00'00'00;

    TBZ(int16_t offset = 0, reg_t reg = W0, uint8_t bit_pos = 0)
        : base(opcode, offset, reg, bit_pos)
    {
    }
  };

  struct TBNZ
      : utils::properties<utils::property<templates::bit_pos_operand>,
                          utils::property<templates::register_operand,
                                          utils::val<register_type::reg5_0>>,
                          utils::property<templates::offset_operand,
                                          utils::val<offset_type::imm14_5>>>
  {
    static constexpr uint32_t opcode = 0x37'00'00'00;

    TBNZ(int16_t offset = 0, reg_t reg = W0, uint8_t bit_pos = 0)
        : base(opcode, offset, reg, bit_pos)
    {
    }
  };

  struct LDR
      : utils::properties<utils::property<templates::size_operand,
                                          utils::val<size_type::size_30>>,
                          utils::property<templates::register_operand,
                                          utils::val<register_type::reg5_0>>,
                          utils::property<templates::offset_operand,
                                          utils::val<offset_type::imm19_5>>>
  {
    static constexpr uint32_t opcode = 0x18'00'00'00;

    LDR(int32_t offset = 0, reg_t reg = W0,
        register_size size = register_size::word)
        : base(opcode, offset, reg, size)
    {
    }
  };

  struct LDRSW
      : utils::properties<utils::property<templates::register_operand,
                                          utils::val<register_type::reg5_0>>,
                          utils::property<templates::offset_operand,
                                          utils::val<offset_type::imm19_5>>>
  {
    static constexpr uint32_t opcode = 0x98'00'00'00;

    LDRSW(int32_t offset = 0, reg_t reg = W0) : base(opcode, offset, reg) {}
  };

  struct LDRV
      : utils::properties<utils::property<templates::size_operand,
                                          utils::val<size_type::size2_30>>,
                          utils::property<templates::register_operand,
                                          utils::val<register_type::reg5_0>>,
                          utils::property<templates::offset_operand,
                                          utils::val<offset_type::imm19_5>>>
  {
    static constexpr uint32_t opcode = 0x1C'00'00'00;

    LDRV(int32_t offset = 0, reg_t reg = W0,
         register_size size = register_size::word)
        : base(opcode, offset, reg, size)
    {
    }
  };

  struct ADR
      : utils::properties<utils::property<templates::register_operand,
                                          utils::val<register_type::reg5_0>>,
                          utils::property<templates::splited_offset_operand,
                                          utils::val<offset_pad_type::none>>>
  {
    static constexpr uint32_t opcode = 0x10'00'00'00;

    ADR(int32_t offset = 0, reg_t reg = W0) : base(opcode, offset, reg) {}
  };

  struct ADRP
      : utils::properties<utils::property<templates::register_operand,
                                          utils::val<register_type::reg5_0>>,
                          utils::property<templates::splited_offset_operand,
                                          utils::val<offset_pad_type::twelve>>>
  {
    static constexpr uint32_t opcode = 0x90'00'00'00;

    ADRP(int32_t offset = 0, reg_t reg = W0) : base(opcode, offset, reg) {}
  };

  struct BR
      : utils::properties<utils::property<templates::register_operand,
                                          utils::val<register_type::reg5_5>>>
  {
    static constexpr uint32_t opcode = 0xD6'1F'00'00;

    BR(reg_t reg = W0) : base(opcode, reg) {}
  };
} // namespace alterhook::aarch64

#pragma GCC visibility pop