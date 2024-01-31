/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once

#if utils_clang
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wswitch"
  #pragma clang diagnostic ignored "-Wmissing-braces"
#endif

#pragma GCC visibility push(hidden)

// all of the following are used to make asm generation look nicer than a mess
// of hardcoded constants
namespace alterhook
{
  enum reg_t : uint8_t
  {
    r0  = 0,
    r1  = 1,
    r2  = 2,
    r3  = 3,
    r4  = 4,
    r5  = 5,
    r6  = 6,
    r7  = 7,
    r8  = 8,
    r9  = 9,
    r10 = 10,
    r11 = 11,
    r12 = 12,
    r13 = 13,
    r14 = 14,
    r15 = 15,
    sp  = r13,
    lr  = r14,
    pc  = r15
  };

  enum class instruction_set : uint8_t
  {
    ARM,
    THUMB,
    THUMB2,
    UNKNOWN
  };

  namespace helpers
  {
    template <size_t last_index, typename instr_t, typename operand_t,
              size_t... indexes>
    static void patch_operand_impl(instruction_set            instr_set,
                                   const cs_operand_encoding& encoding,
                                   instr_t& instr, operand_t value,
                                   std::index_sequence<indexes...>) noexcept
    {
      const auto *sizes_begin = encoding.sizes,
                 *sizes_end   = encoding.sizes + encoding.operand_pieces_count;
      const uint8_t operand_size =
          std::accumulate(sizes_begin, sizes_end, uint8_t{});
      uint8_t current_size = 0;

      const auto do_patch = [&](const size_t i, const uint32_t op_part)
      {
        const uint8_t op_index = instr_set == instruction_set::THUMB2
                                     ? encoding.indexes[i] < 16
                                           ? encoding.indexes[i] + 16
                                           : encoding.indexes[i] - 16
                                     : encoding.indexes[i];

        const uint32_t mask  = (1u << encoding.sizes[i]) - 1;
        instr               &= ~(mask << op_index);
        instr               |= op_part << op_index;
      };
      const auto process = [&](const size_t i) -> bool
      {
        if (encoding.operand_pieces_count < (i + 1))
          return false;
        current_size        += encoding.sizes[i];
        const uint32_t mask  = (1u << encoding.sizes[i]) - 1;
        const uint32_t op_part =
            (value >> (operand_size - current_size)) & mask;

        do_patch(i, op_part);
        return true;
      };

      if ((!process(indexes) || ...) ||
          encoding.operand_pieces_count != (last_index + 1))
        return;

      const uint32_t mask    = (1u << encoding.sizes[last_index]) - 1;
      const uint32_t op_part = value & mask;
      do_patch(last_index, op_part);
    }
  } // namespace helpers

  template <size_t max_pieces, typename instr_t, typename operand_t>
  static auto patch_operand(instruction_set            instr_set,
                            const cs_operand_encoding& encoding, instr_t instr,
                            operand_t value) noexcept
      -> std::enable_if_t<std::is_unsigned_v<instr_t> &&
                              (std::is_integral_v<operand_t> ||
                               std::is_enum_v<operand_t>),
                          instr_t>
  {
    helpers::patch_operand_impl<max_pieces - 1>(
        instr_set, encoding, instr, value,
        std::make_index_sequence<max_pieces - 1>());
    return instr;
  }

  constexpr std::array offset_encodings = {
    cs_operand_encoding{1,  { 0 },                 { 12 }             },
    cs_operand_encoding{ 1, { 0 },                 { 12 }             },
    cs_operand_encoding{ 2, { 8, 0 },              { 4, 4 }           },
    cs_operand_encoding{ 1, { 0 },                 { 8 }              },
    cs_operand_encoding{ 3, { 26, 12, 0 },         { 1, 3, 8 }        },
    cs_operand_encoding{ 1, { 0 },                 { 8 }              },
    cs_operand_encoding{ 1, { 0 },                 { 8 }              },
    cs_operand_encoding{ 1, { 0 },                 { 24 }             },
    cs_operand_encoding{ 5, { 26, 13, 11, 16, 0 }, { 1, 1, 1, 10, 11 }},
    cs_operand_encoding{ 1, { 0 },                 { 8 }              },
    cs_operand_encoding{ 1, { 0 },                 { 11 }             },
    cs_operand_encoding{ 2, { 8, 0 },              { 12, 4 }          },
    cs_operand_encoding{ 2, { 0, 24 },             { 24, 1 }          },
    cs_operand_encoding{ 5, { 26, 13, 11, 16, 1 }, { 1, 1, 1, 10, 10 }}
  };

  constexpr std::array signbit_encodings = {
    cs_operand_encoding{0,  {},     {}   },
    cs_operand_encoding{ 1, { 23 }, { 1 }},
    cs_operand_encoding{ 1, { 23 }, { 1 }},
    cs_operand_encoding{ 1, { 23 }, { 1 }},
    cs_operand_encoding{ 0, {},     {}   },
    cs_operand_encoding{ 0, {},     {}   },
    cs_operand_encoding{ 0, {},     {}   },
    cs_operand_encoding{ 0, {},     {}   },
    cs_operand_encoding{ 0, {},     {}   },
    cs_operand_encoding{ 0, {},     {}   },
    cs_operand_encoding{ 0, {},     {}   },
    cs_operand_encoding{ 0, {},     {}   },
    cs_operand_encoding{ 0, {},     {}   },
    cs_operand_encoding{ 0, {},     {}   }
  };

  constexpr std::array register_encodings = {
    cs_operand_encoding{1,  { 16 }, { 4 }},
    cs_operand_encoding{ 1, { 12 }, { 4 }},
    cs_operand_encoding{ 1, { 0 },  { 4 }},
    cs_operand_encoding{ 1, { 8 },  { 4 }},
    cs_operand_encoding{ 1, { 8 },  { 3 }}
  };

  // all of the bellow map to the encodings above
  enum class offset_type
  {
    uimm12_0,
    pimm12_0_23,
    pimm4_8_4_0_23, // double piece + sign bit
    pimm8_0_pad2,
    uimm1_26_3_12_8_0,
    uimm8_0_pad2,
    uimm8_0,
    imm24_0_pad2,
    imm1_26_1_13_1_11_10_16_11_0_pad1,
    imm8_0,
    imm11_0,
    uimm12_8_4_0,
    imm24_0_1_24,
    imm1_26_1_13_1_11_10_16_10_1_pad2
  };

  enum class register_type
  {
    reg16,
    reg12,
    reg0,
    reg8,
    reg3_8
  };

  enum class reglist_type
  {
    full,
    lr_12,
    lr_7,
    pc_7
  };

  namespace templates
  {
    template <typename T, typename offset_t, typename = void>
    inline constexpr bool has_custom_convert_offset = false;
    template <typename T, typename offset_t>
    inline constexpr bool has_custom_convert_offset<
        T, offset_t,
        std::void_t<decltype(T::convert_offset(std::declval<offset_t>()))>> =
        true;

    template <typename T, typename offset_t, typename = void>
    inline constexpr bool has_custom_offset_fits = false;
    template <typename T, typename offset_t>
    inline constexpr bool has_custom_offset_fits<
        T, offset_t,
        std::void_t<decltype(T::offset_fits(std::declval<offset_t>()))>> =
        std::is_same_v<decltype(T::offset_fits(std::declval<offset_t>())),
                       bool>;

    template <typename T, typename offset_t, typename = void>
    inline constexpr bool has_custom_assert_offset = false;
    template <typename T, typename offset_t>
    inline constexpr bool has_custom_assert_offset<
        T, offset_t,
        std::void_t<decltype(T::assert_offset(std::declval<offset_t>()))>> =
        true;

    template <typename customcls, typename offset_format_t, typename base>
    struct customized_offset_operand : base
    {
      typedef utils::type_sequence<
          uint16_t, int16_t, int16_t, int16_t, uint16_t, uint16_t, uint8_t,
          int32_t, int32_t, int8_t, int16_t, uint16_t, int32_t, int32_t>
                                  offset_types;
      static constexpr std::array offset_pads       = { 0, 0, 0, 2, 0, 2, 0,
                                                        2, 1, 1, 1, 0, 1, 2 };
      static constexpr std::array offset_max_values = {
        0xFFF,      0xFFF,      0xFF, 0xFF,  0xFFF,   0xFF,         0xFF,
        0xFF'FF'FF, 0xFF'FF'FF, 0xFF, 0x7FF, 0xFF'FF, 0x1'FF'FF'FF, 0x7F'FF'FF
      };
      static constexpr offset_type offset_format = offset_format_t::value;
      static constexpr cs_operand_encoding offset_encoding =
          offset_encodings[utils::to_underlying(offset_format)];
      static constexpr cs_operand_encoding signbit_encoding =
          signbit_encodings[utils::to_underlying(offset_format)];
      static constexpr size_t offset_max =
          offset_max_values[utils::to_underlying(offset_format)];
      static constexpr size_t offset_pad =
          offset_pads[utils::to_underlying(offset_format)];
      typedef utils::type_at_t<utils::to_underlying(offset_format),
                               offset_types>
          offset_t;

      static typename base::instr_t convert_offset(offset_t offset) noexcept
      {
        if constexpr (has_custom_convert_offset<customcls, offset_t>)
          return customcls::convert_offset(offset);
        else if constexpr (signbit_encoding.operand_pieces_count == 1)
          return (abs(offset) >> offset_pad);
        else
          return (offset >> offset_pad);
      }

      static bool offset_fits(offset_t offset) noexcept
      {
        if constexpr (has_custom_offset_fits<customcls, offset_t>)
          return customcls::offset_fits(offset);
        else if constexpr (std::is_signed_v<offset_t> &&
                           signbit_encoding.operand_pieces_count == 0)
          return convert_offset(abs(offset)) <= (offset_max >> 1);
        else
          return convert_offset(offset) <= offset_max;
      }

      static void assert_offset(offset_t offset) noexcept
      {
        if constexpr (has_custom_assert_offset<customcls, offset_t>)
          customcls::assert_offset(offset);
        else if constexpr (offset_format == offset_type::imm24_0_1_24)
          utils_assert(offset_fits(offset),
                       "offset too large to fit in 25 bits");
        else if constexpr (utils::any_of(
                               offset_format, offset_type::imm24_0_pad2,
                               offset_type::imm1_26_1_13_1_11_10_16_11_0_pad1))
          utils_assert(offset_fits(offset),
                       "offset too large to fit in 24 bits");
        else if constexpr (offset_format ==
                           offset_type::imm1_26_1_13_1_11_10_16_10_1_pad2)
          utils_assert(offset_fits(offset),
                       "offset too large to fit in 23 bits");
        else if constexpr (offset_format == offset_type::uimm12_8_4_0)
          utils_assert(offset_fits(offset),
                       "offset too large to fit in 16 bits");
        else if constexpr (utils::any_of(offset_format, offset_type::uimm12_0,
                                         offset_type::pimm12_0_23,
                                         offset_type::uimm1_26_3_12_8_0))
          utils_assert(offset_fits(offset),
                       "offset too large to fit in 12 bits");
        else if constexpr (offset_format == offset_type::imm11_0)
          utils_assert(offset_fits(offset),
                       "offset too large to fit in 11 bits");
        else if constexpr (utils::any_of(
                               offset_format, offset_type::pimm4_8_4_0_23,
                               offset_type::pimm8_0_pad2,
                               offset_type::uimm8_0_pad2, offset_type::uimm8_0,
                               offset_type::imm8_0))
          utils_assert(offset_fits(offset),
                       "offset too large to fit in 8 bits");
      }

      template <typename... types>
      customized_offset_operand(typename base::instr_t opcode, offset_t offset,
                                types&&... rest)
          : base((assert_offset(offset),
                  patch_operand<5>(base::instr_set, offset_encoding, opcode,
                                   convert_offset(offset)) |
                      (signbit_encoding.operand_pieces_count == 1
                           ? patch_operand<1>(
                                 base::instr_set, signbit_encoding, opcode,
                                 static_cast<typename base::instr_t>(offset >=
                                                                     0))
                           : 0)),
                 std::forward<types>(rest)...)
      {
      }

      void set_offset(offset_t offset) noexcept
      {
        assert_offset(offset);
        base::instr = patch_operand<5>(base::instr_set, offset_encoding,
                                       base::instr, convert_offset(offset));

        if constexpr (signbit_encoding.operand_pieces_count == 1)
          base::instr = patch_operand<1>(
              base::instr_set, signbit_encoding, base::instr,
              static_cast<typename base::instr_t>(offset >= 0));
      }
    };

    template <typename offset_format_t, typename base>
    using offset_operand =
        customized_offset_operand<void, offset_format_t, base>;

    template <typename register_format_t, typename base>
    struct register_operand : base
    {
      static constexpr std::array    register_max_values = { 0b1111, 0b1111,
                                                             0b1111, 0b1111,
                                                             0b111 };
      static constexpr register_type register_format = register_format_t::value;
      static constexpr cs_operand_encoding register_encoding =
          register_encodings[utils::to_underlying(register_format)];
      static constexpr size_t register_max_value =
          register_max_values[utils::to_underlying(register_format)];

      static bool register_fits(uint8_t reg) noexcept
      {
        return reg <= register_max_value;
      }

      static void assert_register([[maybe_unused]] uint8_t reg) noexcept
      {
        if constexpr (register_format == register_type::reg3_8)
          utils_assert(register_fits(reg),
                       "register value too large to fit in 3 bits");
        else
          utils_assert(register_fits(reg),
                       "register value too large to fit in 4 bits");
      }

      template <typename... types>
      register_operand(typename base::instr_t opcode, uint8_t reg,
                       types&&... rest)
          : base((assert_register(reg),
                  patch_operand<2>(base::instr_set, register_encoding, opcode,
                                   reg)),
                 std::forward<types>(rest)...)
      {
      }

      void set_register(uint8_t reg) noexcept
      {
        assert_register(reg);
        base::instr = patch_operand<2>(base::instr_set, register_encoding,
                                       base::instr, reg);
      }
    };

    template <typename reglist_format_t, typename base>
    struct reglist_operand : base
    {
      static constexpr reglist_type reglist_format = reglist_format_t::value;
      static constexpr std::array   prohibited_registers_list = {
        std::bitset<16>(), std::bitset<16>(0xA0'00), std::bitset<16>(0xBF'00),
        std::bitset<16>(0x7F'00)
      };
      static constexpr std::array masks = { 0xFF'FF, 0x5F'FF, 0x1FF, 0x1FF };
      static constexpr std::array special_registers = {
        std::pair{r0,  0},
        std::pair{ r0, 0},
        std::pair{ lr, 8},
        std::pair{ pc, 8}
      };
      static constexpr std::bitset<16> prohibited_registers =
          prohibited_registers_list[utils::to_underlying(reglist_format)];
      static constexpr uint16_t mask =
          masks[utils::to_underlying(reglist_format)];
      static constexpr std::pair special_register =
          special_registers[utils::to_underlying(reglist_format)];

      template <typename... types>
      reglist_operand(typename base::instr_t opcode, types&&... args)
          : base(opcode, std::forward<types>(args)...)
      {
      }

      void assert_register([[maybe_unused]] uint8_t reg)
      {
        utils_assert(!prohibited_registers[reg],
                     "register is prohibited in the instruction's reglist");
      }

      template <typename callable>
      bool handle_special_register(uint8_t reg, callable&& func)
      {
        if constexpr (special_register.second > 0)
        {
          if (reg != special_register.first)
            return false;

          func();
          return true;
        }
        return false;
      }

      uint8_t get_index(uint8_t reg) noexcept
      {
        if constexpr (special_register.second > 0)
        {
          if (reg == special_register.first)
            return special_register.second;
        }
        return reg;
      }

      void append(uint8_t reg) noexcept
      {
        assert_register(reg);
        base::instr |= 1 << get_index(reg);
      }

      void remove(uint8_t reg) noexcept
      {
        assert_register(reg);
        base::instr &= ~(1 << get_index(reg));
      }

      bool greatest(uint8_t reg) noexcept
      {
        assert_register(reg);
        return (1 << get_index(reg)) > (base::instr & mask);
      }
    };

    template <typename base>
    struct condition_operand : base
    {
      condition_operand(uint32_t opcode, CondCodes condition = ARMCC_AL)
          : base(opcode | (condition << 28))
      {
      }

      void set_condition(CondCodes condition) noexcept
      {
        base::instr &= ~(0b1111 << 28);
        base::instr |= (condition << 28);
      }

      CondCodes get_condition() noexcept
      {
        return CondCodes(base::instr >> 28);
      }
    };

    template <size_t instr_count>
    struct custom_instruction
    {
      typedef custom_instruction custom_instruction_tag;
      static constexpr size_t    instruction_count = instr_count;
    };

    template <size_t pad, size_t sbitpos = 23>
    struct xored_offset
    {
      static uint32_t convert_offset(int32_t offset) noexcept
      {
        offset            >>= pad;
        const uint32_t S    = (offset >> sbitpos) & 1,
                       I1   = (offset >> (sbitpos - 1)) & 1,
                       I2   = (offset >> (sbitpos - 2)) & 1;
        const uint32_t J1 = (I1 ^ 1) ^ S, J2 = (I2 ^ 1) ^ S;
        offset &= ~(0b11 << (sbitpos - 2));
        offset |= (((J1 << 1) | J2) << (sbitpos - 2));
        return offset;
      }
    };
  } // namespace templates

  namespace arm
  {
    template <typename base = void>
    struct INSTRUCTION
    {
      static_assert(std::is_same_v<base, void>,
                    "arm::INSTRUCTION is not allowed to have a base");
      static constexpr instruction_set instr_set = instruction_set::ARM;

      typedef uint32_t instr_t;

      instr_t instr;

      INSTRUCTION(instr_t instr) : instr(instr) {}
    };

    template <typename... types>
    using instruction_properties =
        utils::properties<utils::property<INSTRUCTION>, types...>;

    struct PUSH : instruction_properties<
                      utils::property<templates::condition_operand>,
                      utils::property<templates::register_operand,
                                      utils::val<register_type::reg12>>>
    {
      static constexpr uint32_t opcode = 0xE5'2D'00'04;

      PUSH(uint8_t reg, CondCodes condition = ARMCC_AL)
          : base(opcode, reg, condition)
      {
      }
    };

    struct PUSH_REGLIST : instruction_properties<
                              utils::property<templates::condition_operand>,
                              utils::property<templates::reglist_operand,
                                              utils::val<reglist_type::full>>>
    {
      static constexpr uint32_t opcode = 0xE9'2D'00'00;

      PUSH_REGLIST(CondCodes condition = ARMCC_AL) : base(opcode, condition) {}
    };

    struct POP : instruction_properties<
                     utils::property<templates::condition_operand>,
                     utils::property<templates::register_operand,
                                     utils::val<register_type::reg12>>>
    {
      static constexpr uint32_t opcode = 0xE4'9D'00'04;

      POP(uint8_t reg, CondCodes condition = ARMCC_AL)
          : base(opcode, reg, condition)
      {
      }
    };

    struct MOV : instruction_properties<
                     utils::property<templates::condition_operand>,
                     utils::property<templates::register_operand,
                                     utils::val<register_type::reg0>>,
                     utils::property<templates::register_operand,
                                     utils::val<register_type::reg12>>>
    {
      static constexpr uint32_t opcode = 0xE1'A0'00'00;

      MOV(uint8_t dest, uint8_t src, CondCodes condition = ARMCC_AL)
          : base(opcode, dest, src, condition)
      {
      }

      void set_destination_register(uint8_t reg)
      {
        property_at<3>::set_register(reg);
      }

      void set_source_register(uint8_t reg)
      {
        property_at<2>::set_register(reg);
      }

      void set_register(uint8_t reg)
      {
        set_destination_register(reg);
        set_source_register(reg);
      }
    };

    struct ADD : instruction_properties<
                     utils::property<templates::condition_operand>,
                     utils::property<templates::register_operand,
                                     utils::val<register_type::reg12>>,
                     utils::property<templates::register_operand,
                                     utils::val<register_type::reg16>>,
                     utils::property<templates::offset_operand,
                                     utils::val<offset_type::uimm12_0>>>
    {
      static constexpr uint32_t opcode = 0xE2'80'00'00;

      ADD(uint8_t dstreg, uint8_t srcreg, uint16_t offset,
          CondCodes condition = ARMCC_AL)
          : base(opcode, offset, srcreg, dstreg, condition)
      {
      }

      void set_destination_register(uint8_t reg) noexcept
      {
        property_at<2>::set_register(reg);
      }

      void set_source_register(uint8_t reg) noexcept
      {
        property_at<3>::set_register(reg);
      }

      void set_register(uint8_t reg) noexcept
      {
        set_destination_register(reg);
        set_source_register(reg);
      }
    };

    struct SUB : instruction_properties<
                     utils::property<templates::condition_operand>,
                     utils::property<templates::register_operand,
                                     utils::val<register_type::reg12>>,
                     utils::property<templates::register_operand,
                                     utils::val<register_type::reg16>>,
                     utils::property<templates::offset_operand,
                                     utils::val<offset_type::uimm12_0>>>
    {
      static constexpr uint32_t opcode = 0x2'40'00'00;

      SUB(uint8_t dstreg, uint8_t srcreg, uint16_t offset,
          CondCodes condition = ARMCC_AL)
          : base(opcode, offset, srcreg, dstreg, condition)
      {
      }

      void set_destination_register(uint8_t reg) noexcept
      {
        property_at<2>::set_register(reg);
      }

      void set_source_register(uint8_t reg) noexcept
      {
        property_at<3>::set_register(reg);
      }

      void set_register(uint8_t reg) noexcept
      {
        set_destination_register(reg);
        set_source_register(reg);
      }
    };

    struct LDRD_LITERAL
        : instruction_properties<
              utils::property<templates::condition_operand>,
              utils::property<templates::register_operand,
                              utils::val<register_type::reg12>>,
              utils::property<templates::offset_operand,
                              utils::val<offset_type::pimm4_8_4_0_23>>>
    {
      static constexpr uint32_t opcode = 0xE1'4F'00'D0;

      LDRD_LITERAL(reg_t reg, int16_t offset, CondCodes condition = ARMCC_AL)
          : base(opcode, offset, reg, condition)
      {
      }
    };

    struct LDR_LITERAL
        : instruction_properties<
              utils::property<templates::condition_operand>,
              utils::property<templates::register_operand,
                              utils::val<register_type::reg12>>,
              utils::property<templates::offset_operand,
                              utils::val<offset_type::pimm12_0_23>>>
    {
      static constexpr uint32_t opcode = 0xE5'1F'00'00;

      LDR_LITERAL(uint8_t reg, int16_t offset, CondCodes condition = ARMCC_AL)
          : base(opcode, offset, reg, condition)
      {
      }
    };

    struct LDRH_LITERAL
        : instruction_properties<
              utils::property<templates::condition_operand>,
              utils::property<templates::register_operand,
                              utils::val<register_type::reg12>>,
              utils::property<templates::offset_operand,
                              utils::val<offset_type::pimm4_8_4_0_23>>>
    {
      static constexpr uint32_t opcode = 0xE1'5F'00'B0;

      LDRH_LITERAL(uint8_t reg, int16_t offset, CondCodes condition = ARMCC_AL)
          : base(opcode, offset, reg, condition)
      {
      }
    };

    struct LDRB_LITERAL
        : instruction_properties<
              utils::property<templates::condition_operand>,
              utils::property<templates::register_operand,
                              utils::val<register_type::reg12>>,
              utils::property<templates::offset_operand,
                              utils::val<offset_type::pimm12_0_23>>>
    {
      static constexpr uint32_t opcode = 0xE5'5F'00'00;

      LDRB_LITERAL(uint8_t reg, int16_t offset, CondCodes condition = ARMCC_AL)
          : base(opcode, offset, reg, condition)
      {
      }
    };

    struct B : instruction_properties<
                   utils::property<templates::condition_operand>,
                   utils::property<templates::offset_operand,
                                   utils::val<offset_type::imm24_0_pad2>>>
    {
      static constexpr uint32_t opcode = 0xA'00'00'00;

      B(offset_t offset, CondCodes condition = ARMCC_AL)
          : base(opcode, offset, condition)
      {
      }
    };

    struct BL : instruction_properties<
                    utils::property<templates::condition_operand>,
                    utils::property<templates::offset_operand,
                                    utils::val<offset_type::imm24_0_pad2>>>
    {
      static constexpr uint32_t opcode = 0xB'00'00'00;

      BL(offset_t offset, CondCodes condition = ARMCC_AL)
          : base(opcode, offset, condition)
      {
      }
    };

    struct BLX
        : instruction_properties<utils::property<
              templates::offset_operand, utils::val<offset_type::imm24_0_1_24>>>
    {
      static constexpr uint32_t opcode = 0xFA'00'00'00;

      BLX(offset_t offset) : base(opcode, offset) {}
    };

    struct NOP
        : instruction_properties<utils::property<templates::condition_operand>>
    {
      static constexpr uint32_t opcode = 0x3'20'F0'00;

      NOP(CondCodes condition = ARMCC_AL) : base(opcode, condition) {}
    };

    struct BKPT : instruction_properties<
                      utils::property<templates::condition_operand>,
                      utils::property<templates::offset_operand,
                                      utils::val<offset_type::uimm12_8_4_0>>>
    {
      static constexpr uint32_t opcode = 0x1'20'00'70;

      BKPT(offset_t offset = 0) : base(opcode, offset, ARMCC_AL) {}

      void set_condition(CondCodes) noexcept = delete;
    };

    namespace custom
    {
      struct JMP : templates::custom_instruction<1>
      {
        LDR_LITERAL ldr;

        JMP(int16_t ldr_offset, CondCodes ldr_condition = ARMCC_AL)
            : ldr(pc, ldr_offset, ldr_condition)
        {
        }

        void set_offset(int16_t offset) { ldr.set_offset(offset); }

        void set_condition(CondCodes cond) { ldr.set_condition(cond); }
      };

      struct FULL_JMP : templates::custom_instruction<1>
      {
        LDR_LITERAL ldr;
        uint32_t    address;

        FULL_JMP(uint32_t address) : ldr(pc, -4), address(address) {}
      };

      struct CALL : templates::custom_instruction<2>
      {
        MOV         mov;
        LDR_LITERAL ldr;

        CALL(int16_t ldr_offset, CondCodes ldr_condition = ARMCC_AL)
            : mov(lr, pc), ldr(pc, ldr_offset - 4, ldr_condition)
        {
        }

        void set_offset(int16_t offset) { ldr.set_offset(offset - 4); }

        void set_condition(CondCodes cond)
        {
          mov.set_condition(cond);
          ldr.set_condition(cond);
        }
      };

      struct BX_RELATIVE : templates::custom_instruction<1>
      {
      public:
        typedef int16_t                  offset_t;
        static constexpr instruction_set instr_set = instruction_set::ARM;
        BX_RELATIVE(offset_t offset, CondCodes condition);

        void set_offset(int16_t offset)
        {
          if (offset >= 0)
            new (&instr)
                instr_t(ADD(pc, pc, offset ^ 1, instr.add.get_condition()));
          else
            new (&instr)
                instr_t(SUB(pc, pc, -(offset ^ 1), instr.sub.get_condition()));
        }

        static bool offset_fits(int16_t offset) noexcept
        {
          return ADD::offset_fits(abs(offset));
        }

      private:
        union instr_t
        {
          ADD add;
          SUB sub;

          instr_t(ADD add) : add(add) {}

          instr_t(SUB sub) : sub(sub) {}
        } instr;
      };

      inline BX_RELATIVE::BX_RELATIVE(offset_t offset, CondCodes condition)
          : instr(offset >= 0 ? instr_t(ADD(pc, pc, offset ^ 1, condition))
                              : instr_t(SUB(pc, pc, -(offset ^ 1), condition)))
      {
      }
    } // namespace custom
  }   // namespace arm

  namespace thumb2
  {
    template <typename base = void>
    struct INSTRUCTION
    {
      static_assert(std::is_same_v<base, void>,
                    "thumb2::INSTRUCTION is not allowed to have a base class");
      static constexpr instruction_set instr_set = instruction_set::THUMB2;

      typedef uint32_t instr_t;

      union
      {
        instr_t                       instr;
        std::pair<uint16_t, uint16_t> pieces;
      };

      static constexpr uint32_t opcode_with(uint16_t piece1,
                                            uint16_t piece2) noexcept
      {
        return (static_cast<uint32_t>(piece2) << 16) |
               static_cast<uint32_t>(piece1);
      }

      INSTRUCTION(uint32_t instr) : instr(instr) {}
    };

    template <typename... types>
    using instruction_properties =
        utils::properties<utils::property<INSTRUCTION>, types...>;

    struct PUSH_REGLIST
        : instruction_properties<utils::property<
              templates::reglist_operand, utils::val<reglist_type::lr_12>>>
    {
      static constexpr uint32_t opcode = base::opcode_with(0xE9'2D, 0x00'00);

      PUSH_REGLIST() : base(opcode) {}
    };

    struct LDRD_LITERAL
        : instruction_properties<
              utils::property<templates::register_operand,
                              utils::val<register_type::reg12>>,
              utils::property<templates::register_operand,
                              utils::val<register_type::reg8>>,
              utils::property<templates::offset_operand,
                              utils::val<offset_type::pimm8_0_pad2>>>
    {
      static constexpr uint32_t opcode = base::opcode_with(0xE9'5F, 0x00'00);

      LDRD_LITERAL(uint8_t reg1, uint8_t reg2, int16_t offset)
          : base(opcode, offset, reg2, reg1)
      {
      }

      void set_second_register(uint8_t reg) noexcept
      {
        property_at<2>::set_register(reg);
      }

      void set_register(uint8_t reg) noexcept
      {
        property_at<1>::set_register(reg);
      }
    };

    struct LDR_LITERAL
        : instruction_properties<
              utils::property<templates::register_operand,
                              utils::val<register_type::reg12>>,
              utils::property<templates::offset_operand,
                              utils::val<offset_type::pimm12_0_23>>>
    {
      static constexpr uint32_t opcode = base::opcode_with(0xF8'5F, 0x00'00);

      LDR_LITERAL(uint8_t reg, int16_t offset) : base(opcode, offset, reg) {}
    };

    struct LDRH_LITERAL
        : instruction_properties<
              utils::property<templates::register_operand,
                              utils::val<register_type::reg12>>,
              utils::property<templates::offset_operand,
                              utils::val<offset_type::pimm12_0_23>>>
    {
      static constexpr uint32_t opcode = base::opcode_with(0xF8'3F, 0x00'00);

      LDRH_LITERAL(uint8_t reg, int16_t offset) : base(opcode, offset, reg) {}
    };

    struct LDRB_LITERAL
        : instruction_properties<
              utils::property<templates::register_operand,
                              utils::val<register_type::reg12>>,
              utils::property<templates::offset_operand,
                              utils::val<offset_type::pimm12_0_23>>>
    {
      static constexpr uint32_t opcode = base::opcode_with(0xF8'1F, 0x00'00);

      LDRB_LITERAL(uint8_t reg, int16_t offset) : base(opcode, offset, reg) {}
    };

    struct LDR_IMM : instruction_properties<
                         utils::property<templates::register_operand,
                                         utils::val<register_type::reg16>>,
                         utils::property<templates::register_operand,
                                         utils::val<register_type::reg12>>,
                         utils::property<templates::offset_operand,
                                         utils::val<offset_type::uimm12_0>>>
    {
      static constexpr uint32_t opcode = base::opcode_with(0xF8'D0, 0x00'00);

      LDR_IMM(uint8_t destreg, uint8_t srcreg, uint16_t offset)
          : base(opcode, offset, destreg, srcreg)
      {
      }

      void set_destination_register(uint8_t reg) noexcept
      {
        property_at<2>::set_register(reg);
      }

      void set_source_register(uint8_t reg) noexcept
      {
        property_at<1>::set_register(reg);
      }
    };

    struct ADD
        : instruction_properties<
              utils::property<templates::register_operand,
                              utils::val<register_type::reg16>>,
              utils::property<templates::register_operand,
                              utils::val<register_type::reg8>>,
              utils::property<templates::offset_operand,
                              utils::val<offset_type::uimm1_26_3_12_8_0>>>
    {
      static constexpr uint32_t opcode = base::opcode_with(0xF2'00, 0x00'00);

      ADD(uint8_t destreg, uint8_t srcreg, uint16_t offset)
          : base(opcode, offset, destreg, srcreg)
      {
      }

      void set_destination_register(uint8_t reg) noexcept
      {
        property_at<2>::set_register(reg);
      }

      void set_source_register(uint8_t reg) noexcept
      {
        property_at<1>::set_register(reg);
      }

      void set_register(uint8_t reg) noexcept
      {
        set_destination_register(reg);
        set_source_register(reg);
      }
    };

    struct SUB
        : instruction_properties<
              utils::property<templates::register_operand,
                              utils::val<register_type::reg16>>,
              utils::property<templates::register_operand,
                              utils::val<register_type::reg8>>,
              utils::property<templates::offset_operand,
                              utils::val<offset_type::uimm1_26_3_12_8_0>>>
    {
      static constexpr uint32_t opcode = base::opcode_with(0xF2'A0, 0x00'00);

      SUB(uint8_t destreg, uint8_t srcreg, offset_t offset)
          : base(opcode, offset, destreg, srcreg)
      {
      }

      void set_destination_register(uint8_t reg) noexcept
      {
        property_at<2>::set_register(reg);
      }

      void set_source_register(uint8_t reg) noexcept
      {
        property_at<1>::set_register(reg);
      }

      void set_register(uint8_t reg) noexcept
      {
        set_destination_register(reg);
        set_source_register(reg);
      }
    };

    struct B
        : instruction_properties<utils::property<
              templates::customized_offset_operand, templates::xored_offset<1>,
              utils::val<offset_type::imm1_26_1_13_1_11_10_16_11_0_pad1>>>
    {
      static constexpr uint32_t opcode = base::opcode_with(0xF0'00, 0x90'00);

      B(offset_t offset) : base(opcode, offset) {}
    };

    struct B_cond
        : instruction_properties<utils::property<
              templates::offset_operand,
              utils::val<offset_type::imm1_26_1_13_1_11_10_16_11_0_pad1>>>
    {
      static constexpr uint32_t opcode = base::opcode_with(0xF0'00, 0x80'00);

      B_cond(offset_t offset, CondCodes condition = ARMCC_AL)
          : base(opcode | (condition << 6), offset)
      {
      }

      void set_condition(CondCodes condition) noexcept
      {
        instr &= ~(0b1111 << 6);
        instr |= (condition << 6);
      }
    };

    struct NOP : instruction_properties<>
    {
      static constexpr uint32_t opcode = base::opcode_with(0xF3'AF, 0x80'00);

      NOP() : base(opcode) {}
    };

    struct BL
        : instruction_properties<utils::property<
              templates::customized_offset_operand, templates::xored_offset<1>,
              utils::val<offset_type::imm1_26_1_13_1_11_10_16_11_0_pad1>>>
    {
      static constexpr uint32_t opcode = base::opcode_with(0xF0'00, 0xD0'00);

      BL(offset_t offset) : base(opcode, offset) {}
    };

    struct BLX
        : instruction_properties<utils::property<
              templates::customized_offset_operand,
              templates::xored_offset<2, 22>,
              utils::val<offset_type::imm1_26_1_13_1_11_10_16_10_1_pad2>>>
    {
      static constexpr uint32_t opcode = base::opcode_with(0xF0'00, 0xC0'00);

      BLX(offset_t offset) : base(opcode, offset) {}
    };

    namespace custom
    {
      struct JMP : templates::custom_instruction<1>
      {
        LDR_LITERAL ldr;

        JMP(int16_t ldr_offset) : ldr(pc, ldr_offset) {}

        void set_offset(int16_t offset) { ldr.set_offset(offset); }
      };

      struct FULL_JMP : templates::custom_instruction<1>
      {
        LDR_LITERAL ldr;
        uint32_t    address;

        FULL_JMP(uint32_t address) : ldr(pc, 0), address(address) {}
      };

      struct CALL : templates::custom_instruction<2>
      {
        ADD         add;
        LDR_LITERAL ldr;

        CALL(int16_t ldr_offset, bool align)
            : add(lr, pc, align ? 7 : 5), ldr(pc, ldr_offset - 4)
        {
        }

        void set_offset(int32_t offset) { ldr.set_offset(offset - 4); }
      };
    } // namespace custom
  }   // namespace thumb2

  namespace thumb
  {
    template <typename base = void>
    struct INSTRUCTION
    {
      static_assert(std::is_same_v<base, void>,
                    "thumb::INSTRUCTION is not allowed to have a base class");
      static constexpr instruction_set instr_set = instruction_set::THUMB;

      typedef uint16_t instr_t;

      instr_t instr;

      INSTRUCTION(instr_t instr) : instr(instr) {}
    };

    template <typename... types>
    using instruction_properties =
        utils::properties<utils::property<INSTRUCTION>, types...>;

    struct PUSH_REGLIST
        : instruction_properties<utils::property<
              templates::reglist_operand, utils::val<reglist_type::lr_7>>>
    {
      static constexpr uint16_t opcode = 0xB4'00;

      PUSH_REGLIST() : base(opcode) {}
    };

    // emulating single register push (even though there is no such encoding in
    // reality)
    struct PUSH : PUSH_REGLIST
    {
      PUSH(uint8_t reg) : PUSH_REGLIST() { PUSH_REGLIST::append(reg); }

      void append(uint8_t) noexcept   = delete;
      void remove(uint8_t) noexcept   = delete;
      bool greatest(uint8_t) noexcept = delete;

      void set_register(uint8_t reg) noexcept
      {
        instr &= ~mask;
        instr |= 1 << get_index(reg);
      }
    };

    struct POP_REGLIST
        : instruction_properties<utils::property<
              templates::reglist_operand, utils::val<reglist_type::pc_7>>>
    {
      static constexpr uint16_t opcode = 0xBC'00;

      POP_REGLIST() : base(opcode) {}
    };

    struct POP : POP_REGLIST
    {
      POP(uint8_t reg) : POP_REGLIST() { POP_REGLIST::append(reg); }

      void append(uint8_t) noexcept   = delete;
      void remove(uint8_t) noexcept   = delete;
      bool greatest(uint8_t) noexcept = delete;

      void set_register(uint8_t reg) noexcept
      {
        instr &= ~mask;
        instr |= 1 << get_index(reg);
      }
    };

    struct LDR_LITERAL
        : instruction_properties<
              utils::property<templates::register_operand,
                              utils::val<register_type::reg3_8>>,
              utils::property<templates::offset_operand,
                              utils::val<offset_type::uimm8_0_pad2>>>
    {
      static constexpr uint16_t opcode = 0x48'00;

      LDR_LITERAL(uint8_t reg, uint16_t offset) : base(opcode, offset, reg) {}
    };

    struct ADD : instruction_properties<
                     utils::property<templates::register_operand,
                                     utils::val<register_type::reg3_8>>,
                     utils::property<templates::offset_operand,
                                     utils::val<offset_type::uimm8_0>>>
    {
      static constexpr uint16_t opcode = 0x30'00;

      ADD(uint8_t reg, uint8_t offset) : base(opcode, offset, reg) {}
    };

    struct B : instruction_properties<utils::property<
                   templates::offset_operand, utils::val<offset_type::imm11_0>>>
    {
      static constexpr uint16_t opcode = 0xE0'00;

      B(offset_t offset) : base(opcode, offset) {}
    };

    struct B_cond
        : instruction_properties<utils::property<
              templates::offset_operand, utils::val<offset_type::imm8_0>>>
    {
      static constexpr uint16_t opcode = 0xD0'00;

      B_cond(offset_t offset, CondCodes condition)
          : base(opcode | (condition << 8), offset)
      {
      }

      void set_condition(CondCodes condition)
      {
        instr &= ~(0b1111 << 8);
        instr |= (condition << 8);
      }
    };

    struct NOP : instruction_properties<>
    {
      static constexpr uint16_t opcode = 0xBF'00;

      NOP() : base(opcode) {}
    };

    struct BKPT
        : instruction_properties<utils::property<
              templates::offset_operand, utils::val<offset_type::uimm8_0>>>
    {
      static constexpr uint16_t opcode = 0xBE'00;

      BKPT(offset_t offset = 0) : base(opcode, offset) {}
    };

    struct IT : instruction_properties<>
    {
      static constexpr uint16_t opcode = 0xBF'08;

      IT(CondCodes base_condition)
          : base(opcode | (static_cast<uint16_t>(base_condition) << 4))
      {
      }

      class const_reference;
      class reference;
      class const_iterator;
      class iterator;

      uint8_t count() const noexcept
      {
        return 4 - utils::bitscanf(instr & 0b1111u).value();
      }

      reference       operator[](uint8_t index) noexcept;
      const_reference operator[](uint8_t index) const noexcept;

      iterator       begin() noexcept;
      const_iterator begin() const noexcept;
      const_iterator cbegin() const noexcept;
      iterator       end() noexcept;
      const_iterator end() const noexcept;
      const_iterator cend() const noexcept;

      void push(CondCodes condition);

      CondCodes pop() noexcept;

      void pop(uint8_t count)
      {
        for (size_t i = 0; i != count; ++i)
          pop();
      }
    };

    class IT::const_reference
    {
    public:
      CondCodes get() const noexcept
      {
        CondCodes condition =
            static_cast<CondCodes>((ptr->instr >> 4) & 0b1111);
        if (index == 0)
          return condition;

        return ((ptr->instr >> (4 - index)) & 1) == (condition & 1)
                   ? condition
                   : ARMCC_getOppositeCondition(condition);
      }

      operator CondCodes() const noexcept { return get(); }

    private:
      friend struct IT;
      friend class reference;
      friend class const_iterator;

      const_reference(const IT* ptr, const uint8_t index)
          : ptr(ptr), index(index)
      {
      }

      const IT* ptr   = nullptr;
      uint8_t   index = 0;
    };

    class IT::reference : public IT::const_reference
    {
    public:
      reference& operator=(CondCodes new_condition) noexcept
      {
        CondCodes condition =
            static_cast<CondCodes>((ptr->instr >> 4) & 0b1111);
        if (index == 0)
        {
          if (condition == new_condition)
            return *this;
          const_cast<uint16_t&>(ptr->instr) &= ~(0b1111 << 4);
          const_cast<uint16_t&>(ptr->instr) |= (new_condition << 4);

          // if the base isn't flipped and is instead replaced with a new
          // condition we proceed on flipping the mask bits in order for the
          // rest of the instructions to remain in the same T/E state. Otherwise
          // we leave it as is.
          if (new_condition != ARMCC_getOppositeCondition(condition) &&
              (new_condition & 1) != (condition & 1))
            const_cast<uint16_t&>(ptr->instr) ^= 0b1111;
          return *this;
        }

        utils_assert(new_condition == condition ||
                         new_condition == ARMCC_getOppositeCondition(condition),
                     "can't set the condition of an instruction to anything "
                     "different than the base condition or the opposite of it");

        if (((ptr->instr >> (4 - index)) & 1) != (new_condition & 1))
          const_cast<uint16_t&>(ptr->instr) ^= (1 << (4 - index));
        return *this;
      }

    private:
      friend struct IT;
      friend class iterator;

      reference(IT* ptr, uint8_t index) : const_reference(ptr, index) {}

      reference(const_reference other) : const_reference(other) {}
    };

    class IT::const_iterator
    {
    public:
      typedef std::random_access_iterator_tag iterator_category;
      typedef CondCodes                       value_type;
      typedef int8_t                          difference_type;

      const_iterator() {}

      const_reference operator*() const noexcept
      {
        utils_assert(ptr, "cannot dereference uninitialized it block iterator");
        utils_assert(index < ptr->count(),
                     "cannot dereference an out of range it block iterator");
        return { ptr, index };
      }

      const_iterator& operator++() noexcept
      {
        utils_assert(ptr, "cannot increment uninitialized it block iterator");
        utils_assert(index < ptr->count(),
                     "cannot increment it block iterator past the end");
        ++index;
        return *this;
      }

      const_iterator operator++(int) noexcept
      {
        const_iterator tmp = *this;
        operator++();
        return tmp;
      }

      const_iterator& operator--() noexcept
      {
        utils_assert(ptr, "cannot decrement uninitialized it block iterator");
        utils_assert(index > 0,
                     "cannot decrement it block iterator before begin");
        --index;
        return *this;
      }

      const_iterator operator--(int) noexcept
      {
        const_iterator tmp = *this;
        operator--();
        return tmp;
      }

      const_iterator& operator+=(int8_t offset) noexcept
      {
        verify_offset(offset);
        index += offset;
        return *this;
      }

      const_iterator& operator-=(int8_t offset) noexcept
      {
        return operator+=(-offset);
      }

      int8_t operator-(const const_iterator& other) const noexcept
      {
        compatible(other);
        return index - other.index;
      }

      const_reference operator[](const int8_t offset) const noexcept
      {
        verify_offset(offset);
        return { ptr, static_cast<uint8_t>(index + offset) };
      }

      const_iterator operator+(const int8_t offset) const noexcept
      {
        const_iterator tmp  = *this;
        tmp                += offset;
        return tmp;
      }

      const_iterator operator-(const int8_t offset) const noexcept
      {
        return operator+(-offset);
      }

      friend const_iterator operator+(const int8_t   offset,
                                      const_iterator itr) noexcept
      {
        itr += offset;
        return itr;
      }

      bool operator==(const const_iterator& other) const noexcept
      {
        compatible(other);
        return index == other.index;
      }

      bool operator!=(const const_iterator& other) const noexcept
      {
        return !operator==(other);
      }

      bool operator<(const const_iterator& other) const noexcept
      {
        compatible(other);
        return index < other.index;
      }

      bool operator>(const const_iterator& other) const noexcept
      {
        return other < *this;
      }

      bool operator<=(const const_iterator& other) const noexcept
      {
        return !operator>(other);
      }

      bool operator>=(const const_iterator& other) const noexcept
      {
        return !operator<(other);
      }

    private:
      friend struct IT;
      friend class iterator;

      const_iterator(const IT* ptr, uint8_t index) : ptr(ptr), index(index) {}

      void verify_offset(int8_t offset) const noexcept
      {
        if (offset != 0)
          utils_assert(ptr, "cannot seek uninitialized it block iterator");
        if (offset < 0)
          utils_assert(index >= -offset,
                       "cannot seek it block iterator before begin");
        if (offset > 0)
          utils_assert((ptr->count() - index) >= offset,
                       "cannot seek it block iterator past the end");
      }

      void compatible(
          [[maybe_unused]] const const_iterator& other) const noexcept
      {
        utils_assert(ptr == other.ptr, "it block iterators are incompatible");
      }

      const IT* ptr   = nullptr;
      uint8_t   index = 0;
    };

    class IT::iterator : public IT::const_iterator
    {
    public:
      typedef std::random_access_iterator_tag iterator_category;
      typedef CondCodes                       value_type;
      typedef int8_t                          difference_type;

      iterator() {}

      reference operator*() const noexcept
      {
        return const_iterator::operator*();
      }

      iterator& operator++() noexcept
      {
        const_iterator::operator++();
        return *this;
      }

      iterator operator++(int) noexcept
      {
        auto tmp = *this;
        const_iterator::operator++();
        return tmp;
      }

      iterator& operator--() noexcept
      {
        const_iterator::operator--();
        return *this;
      }

      iterator operator--(int) noexcept
      {
        auto tmp = *this;
        const_iterator::operator--();
        return tmp;
      }

      iterator& operator+=(const int8_t offset) noexcept
      {
        const_iterator::operator+=(offset);
        return *this;
      }

      iterator operator+(const int8_t offset) const noexcept
      {
        auto tmp  = *this;
        tmp      += offset;
        return tmp;
      }

      friend iterator operator+(const int8_t offset, iterator itr) noexcept
      {
        itr += offset;
        return itr;
      }

      iterator& operator-=(const int8_t offset) noexcept
      {
        const_iterator::operator-=(offset);
        return *this;
      }

      using const_iterator::operator-;

      iterator operator-(const int8_t offset) const noexcept
      {
        auto tmp  = *this;
        tmp      -= offset;
        return tmp;
      }

      reference operator[](const int8_t offset) const noexcept
      {
        return const_iterator::operator[](offset);
      }

    private:
      friend struct IT;

      iterator(IT* ptr, uint8_t index) : const_iterator(ptr, index) {}
    };

    inline typename IT::reference IT::operator[](uint8_t index) noexcept
    {
      utils_assert(index < count(),
                   "condition at index specified is out of range");
      return { this, index };
    }

    inline typename IT::const_reference
        IT::operator[](uint8_t index) const noexcept
    {
      utils_assert(index < count(),
                   "condition at index specified is out of range");
      return { this, index };
    }

    inline typename IT::iterator IT::begin() noexcept { return { this, 0 }; }

    inline typename IT::const_iterator IT::begin() const noexcept
    {
      return { this, 0 };
    }

    inline typename IT::const_iterator IT::cbegin() const noexcept
    {
      return { this, 0 };
    }

    inline typename IT::iterator IT::end() noexcept
    {
      return { this, count() };
    }

    inline typename IT::const_iterator IT::end() const noexcept
    {
      return { this, count() };
    }

    inline typename IT::const_iterator IT::cend() const noexcept
    {
      return { this, count() };
    }

    inline void IT::push(CondCodes condition)
    {
      constexpr uint8_t prevmask = 0b10000;
      const CondCodes basecond = static_cast<CondCodes>((instr >> 4) & 0b1111);
      const uint8_t   cond_count = count();
      utils_assert(cond_count < 4,
                   "an IT block cannot exceed 4 conditions in count");
      utils_assert(condition == basecond ||
                       condition == ARMCC_getOppositeCondition(basecond),
                   "the next condition of the IT block must always be the same "
                   "or the opposite of the base one");
      const uint16_t nextmask  = (prevmask >> 1) | ((condition & 1) << 4);
      instr                   &= ~(prevmask >> cond_count);
      instr                   |= (nextmask >> cond_count);
    }

    inline CondCodes IT::pop() noexcept
    {
      constexpr uint8_t prevmask   = 0b10000;
      constexpr uint8_t nextmask   = prevmask << 1;
      const uint8_t     cond_count = count();
      utils_assert(cond_count > 1, "cannot leave an IT block empty");
      CondCodes current  = operator[](cond_count - 1);
      instr             &= ~(prevmask >> cond_count);
      instr             |= (nextmask >> cond_count);
      return current;
    }
  } // namespace thumb
} // namespace alterhook

#pragma GCC visibility pop

#if utils_clang
  #pragma clang diagnostic pop
#endif
