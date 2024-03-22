/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#pragma GCC visibility push(hidden)

namespace alterhook::aarch64
{
  // clang-format off
  enum reg_t : uint8_t
  {
    W0  = 0,  W1  = 1,  W2  = 2,  W3  = 3,  W4  = 4,
    W5  = 5,  W6  = 6,  W7  = 7,  W8  = 8,  W9  = 9,
    W10 = 10, W11 = 11, W12 = 12, W13 = 13, W14 = 14,
    W15 = 15, W16 = 16, W17 = 17, W18 = 18, W19 = 19,
    W20 = 20, W21 = 21, W22 = 22, W23 = 23, W24 = 24,
    W25 = 25, W26 = 26, W27 = 27, W28 = 28, W29 = 29,
    W30 = 30, SP = 31,
    X0  = W0,  X1  = W1,  X2  = W2,  X3  = W3,
    X4  = W4,  X5  = W5,  X6  = W6,  X7  = W7,  X8  = W8,
    X9  = W9,  X10 = W10, X11 = W11, X12 = W12, X13 = W13,
    X14 = W14, X15 = W15, X16 = W16, X17 = W17, X18 = W18,
    X19 = W19, X20 = W20, X21 = W21, X22 = W22, X23 = W23,
    X24 = W24, X25 = W25, X26 = W26, X27 = W27, X28 = W28,
    X29 = W29, X30 = W30
  };

  enum class wregisters : uint8_t
  {
    W0  = 0,  W1  = 1,  W2  = 2,  W3  = 3,  W4  = 4,
    W5  = 5,  W6  = 6,  W7  = 7,  W8  = 8,  W9  = 9,
    W10 = 10, W11 = 11, W12 = 12, W13 = 13, W14 = 14,
    W15 = 15, W16 = 16, W17 = 17, W18 = 18, W19 = 19,
    W20 = 20, W21 = 21, W22 = 22, W23 = 23, W24 = 24,
    W25 = 25, W26 = 26, W27 = 27, W28 = 28, W29 = 29,
    W30 = 30
  };

  enum class xregisters : uint8_t
  {
    X0  = 0,  X1  = 1,  X2  = 2,  X3  = 3,
    X4  = 4,  X5  = 5,  X6  = 6,  X7  = 7,  X8  = 8,
    X9  = 9,  X10 = 10, X11 = 11, X12 = 12, X13 = 13,
    X14 = 14, X15 = 15, X16 = 16, X17 = 17, X18 = 18,
    X19 = 19, X20 = 20, X21 = 21, X22 = 22, X23 = 23,
    X24 = 24, X25 = 25, X26 = 26, X27 = 27, X28 = 28,
    X29 = 29, X30 = 30
  };

  enum class qregisters : uint8_t
  {
    Q0  = 0,  Q1  = 1,  Q2  = 2,  Q3  = 3,
    Q4  = 4,  Q5  = 5,  Q6  = 6,  Q7  = 7,  Q8  = 8,
    Q9  = 9,  Q10 = 10, Q11 = 11, Q12 = 12, Q13 = 13,
    Q14 = 14, Q15 = 15, Q16 = 16, Q17 = 17, Q18 = 18,
    Q19 = 19, Q20 = 20, Q21 = 21, Q22 = 22, Q23 = 23,
    Q24 = 24, Q25 = 25, Q26 = 26, Q27 = 27, Q28 = 28,
    Q29 = 29, Q30 = 30
  };

  // clang-format on

  namespace helpers
  {
    template <typename operand_t, size_t... indexes>
    static uint32_t patch_operand_impl(const cs_operand_encoding& encoding,
                                       uint32_t instr, operand_t value,
                                       std::index_sequence<indexes...>) noexcept
    {
      const auto *sizes_begin = encoding.sizes,
                 *sizes_end   = encoding.sizes + encoding.operand_pieces_count;
      const uint8_t operand_size =
          std::accumulate(sizes_begin, sizes_end, uint8_t{});
      uint8_t current_size = 0;

      const auto process = [&](const size_t i) -> bool
      {
        if (encoding.operand_pieces_count < (i + 1))
          return false;
        current_size        += encoding.sizes[i];
        const uint32_t mask  = (1u << encoding.sizes[i]) - 1;
        const uint32_t op_part =
            (value >> (operand_size - current_size)) & mask;
        instr &= ~(mask << encoding.indexes[i]);
        instr |= (op_part << encoding.indexes[i]);
        return true;
      };

      (!process(indexes) || ...);
      return instr;
    }

    template <typename operand_t, size_t... indexes>
    static operand_t
        fetch_operand_impl(const cs_operand_encoding& encoding, uint32_t instr,
                           std::index_sequence<indexes...>) noexcept
    {
      const auto *sizes_begin = encoding.sizes,
                 *sizes_end   = encoding.sizes + encoding.operand_pieces_count;
      const uint8_t operand_size =
          std::accumulate(sizes_begin, sizes_end, uint8_t{});
      uint8_t                         current_size = 0;
      std::make_unsigned_t<operand_t> result{};

      const auto process = [&](const size_t i) -> bool
      {
        if (encoding.operand_pieces_count < (i + 1))
          return false;
        current_size         += encoding.sizes[i];
        const uint32_t mask   = (1u << encoding.sizes[i]) - 1;
        const auto     value  = static_cast<std::make_unsigned_t<operand_t>>(
            (instr >> encoding.indexes[i]) & mask);
        result |= (value << (operand_size - current_size));
        return true;
      };

      (!process(indexes) || ...);
      return static_cast<operand_t>(result);
    }
  } // namespace helpers

  template <size_t max_pieces, typename operand_t>
  static uint32_t patch_operand(const cs_operand_encoding& encoding,
                                uint32_t instr, operand_t value) noexcept
  {
    static_assert(
        std::is_integral_v<operand_t> || std::is_enum_v<operand_t>,
        "patch_operand: value is expected to be of integral or enum type");
    return helpers::patch_operand_impl(encoding, instr, value,
                                       std::make_index_sequence<max_pieces>());
  }

  template <size_t max_pieces, typename operand_t>
  static operand_t fetch_operand(const cs_operand_encoding& encoding,
                                 uint32_t                   instr) noexcept
  {
    static_assert(
        std::is_integral_v<operand_t> || std::is_enum_v<operand_t>,
        "fetch_operand: value is expected to be of integral or enum type");
    return helpers::fetch_operand_impl<operand_t>(
        encoding, instr, std::make_index_sequence<max_pieces>());
  }

  constexpr std::array offset_encodings = {
    cs_operand_encoding{1,  { 0 },     { 26 }   },
    cs_operand_encoding{ 1, { 5 },     { 19 }   },
    cs_operand_encoding{ 1, { 5 },     { 14 }   },
    cs_operand_encoding{ 2, { 29, 5 }, { 2, 19 }},
    cs_operand_encoding{ 2, { 29, 5 }, { 2, 19 }},
    cs_operand_encoding{ 1, { 5 },     { 16 }   },
    cs_operand_encoding{ 1, { 10 },    { 12 }   },
    cs_operand_encoding{ 1, { 10 },    { 12 }   },
    cs_operand_encoding{ 1, { 10 },    { 12 }   },
    cs_operand_encoding{ 1, { 10 },    { 12 }   },
    cs_operand_encoding{ 1, { 10 },    { 12 }   },
    cs_operand_encoding{ 1, { 12 },    { 9 }    }
  };

  constexpr std::array register_encodings = {
    cs_operand_encoding{1,  { 0 }, { 5 }},
    cs_operand_encoding{ 1, { 5 }, { 5 }}
  };

  constexpr std::array resizable_register_encodings = {
    cs_operand_encoding{1,  { 0 }, { 5 }},
    cs_operand_encoding{ 1, { 0 }, { 5 }},
    cs_operand_encoding{ 1, { 0 }, { 5 }},
    cs_operand_encoding{ 1, { 5 }, { 5 }}
  };

  constexpr std::array regsize_encodings = {
    cs_operand_encoding{1,  { 31 }, { 1 }},
    cs_operand_encoding{ 1, { 30 }, { 2 }},
    cs_operand_encoding{ 1, { 30 }, { 1 }},
    cs_operand_encoding{ 1, { 31 }, { 1 }}
  };

  enum class offset_type
  {
    imm26_0_pad2,
    imm19_5_pad2,
    imm14_5_pad2,
    imm2_29_19_5,
    imm2_29_19_5_pad12,
    uimm16_5,
    uimm12_10,
    uimm12_10_pad2,
    uimm12_10_pad3,
    uimm12_10_pad1,
    uimm12_10_pad4,
    imm9_12
  };

  enum class register_type
  {
    reg5_0,
    reg5_5
  };

  enum class resizable_register_type
  {
    reg5_0_size1_31,
    reg5_0_size2_30,
    reg5_0_size1_30,
    reg5_5_size1_31
  };

  struct INSTRUCTION
  {
    uint32_t instr = 0;

    INSTRUCTION() = default;

    INSTRUCTION(uint32_t instr) : instr(instr) {}
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
    inline constexpr bool has_custom_decode_offset = false;
    template <typename T, typename offset_t>
    inline constexpr bool has_custom_decode_offset<
        T, offset_t,
        std::void_t<decltype(T::decode_offset(std::declval<offset_t>()))>> =
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

    template <typename customcls, typename offset_format_t,
              typename base = INSTRUCTION>
    struct customized_offset_operand : base
    {
      typedef utils::type_sequence<int32_t, int32_t, int16_t, int32_t, int32_t,
                                   uint16_t, uint16_t, uint16_t, uint16_t,
                                   uint16_t, uint16_t, int16_t>
                                   offset_types;
      static constexpr std::array  offset_pads      = { 2, 2, 2, 0, 12, 0,
                                                        0, 2, 3, 1, 4,  0 };
      static constexpr std::array  offset_bitcounts = { 26, 19, 14, 21, 21, 16,
                                                        12, 12, 12, 12, 12, 9 };
      static constexpr offset_type offset_format    = offset_format_t::value;
      static constexpr cs_operand_encoding offset_encoding =
          offset_encodings[utils::to_underlying(offset_format)];
      static constexpr uint32_t offset_pad =
          offset_pads[utils::to_underlying(offset_format)];
      static constexpr uint32_t offset_bitcount =
          offset_bitcounts[utils::to_underlying(offset_format)];
      static constexpr uint32_t offset_max =
          utils::bitsfill<uint32_t>(offset_bitcount);
      typedef offset_types::template at<utils::to_underlying(offset_format)>
          offset_t;
      typedef std::conditional_t<std::is_signed_v<offset_t>, intptr_t,
                                 uintptr_t>
          offset_fits_t;

      static uint32_t convert_offset(offset_t offset) noexcept
      {
        if constexpr (has_custom_convert_offset<customcls, offset_t>)
          return customcls::convert_offset(offset);
        else
          return (offset >> offset_pad);
      }

      static offset_t decode_offset(offset_t offset)
      {
        if constexpr (has_custom_decode_offset<customcls, offset_t>)
          return customcls::decode_offset(offset);
        else
        {
          static_assert(
              !has_custom_convert_offset<customcls, offset_t>,
              "custom offset converter provided but no custom decoder");
          if constexpr (std::is_signed_v<offset_t>)
            return static_cast<offset_t>(
                static_cast<std::make_unsigned_t<offset_t>>(
                    utils::sign_extend<offset_bitcount>(offset))
                << offset_pad);
          else
            return offset << offset_pad;
        }
      }

      static bool offset_fits(offset_fits_t offset) noexcept
      {
        if constexpr (has_custom_offset_fits<customcls, offset_t>)
          return customcls::offset_fits(offset);
        else
        {
          if constexpr (offset_pad != 0)
          {
            if (offset & utils::bitsfill<uintptr_t>(offset_pad))
              return false;
          }
          if ((std::numeric_limits<offset_t>::max)() < offset)
            return false;
          if constexpr (std::is_signed_v<offset_t>)
            return convert_offset(abs(offset)) <= (offset_max >> 1);
          else
            return convert_offset(offset) <= offset_max;
        }
      }

      static void assert_offset(offset_t offset)
      {
        if constexpr (has_custom_assert_offset<customcls, offset_t>)
          customcls::assert_offset(offset);
        else if constexpr (offset_format == offset_type::imm26_0_pad2)
          utils_assert(offset_fits(offset),
                       "offset too large to fit in 26 bits");
        else if constexpr (utils::any_of(offset_format,
                                         offset_type::imm2_29_19_5,
                                         offset_type::imm2_29_19_5_pad12))
          utils_assert(offset_fits(offset),
                       "offset too large to fit in 21 bits");
        else if constexpr (offset_format == offset_type::imm19_5_pad2)
          utils_assert(offset_fits(offset),
                       "offset too large to fit in 19 bits");
        else if constexpr (offset_format == offset_type::uimm16_5)
          utils_assert(offset_fits(offset),
                       "offset too large to fit in 16 bits");
        else if constexpr (offset_format == offset_type::imm14_5_pad2)
          utils_assert(offset_fits(offset),
                       "offset too large to fit in 14 bits");
        else if constexpr (utils::any_of(offset_format, offset_type::uimm12_10,
                                         offset_type::uimm12_10_pad1,
                                         offset_type::uimm12_10_pad2,
                                         offset_type::uimm12_10_pad3,
                                         offset_type::uimm12_10_pad4))
          utils_assert(offset_fits(offset),
                       "offset too large to fit in 12 bits");
        else if constexpr (offset_format == offset_type::imm9_12)
          utils_assert(offset_fits(offset),
                       "offset too large to fit in 9 bits");
        else
          static_assert(utils::always_false<base>, "offset type not covered");
      }

      template <typename... types>
      customized_offset_operand(uint32_t opcode, offset_t offset,
                                types&&... rest)
          : base((assert_offset(offset),
                  patch_operand<2>(offset_encoding, opcode,
                                   convert_offset(offset))),
                 std::forward<types>(rest)...)
      {
      }

      void set_offset(offset_t offset) noexcept
      {
        assert_offset(offset);
        base::instr = patch_operand<2>(offset_encoding, base::instr, offset);
      }

      offset_t get_offset() const noexcept
      {
        return decode_offset(
            fetch_operand<2, offset_t>(offset_encoding, base::instr));
      }
    };

    template <typename offset_format_t, typename base = INSTRUCTION>
    using offset_operand =
        customized_offset_operand<void, offset_format_t, base>;

    template <typename base = INSTRUCTION>
    struct condition_operand : base
    {
      static constexpr cs_operand_encoding condition_encoding = { 1,
                                                                  { 0 },
                                                                  { 4 } };
      static constexpr size_t              condition_max      = 0xF;
      typedef uint8_t                      condition_t;

      static void
          assert_condition([[maybe_unused]] condition_t condition) noexcept
      {
        utils_assert(condition <= condition_max,
                     "condition value too large to fit in 4 bits");
      }

      template <typename... types>
      condition_operand(uint32_t opcode, condition_t condition, types&&... rest)
          : base((assert_condition(condition),
                  patch_operand<1>(condition_encoding, opcode, condition)),
                 std::forward<types>(rest)...)
      {
      }

      void set_condition(condition_t condition) noexcept
      {
        assert_condition(condition);
        base::instr =
            patch_operand<1>(condition_encoding, base::instr, condition);
      }
    };

    template <typename register_format_t, typename base = INSTRUCTION>
    struct register_operand : base
    {
      static constexpr register_type register_format = register_format_t::value;
      static constexpr cs_operand_encoding register_encoding =
          register_encodings[utils::to_underlying(register_format)];
      static constexpr uint32_t register_max = 0x1F;
      typedef reg_t             register_t;

      static void assert_register([[maybe_unused]] register_t reg) noexcept
      {
        utils_assert(reg <= register_max,
                     "register value too large to fit in 5 bits");
      }

      template <typename... types>
      register_operand(uint32_t opcode, register_t reg, types&&... args)
          : base((assert_register(reg),
                  patch_operand<1>(register_encoding, opcode, reg)),
                 std::forward<types>(args)...)
      {
      }

      void set_register(register_t reg) noexcept
      {
        assert_register(reg);
        base::instr = patch_operand<1>(register_encoding, base::instr, reg);
      }

      reg_t get_register() const noexcept
      {
        return static_cast<reg_t>(
            fetch_operand<1, uint8_t>(register_encoding, base::instr));
      }
    };

    template <typename resizable_register_format_t, typename base = INSTRUCTION>
    struct resizable_register_operand : base
    {
      static constexpr resizable_register_type resizable_register_format =
          resizable_register_format_t::value;
      static constexpr cs_operand_encoding resizable_register_encoding =
          resizable_register_encodings[utils::to_underlying(
              resizable_register_format)];
      static constexpr cs_operand_encoding regsize_encoding =
          regsize_encodings[utils::to_underlying(resizable_register_format)];
      static constexpr uint32_t register_max = 0x1F;
      typedef utils::type_sequence<wregisters, xregisters, qregisters>
          valid_registers;

      template <typename T>
      static void assert_resizable_register([[maybe_unused]] T reg) noexcept
      {
        utils_assert(utils::to_underlying(reg) <= register_max,
                     "register value too large to fit in 5 bits");
      }

      template <typename T>
      static constexpr void ctime_assert()
      {
        static_assert(valid_registers::template has<T>,
                      "an invalid register type was passed to "
                      "`assert_resizable_register`");
        static_assert(valid_registers::template find<T> <=
                          regsize_encoding.sizes[0],
                      "register size type not allowed on this instruction");
      }

      template <typename T, typename... types>
      resizable_register_operand(uint32_t opcode, T reg, types&&... rest)
          : base((assert_resizable_register(reg),
                  patch_operand<1>(resizable_register_encoding, opcode,
                                   utils::to_underlying(reg)) |
                      patch_operand<1>(regsize_encoding, opcode,
                                       valid_registers::template find<T>)),
                 std::forward<types>(rest)...)
      {
        ctime_assert<T>();
      }

      template <typename T>
      void set_register(T reg) noexcept
      {
        ctime_assert<T>();
        assert_resizable_register(reg);
        base::instr = patch_operand<1>(
            resizable_register_encoding,
            patch_operand<1>(regsize_encoding, base::instr,
                             valid_registers::template find<T>),
            utils::to_underlying(reg));
      }

      template <typename T>
      T get_register() noexcept
      {
        ctime_assert<T>();
        utils_assert(
            (fetch_operand<1, uint8_t>(regsize_encoding, base::instr)) ==
                valid_registers::template find<T>,
            "incorrect register type");
        return static_cast<T>(fetch_operand<1, uint8_t>(
            resizable_register_encoding, base::instr));
      }

      uint8_t register_size() const noexcept
      {
        constexpr std::array<uint8_t, 3> sizes = { 4, 8, 16 };
        return sizes[fetch_operand<1, uint8_t>(regsize_encoding, base::instr)];
      }
    };

    template <typename base = INSTRUCTION>
    struct bitpos_operand : base
    {
      static constexpr cs_operand_encoding bitpos_encoding = {
        2, {31, 19},
         { 1, 5 }
      };
      static constexpr size_t bitpos_max = 0x3F;
      typedef uint8_t         bitpos_t;

      static void assert_bitpos([[maybe_unused]] bitpos_t bitpos) noexcept
      {
        utils_assert(bitpos <= bitpos_max,
                     "bit position value too large to fit in 6 bits");
      }

      template <typename... types>
      bitpos_operand(uint32_t opcode, bitpos_t bitpos, types&&... rest)
          : base((assert_bitpos(bitpos),
                  patch_operand<2>(bitpos_encoding, opcode, bitpos)),
                 std::forward<types>(rest)...)
      {
      }

      void set_bit_position(bitpos_t bitpos) noexcept
      {
        assert_bitpos(bitpos);
        base::instr = patch_operand<2>(bitpos_encoding, base::instr, bitpos);
      }
    };

    template <size_t pad = 0>
    struct rorimmhi_immlo
    {
      static uint32_t convert_offset(int32_t offset) noexcept
      {
        uint32_t result   = offset;
        result          >>= pad;
        return ((result & 0b11) << 19) | (result >> 2);
      }

      static int32_t decode_offset(int32_t offset) noexcept
      {
        uint32_t result = offset;
        result          = ((result >> 19) & 0b11) | ((result & 0x7'FF'FF) << 2);
        result <<= pad;
        return utils::sign_extend<21>(result);
      }
    };

    typedef decltype(cs_insn::id) insn_id_t;

#define __gen_property_arg_type_overload_impl(clsname, argname)                \
  template <typename... types>                                                 \
  struct property_arg_type<clsname<types...>>                                  \
  {                                                                            \
    typedef typename clsname<types...>::argname type;                          \
  }
#define __gen_property_arg_type_overload(pair)                                 \
  __gen_property_arg_type_overload_impl pair
#define __gen_property_arg_type_overloads(...)                                 \
  utils_map_separated(__gen_property_arg_type_overload, ;, __VA_ARGS__)

    template <typename T>
    struct property_arg_type;

    // exception
    template <typename... types>
    struct property_arg_type<resizable_register_operand<types...>>
    {
      typedef void type;
    };

    __gen_property_arg_type_overloads((customized_offset_operand, offset_t),
                                      (condition_operand, condition_t),
                                      (register_operand, register_t),
                                      (bitpos_operand, bitpos_t));

    template <typename T>
    using property_arg_type_t = typename property_arg_type<T>::type;

    template <insn_id_t idval, uint32_t opcodeval, typename typeseq,
              typename indexseq>
    struct basic_instruction_impl;

    template <insn_id_t idval, uint32_t opcodeval, typename... properties,
              size_t... indexes>
    struct basic_instruction_impl<idval, opcodeval,
                                  utils::type_sequence<properties...>,
                                  std::index_sequence<indexes...>>
        : utils::properties<properties...>
    {
      typedef typename utils::properties<properties...>::base base;
      typedef basic_instruction_impl                          instr_base;
      template <size_t N>
      using property_at = typename base::template property_at<N>;

      static constexpr uint32_t  opcode = opcodeval;
      static constexpr insn_id_t id     = idval;

      basic_instruction_impl(property_arg_type_t<property_at<indexes>>... args)
          : basic_instruction_impl(
                std::tuple(args...),
                utils::make_reversed_index_sequence<sizeof...(properties)>{})
      {
      }

    private:
      template <typename... types, size_t... rindexes>
      basic_instruction_impl(std::tuple<types...>&& args,
                             std::index_sequence<rindexes...>)
          : base(opcode, std::get<rindexes>(args)...)
      {
      }
    };

    template <insn_id_t idval, uint32_t opcodeval, typename... properties>
    using basic_instruction =
        basic_instruction_impl<idval, opcodeval,
                               utils::type_sequence<properties...>,
                               std::make_index_sequence<sizeof...(properties)>>;

    template <insn_id_t idval, uint32_t opcodeval, offset_type offtype>
    struct LDR_PRE
        : basic_instruction<
              idval, opcodeval,
              utils::property<templates::register_operand,
                              utils::val<register_type::reg5_0>>,
              utils::property<templates::register_operand,
                              utils::val<register_type::reg5_5>>,
              utils::property<templates::offset_operand, utils::val<offtype>>>
    {
      typedef typename basic_instruction<
          idval, opcodeval,
          utils::property<templates::register_operand,
                          utils::val<register_type::reg5_0>>,
          utils::property<templates::register_operand,
                          utils::val<register_type::reg5_5>>,
          utils::property<templates::offset_operand,
                          utils::val<offtype>>>::instr_base instr_base;
      using instr_base::instr_base;
      template <size_t N>
      using property_at = typename instr_base::template property_at<N>;

      void set_destination_register(reg_t reg) noexcept
      {
        property_at<0>::set_register(reg);
      }

      void set_base_register(reg_t reg) noexcept
      {
        property_at<1>::set_register(reg);
      }

      void set_register(reg_t) noexcept = delete;
    };
  } // namespace templates

  using B = templates::basic_instruction<
      AArch64_INS_B, 0x14'00'00'00,
      utils::property<templates::offset_operand,
                      utils::val<offset_type::imm26_0_pad2>>>;

  using B_cond = templates::basic_instruction<
      AArch64_INS_B, 0x54'00'00'00,
      utils::property<templates::offset_operand,
                      utils::val<offset_type::imm19_5_pad2>>,
      utils::property<templates::condition_operand>>;

  using BL = templates::basic_instruction<
      AArch64_INS_BL, 0x94'00'00'00,
      utils::property<templates::offset_operand,
                      utils::val<offset_type::imm26_0_pad2>>>;

  using LDRu32 = templates::LDR_PRE<AArch64_INS_LDR, 0xB9'40'00'00,
                                    offset_type::uimm12_10_pad2>;

  using LDRu64 = templates::LDR_PRE<AArch64_INS_LDR, 0xF9'40'00'00,
                                    offset_type::uimm12_10_pad3>;

  using LDRSWu = templates::LDR_PRE<AArch64_INS_LDRSW, 0xB9'80'00'00,
                                    offset_type::uimm12_10_pad3>;

  using LDRVu8   = templates::LDR_PRE<AArch64_INS_LDR, 0x3D'40'00'00,
                                    offset_type::uimm12_10>;
  using LDRVu16  = templates::LDR_PRE<AArch64_INS_LDR, 0x7D'40'00'00,
                                     offset_type::uimm12_10_pad1>;
  using LDRVu32  = templates::LDR_PRE<AArch64_INS_LDR, 0xBD'40'00'00,
                                     offset_type::uimm12_10_pad2>;
  using LDRVu64  = templates::LDR_PRE<AArch64_INS_LDR, 0xFD'40'00'00,
                                     offset_type::uimm12_10_pad3>;
  using LDRVu128 = templates::LDR_PRE<AArch64_INS_LDR, 0x3D'C0'00'00,
                                      offset_type::uimm12_10_pad4>;

  using ADR = templates::basic_instruction<
      AArch64_INS_ADR, 0x10'00'00'00,
      utils::property<templates::register_operand,
                      utils::val<register_type::reg5_0>>,
      utils::property<templates::customized_offset_operand,
                      templates::rorimmhi_immlo<0>,
                      utils::val<offset_type::imm2_29_19_5>>>;

  using ADRP = templates::basic_instruction<
      AArch64_INS_ADRP, 0x90'00'00'00,
      utils::property<templates::register_operand,
                      utils::val<register_type::reg5_0>>,
      utils::property<templates::customized_offset_operand,
                      templates::rorimmhi_immlo<12>,
                      utils::val<offset_type::imm2_29_19_5_pad12>>>;

  using BR = templates::basic_instruction<
      AArch64_INS_BR, 0xD6'1F'00'00,
      utils::property<templates::register_operand,
                      utils::val<register_type::reg5_5>>>;

  using BLR = templates::basic_instruction<
      AArch64_INS_BLR, 0xD6'3F'00'00,
      utils::property<templates::register_operand,
                      utils::val<register_type::reg5_5>>>;

  using BRK = templates::basic_instruction<
      AArch64_INS_BRK, 0xD4'20'00'00,
      utils::property<templates::offset_operand,
                      utils::val<offset_type::uimm16_5>>>;

  struct ADD : utils::properties<
                   utils::property<
                       templates::resizable_register_operand,
                       utils::val<resizable_register_type::reg5_0_size1_31>>,
                   utils::property<
                       templates::resizable_register_operand,
                       utils::val<resizable_register_type::reg5_5_size1_31>>,
                   utils::property<templates::offset_operand,
                                   utils::val<offset_type::uimm12_10>>>
  {
    static constexpr uint32_t opcode = 0x11'00'00'00;

    template <typename T = wregisters>
    ADD(T destreg = T(), T srcreg = T(), offset_t offset = 0)
        : base(opcode, offset, srcreg, destreg)
    {
    }

    template <typename T>
    void set_destination_register(T reg) noexcept
    {
      property_at<0>::set_register(reg);
    }

    template <typename T>
    void set_source_register(T reg) noexcept
    {
      property_at<1>::set_register(reg);
    }

    template <typename T>
    void set_register(T reg) noexcept
    {
      set_destination_register(reg);
      set_source_register(reg);
    }
  };

  struct SUB : utils::properties<
                   utils::property<
                       templates::resizable_register_operand,
                       utils::val<resizable_register_type::reg5_0_size1_31>>,
                   utils::property<
                       templates::resizable_register_operand,
                       utils::val<resizable_register_type::reg5_5_size1_31>>,
                   utils::property<templates::offset_operand,
                                   utils::val<offset_type::uimm12_10>>>
  {
    static constexpr uint32_t opcode = 0x51'00'00'00;

    template <typename T = wregisters>
    SUB(T destreg = T(), T srcreg = T(), offset_t offset = 0)
        : base(opcode, offset, srcreg, destreg)
    {
    }

    template <typename T>
    void set_destination_register(T reg) noexcept
    {
      property_at<0>::set_register(reg);
    }

    template <typename T>
    void set_source_register(T reg) noexcept
    {
      property_at<1>::set_register(reg);
    }

    template <typename T>
    void set_register(T reg) noexcept
    {
      set_destination_register(reg);
      set_source_register(reg);
    }
  };

  struct CBNZ;

  struct CBZ : utils::properties<
                   utils::property<
                       templates::resizable_register_operand,
                       utils::val<resizable_register_type::reg5_0_size1_31>>,
                   utils::property<templates::offset_operand,
                                   utils::val<offset_type::imm19_5_pad2>>>
  {
    static constexpr uint32_t             opcode = 0x34'00'00'00;
    static constexpr templates::insn_id_t id     = AArch64_INS_CBZ;

    CBZ(CBNZ other);

    template <typename T = wregisters>
    CBZ(offset_t offset = 0, T reg = T()) : base(opcode, offset, reg)
    {
    }
  };

  struct CBNZ : utils::properties<
                    utils::property<
                        templates::resizable_register_operand,
                        utils::val<resizable_register_type::reg5_0_size1_31>>,
                    utils::property<templates::offset_operand,
                                    utils::val<offset_type::imm19_5_pad2>>>
  {
    static constexpr uint32_t             opcode = 0x35'00'00'00;
    static constexpr templates::insn_id_t id     = AArch64_INS_CBNZ;

    CBNZ(CBZ other)
        : CBNZ(static_cast<CBNZ&>(static_cast<INSTRUCTION&>(
              (other.instr &= ~CBZ::opcode, other.instr |= opcode, other))))
    {
    }

    template <typename T = wregisters>
    CBNZ(offset_t offset = 0, T reg = T()) : base(opcode, offset, reg)
    {
    }
  };

  inline CBZ::CBZ(CBNZ other)
      : CBZ(static_cast<CBZ&>(static_cast<INSTRUCTION&>(
            (other.instr &= ~CBNZ::opcode, other.instr |= opcode, other))))
  {
  }

  struct TBNZ;

  struct TBZ : templates::basic_instruction<
                   AArch64_INS_TBZ, 0x36'00'00'00,
                   utils::property<templates::offset_operand,
                                   utils::val<offset_type::imm14_5_pad2>>,
                   utils::property<templates::register_operand,
                                   utils::val<register_type::reg5_5>>,
                   utils::property<templates::bitpos_operand>>
  {
    using instr_base::instr_base;

    TBZ(TBNZ other);
  };

  struct TBNZ : templates::basic_instruction<
                    AArch64_INS_TBNZ, 0x37'00'00'00,
                    utils::property<templates::offset_operand,
                                    utils::val<offset_type::imm14_5_pad2>>,
                    utils::property<templates::register_operand,
                                    utils::val<register_type::reg5_5>>,
                    utils::property<templates::bitpos_operand>>
  {
    using instr_base::instr_base;

    TBNZ(TBZ other)
        : TBNZ(static_cast<TBNZ&>(static_cast<INSTRUCTION&>(
              (other.instr &= ~TBZ::opcode, other.instr |= opcode, other))))
    {
    }
  };

  inline TBZ::TBZ(TBNZ other)
      : TBZ(static_cast<TBZ&>(static_cast<INSTRUCTION&>(
            (other.instr &= ~TBNZ::opcode, other.instr |= opcode, other))))
  {
  }

  struct LDR_post
      : utils::properties<
            utils::property<
                templates::resizable_register_operand,
                utils::val<resizable_register_type::reg5_0_size1_30>>,
            utils::property<templates::register_operand,
                            utils::val<register_type::reg5_5>>,
            utils::property<templates::offset_operand,
                            utils::val<offset_type::imm9_12>>>
  {
    static constexpr uint32_t opcode = 0xB8'40'04'00;

    template <typename T>
    LDR_post(T destreg = T(), reg_t basereg = X0, offset_t offset = 0)
        : base(opcode, offset, basereg, destreg)
    {
    }

    template <typename T>
    void set_destination_register(T reg) noexcept
    {
      property_at<0>::set_register(reg);
    }

    void set_base_register(reg_t reg) noexcept
    {
      property_at<1>::set_register(reg);
    }

    void set_register(register_t) noexcept = delete;
    template <typename T>
    void set_register(T) noexcept = delete;
  };

  struct LDR_LITERAL
      : utils::properties<
            utils::property<
                templates::resizable_register_operand,
                utils::val<resizable_register_type::reg5_0_size1_30>>,
            utils::property<templates::offset_operand,
                            utils::val<offset_type::imm19_5_pad2>>>
  {
    static constexpr uint32_t opcode = 0x18'00'00'00;

    template <typename T = wregisters>
    LDR_LITERAL(T reg = T(), offset_t offset = 0) : base(opcode, offset, reg)
    {
    }
  };

  struct LDRSW_LITERAL
      : utils::properties<
            utils::property<templates::register_operand,
                            utils::val<register_type::reg5_0>>,
            utils::property<templates::offset_operand,
                            utils::val<offset_type::imm19_5_pad2>>>
  {
    static constexpr uint32_t opcode = 0x98'00'00'00;

    LDRSW_LITERAL(register_t reg = X0, offset_t offset = 0)
        : base(opcode, offset, reg)
    {
    }
  };

  struct LDRV_LITERAL
      : utils::properties<
            utils::property<
                templates::resizable_register_operand,
                utils::val<resizable_register_type::reg5_0_size2_30>>,
            utils::property<templates::offset_operand,
                            utils::val<offset_type::imm19_5_pad2>>>
  {
    static constexpr uint32_t opcode = 0x1C'00'00'00;

    template <typename T = wregisters>
    LDRV_LITERAL(T reg = T(), offset_t offset = 0) : base(opcode, offset, reg)
    {
    }
  };

  struct STR_pre
      : utils::properties<
            utils::property<
                templates::resizable_register_operand,
                utils::val<resizable_register_type::reg5_0_size1_30>>,
            utils::property<templates::register_operand,
                            utils::val<register_type::reg5_5>>,
            utils::property<templates::offset_operand,
                            utils::val<offset_type::imm9_12>>>
  {
    static constexpr uint32_t opcode = 0xB8'00'0C'00;

    template <typename T = xregisters>
    STR_pre(T srcreg = T(), register_t basereg = X0, offset_t offset = 0)
        : base(opcode, offset, basereg, srcreg)
    {
    }

    template <typename T>
    void set_source_register(T reg) noexcept
    {
      property_at<0>::set_register(reg);
    }

    void set_base_register(register_t reg) noexcept
    {
      property_at<1>::set_register(reg);
    }

    void set_register(register_t) noexcept = delete;
    template <typename T>
    void set_register(T) noexcept = delete;
  };

  struct NOP : INSTRUCTION
  {
    static constexpr uint32_t opcode = 0xD5'03'20'1F;

    NOP() : INSTRUCTION(opcode) {}
  };

  namespace custom
  {
    struct FULL_JMP
    {
      const LDR_LITERAL ldr{ xregisters::X17, 2 * sizeof(INSTRUCTION) };
      const BR          br{ X17 };
      uint64_t          address = 0;

      FULL_JMP(uint64_t address = 0) : address(address) {}
    };

    struct [[gnu::packed]] ALIGNED_FULL_JMP
    {
      const LDR_LITERAL ldr{ xregisters::X17, 3 * sizeof(INSTRUCTION) };
      const BR          br{ X17 };
      const BRK         brk{ 0 };
      uint64_t          address = 0;

      ALIGNED_FULL_JMP(uint64_t address = 0) : address(address) {}
    };

    struct FULL_JUMP_FROM_ABOVE
    {
      uint64_t address = 0;
      const LDR_LITERAL ldr{ xregisters::X17,
                             -static_cast<int32_t>(sizeof(uint64_t)) };
      const BR          br{ X17 };

      FULL_JUMP_FROM_ABOVE(uint64_t address = 0) : address(address) {}
    };

    struct JMP
    {
      const LDR_LITERAL ldr;
      const BR          br{ X17 };

      JMP(int32_t ldr_offset = 0) : ldr(xregisters::X17, ldr_offset) {}
    };

    struct CONDITIONAL_JMP
    {
      const B_cond conditional_b;
      JMP          jmp;

      CONDITIONAL_JMP(AArch64CC_CondCode condition, int32_t ldr_offset)
          : conditional_b(8, AArch64CC_getInvertedCondCode(condition)),
            jmp(ldr_offset)
      {
      }
    };

    struct JMP_IF_ZERO
    {
      const CBNZ cbnz;
      JMP        jmp;

      JMP_IF_ZERO(CBZ cbz, int32_t ldr_offset)
          : cbnz((cbz.set_offset(8), cbz)), jmp(ldr_offset)
      {
      }
    };

    struct JMP_IF_NOT_ZERO
    {
      const CBZ cbz;
      JMP       jmp;

      JMP_IF_NOT_ZERO(CBNZ cbnz, int32_t ldr_offset)
          : cbz((cbnz.set_offset(8), cbnz)), jmp(ldr_offset)
      {
      }
    };

    struct TEST_JMP_ON_ZERO
    {
      const TBNZ tbnz;
      JMP        jmp;

      TEST_JMP_ON_ZERO(TBZ tbz, int32_t ldr_offset)
          : tbnz((tbz.set_offset(8), tbz)), jmp(ldr_offset)
      {
      }
    };

    struct TEST_JMP_ON_NON_ZERO
    {
      const TBZ tbz;
      JMP       jmp;

      TEST_JMP_ON_NON_ZERO(TBNZ tbnz, int32_t ldr_offset)
          : tbz((tbnz.set_offset(8), tbnz)), jmp(ldr_offset)
      {
      }
    };

    struct CALL
    {
      const LDR_LITERAL ldr;
      const BLR         blr{ X17 };

      CALL(int32_t ldr_offset = 0) : ldr(xregisters::X17, ldr_offset) {}
    };

    template <typename T>
    struct LDR_LIKE_ABS
    {
    private:
      typedef typename LDR_LITERAL::offset_t fetch_offset_t;

      LDR_LITERAL fetch_ldr;
      T           ldr;

    public:
      LDR_LIKE_ABS(reg_t reg = X0, reg_t tmp_reg = X0, int32_t fetch_offset = 0)
          : fetch_ldr(static_cast<xregisters>(tmp_reg), fetch_offset),
            ldr(reg, tmp_reg, 0)
      {
      }

      void set_register(aarch64::xregisters reg)
      {
        fetch_ldr.set_register(reg);
        ldr.set_base_register(static_cast<reg_t>(reg));
      }

      fetch_offset_t get_fetch_offset() const noexcept
      {
        return fetch_ldr.get_offset();
      }

      void set_fetch_offset(fetch_offset_t offset) noexcept
      {
        fetch_ldr.set_offset(offset);
      }
    };

    using LDR32_ABS   = LDR_LIKE_ABS<LDRu32>;
    using LDR64_ABS   = LDR_LIKE_ABS<LDRu64>;
    using LDRSW_ABS   = LDR_LIKE_ABS<LDRSWu>;
    using LDRV32_ABS  = LDR_LIKE_ABS<LDRVu32>;
    using LDRV64_ABS  = LDR_LIKE_ABS<LDRVu64>;
    using LDRV128_ABS = LDR_LIKE_ABS<LDRVu128>;

    // acts as a tag for pc handling
    struct DATA_FETCH : LDR_LITERAL
    {
      using LDR_LITERAL::LDR_LITERAL;
    };

    // tag for final branch
    struct SHORT_JMP : B
    {
      using B::B;
    };

    typedef utils::type_sequence<LDR32_ABS, LDR64_ABS, LDRSW_ABS, LDRV32_ABS,
                                 LDRV64_ABS, LDRV128_ABS>
        absolute_loads;

    // note: there are no actual push/pop instructions in the aarch64
    // architecture, reason being that the stack pointer needs to be 16 bytes
    // aligned and considering that a regular register requires maximum 8
    // bytes, a push instruction would waste an additional of 8 bytes
    // each time it's used leading to memory fragmentation. I have decided to
    // provide them nevertheless for use in PC handling where they are used only
    // once and always in pairs before the trampoline ends. The way the
    // following implementations of push/pop work is by using a pre-indexed str
    // that subtracts 16 from SP and a post-indexed ldr that adds 16 to SP
    // respectively.
    // source:
    // https://community.arm.com/arm-community-blogs/b/architectures-and-processors-blog/posts/using-the-stack-in-aarch64-implementing-push-and-pop
    struct PUSH : private STR_pre
    {
      template <typename T = xregisters>
      PUSH(T reg = T()) : STR_pre(reg, SP, -16)
      {
      }

      template <typename T>
      void set_register(T reg) noexcept
      {
        STR_pre::set_source_register(reg);
      }
    };

    struct POP : private LDR_post
    {
      template <typename T = xregisters>
      POP(T reg = T()) : LDR_post(reg, SP, 16)
      {
      }

      template <typename T>
      void set_register(T reg) noexcept
      {
        LDR_post::set_destination_register(reg);
      }
    };

    typedef typename utils::type_sequence<
        SHORT_JMP, FULL_JMP, JMP, CONDITIONAL_JMP, JMP_IF_ZERO, JMP_IF_NOT_ZERO,
        TEST_JMP_ON_ZERO, TEST_JMP_ON_NON_ZERO, CALL, PUSH,
        POP>::template merge<absolute_loads>
        all_custom;
  } // namespace custom

  // clang-format off
  inline bool is_xreg(aarch64_reg reg) noexcept
  {
    switch (reg)
    {
    case AArch64_REG_X0:  case AArch64_REG_X1:  case AArch64_REG_X2:
    case AArch64_REG_X3:  case AArch64_REG_X4:  case AArch64_REG_X5:
    case AArch64_REG_X6:  case AArch64_REG_X7:  case AArch64_REG_X8:
    case AArch64_REG_X9:  case AArch64_REG_X10: case AArch64_REG_X11:
    case AArch64_REG_X12: case AArch64_REG_X13: case AArch64_REG_X14:
    case AArch64_REG_X15: case AArch64_REG_X16: case AArch64_REG_X17:
    case AArch64_REG_X18: case AArch64_REG_X19: case AArch64_REG_X20: 
    case AArch64_REG_X21: case AArch64_REG_X22: case AArch64_REG_X23:
    case AArch64_REG_X24: case AArch64_REG_X25: case AArch64_REG_X26:
    case AArch64_REG_X27: case AArch64_REG_X28: case AArch64_REG_X29:
    case AArch64_REG_X30: return true;
    default: return false;
    }
  }

  inline std::optional<reg_t> map_cs_reg(aarch64_reg reg) noexcept
  {
    switch (reg)
    {
    case AArch64_REG_W0:  case AArch64_REG_X0:  return X0;
    case AArch64_REG_W1:  case AArch64_REG_X1:  return X1;
    case AArch64_REG_W2:  case AArch64_REG_X2:  return X2;
    case AArch64_REG_W3:  case AArch64_REG_X3:  return X3;
    case AArch64_REG_W4:  case AArch64_REG_X4:  return X4;
    case AArch64_REG_W5:  case AArch64_REG_X5:  return X5;
    case AArch64_REG_W6:  case AArch64_REG_X6:  return X6;
    case AArch64_REG_W7:  case AArch64_REG_X7:  return X7;
    case AArch64_REG_W8:  case AArch64_REG_X8:  return X8;
    case AArch64_REG_W9:  case AArch64_REG_X9:  return X9;
    case AArch64_REG_W10: case AArch64_REG_X10: return X10;
    case AArch64_REG_W11: case AArch64_REG_X11: return X11;
    case AArch64_REG_W12: case AArch64_REG_X12: return X12;
    case AArch64_REG_W13: case AArch64_REG_X13: return X13;
    case AArch64_REG_W14: case AArch64_REG_X14: return X14;
    case AArch64_REG_W15: case AArch64_REG_X15: return X15;
    case AArch64_REG_W16: case AArch64_REG_X16: return X16;
    case AArch64_REG_W17: case AArch64_REG_X17: return X17;
    case AArch64_REG_W18: case AArch64_REG_X18: return X18;
    case AArch64_REG_W19: case AArch64_REG_X19: return X19;
    case AArch64_REG_W20: case AArch64_REG_X20: return X20;
    case AArch64_REG_W21: case AArch64_REG_X21: return X21;
    case AArch64_REG_W22: case AArch64_REG_X22: return X22;
    case AArch64_REG_W23: case AArch64_REG_X23: return X23;
    case AArch64_REG_W24: case AArch64_REG_X24: return X24;
    case AArch64_REG_W25: case AArch64_REG_X25: return X25;
    case AArch64_REG_W26: case AArch64_REG_X26: return X26;
    case AArch64_REG_W27: case AArch64_REG_X27: return X27;
    case AArch64_REG_W28: case AArch64_REG_X28: return X28;
    case AArch64_REG_W29: case AArch64_REG_X29: return X29;
    case AArch64_REG_W30: case AArch64_REG_X30: return X30;
    default: return std::nullopt;
    }
  }

  // clang-format on
} // namespace alterhook::aarch64

#pragma GCC visibility pop