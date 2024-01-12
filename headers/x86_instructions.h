/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#if !utils_windows
  #pragma GCC visibility push(hidden)
#endif

namespace alterhook
{
  // clang-format off
  utils_pack_begin()

  struct utils_packed JMP_SHORT
  {
    static constexpr uint8_t opcode = 0xEB;
    const uint8_t id = opcode;
    int8_t offset = 0;

    constexpr JMP_SHORT(int8_t offset) : offset(offset) {}
  };

  // clang-format on

  struct utils_packed JMP
  {
    static constexpr uint8_t opcode = 0xE9;
    const uint8_t            id     = opcode;
    int32_t                  offset = 0;

    constexpr JMP(int32_t offset) : offset(offset) {}

    constexpr uintptr_t destination(uintptr_t src) const
    {
      return src + offset + sizeof(JMP);
    }
  };

  struct utils_packed MOV
  {
    static constexpr uint8_t opcode = 0b10111;
    uint8_t                  reg : 3;
    const uint8_t            id  : 5;
    uint32_t                 imm = 0;

    constexpr MOV(uint8_t reg, uint32_t imm) : reg(reg), id(opcode), imm(imm) {}
  };

  struct utils_packed JMP_ABS
  {
    typedef std::pair<uint8_t, uint8_t> opcode_t;

    static constexpr opcode_t opcode  = { 0xFF, 0x25 };
    const opcode_t            id      = opcode;
    const uint32_t            imm     = 0;
    uint64_t                  address = 0;

    constexpr JMP_ABS(uint64_t address) : address(address) {}

    constexpr JMP_ABS() {}
  };

  struct utils_packed CALL
  {
    static constexpr uint8_t opcode = 0xE8;
    const uint8_t            id     = opcode;
    int32_t                  offset = 0;

    constexpr CALL(int32_t offset) : offset(offset) {}
  };

  namespace helpers
  {
    // very stupid clang thanks
    struct utils_packed CALL_ABS_OPCODE
    {
      uint8_t   opcode = 0xFF;
      uint8_t   modrm  = 0x15;
      uint32_t  imm    = 2;
      JMP_SHORT jmp{ 8 };
    };
  } // namespace helpers

  struct utils_packed CALL_ABS
  {
    typedef helpers::CALL_ABS_OPCODE opcode_t;

    static constexpr opcode_t opcode{};
    const opcode_t            id      = opcode;
    uint64_t                  address = 0;

    constexpr CALL_ABS(uint64_t address) : address(address) {}
  };

  struct utils_packed JCC
  {
    typedef std::pair<uint8_t, uint8_t> opcode_t;

    static constexpr opcode_t opcode = { 0x0F, 0x80 };
    const opcode_t            id     = opcode;
    int32_t                   offset = 0;

    constexpr JCC(uint8_t opcode2, int32_t offset)
        : id({ 0x0F, opcode2 }), offset(offset)
    {
    }

    constexpr JCC(int32_t offset) : offset(offset) {}
  };

  // not putting JMP_ABS in here to keep this easy to use
  struct utils_packed JCC_ABS
  {
    typedef std::array<uint8_t, 4> opcode_t;

    static constexpr opcode_t opcode  = { 0x70, 14, 0xFF, 0x25 };
    const opcode_t            id      = opcode;
    const uint32_t            jmp_imm = 0;
    uint64_t                  address = 0;

    constexpr JCC_ABS(uint8_t base_opcode, uint64_t address)
        : id({ base_opcode, 14, 0xFF, 0x25 }), address(address)
    {
    }

    constexpr JCC_ABS(uint64_t address) : address(address) {}
  };

  utils_pack_end()
} // namespace alterhook

#if !utils_windows
  #pragma GCC visibility pop
#endif