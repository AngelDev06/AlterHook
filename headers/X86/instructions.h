/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#pragma GCC visibility push(hidden)
#pragma pack(push, 1)

namespace alterhook
{
  struct JMP_SHORT
  {
    static constexpr uint8_t opcode = 0xEB;
    const uint8_t            id     = opcode;
    int8_t                   offset = 0;

    constexpr JMP_SHORT(int8_t offset) : offset(offset) {}
  };

  struct JMP
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

  struct MOV
  {
    static constexpr uint8_t opcode = 0b10111;
    uint8_t                  reg : 3;
    const uint8_t            id  : 5;
    uint32_t                 imm = 0;

    constexpr MOV(uint8_t reg, uint32_t imm) : reg(reg), id(opcode), imm(imm) {}
  };

  struct JMP_ABS
  {
    typedef std::array<uint8_t, 2> opcode_t;

    static constexpr opcode_t opcode  = { 0xFF, 0x25 };
    const opcode_t            id      = opcode;
    const uint32_t            imm     = 0;
    uint64_t                  address = 0;

    constexpr JMP_ABS(uint64_t address) : address(address) {}

    constexpr JMP_ABS() {}
  };

  struct CALL
  {
    static constexpr uint8_t opcode = 0xE8;
    const uint8_t            id     = opcode;
    int32_t                  offset = 0;

    constexpr CALL(int32_t offset) : offset(offset) {}
  };

  struct CALL_ABS
  {
    typedef std::array<uint8_t, 2> opcode_t;

    static constexpr opcode_t opcode = { 0xFF, 0x15 };
    const opcode_t            id     = opcode;
    const uint32_t            imm    = 2;
    const JMP_SHORT           jmp{ 8 };
    uint64_t                  address = 0;

    constexpr CALL_ABS(uint64_t address) : address(address) {}
  };

  struct JCC
  {
    typedef std::array<uint8_t, 2> opcode_t;

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
  struct JCC_ABS
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
} // namespace alterhook

#pragma GCC visibility pop
#pragma pack(pop)
