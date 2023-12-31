/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once

namespace alterhook
{
  // clang-format off
  utils_pack_begin()

  struct utils_packed JMP_SHORT
  {
    uint8_t opcode = 0xEB;
    uint8_t offset = 0;

    JMP_SHORT(uint8_t offset) : offset(offset) {}
  };

  // clang-format on

  struct utils_packed JMP
  {
    uint8_t  opcode = 0xE9;
    uint32_t offset = 0;

    JMP(uint32_t offset) : offset(offset) {}
  };

  struct utils_packed MOV
  {
    uint8_t  reg    : 3;
    uint8_t  opcode : 5;
    uint32_t imm = 0;

    MOV(uint8_t reg, uint32_t imm) : reg(reg), opcode(0b10111), imm(imm) {}
  };

  struct utils_packed JMP_ABS
  {
    uint8_t  opcode  = 0xFF;
    uint8_t  modrm   = 0x25;
    uint32_t imm     = 0;
    uint64_t address = 0;

    JMP_ABS(uint64_t address) : address(address) {}

    JMP_ABS() {}
  };

  struct utils_packed CALL
  {
    uint8_t  opcode = 0xE8;
    uint32_t offset = 0;

    CALL(uint32_t offset) : offset(offset) {}
  };

  struct utils_packed CALL_ABS
  {
    uint8_t   opcode = 0xFF;
    uint8_t   modrm  = 0x15;
    uint32_t  imm    = 2;
    JMP_SHORT jmp{ 8 };
    uint64_t  address = 0;

    CALL_ABS(uint64_t address) : address(address) {}
  };

  struct utils_packed JCC
  {
    uint8_t  opcode1 = 0x0F;
    uint8_t  opcode2 = 0x80;
    uint32_t offset  = 0;

    JCC(uint8_t opcode2, uint32_t offset) : opcode2(opcode2), offset(offset) {}
  };

  // not putting JMP_ABS in here to keep this easy to use
  struct utils_packed JCC_ABS
  {
    uint8_t  opcode     = 0x70;
    uint8_t  offset     = 14;
    uint8_t  jmp_opcode = 0xFF;
    uint8_t  jmp_modrm  = 0x25;
    uint32_t jmp_imm    = 0;
    uint64_t address    = 0;

    JCC_ABS(uint8_t opcode, uint64_t address) : opcode(opcode), address(address)
    {
    }
  };

  utils_pack_end()
} // namespace alterhook
