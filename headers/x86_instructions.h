/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once

namespace alterhook
{
  utils_pack_begin()

  struct utils_packed JMP_SHORT
  {
    uint8_t opcode = 0xEB;
    uint8_t offset = 0;
  };

  struct utils_packed JMP
  {
    uint8_t  opcode = 0xE9;
    uint32_t offset = 0;
  };

  struct utils_packed JMP_ABS
  {
    uint8_t  opcode  = 0xFF;
    uint8_t  modrm   = 0x25;
    uint32_t imm     = 0;
    uint64_t address = 0;
  };

  struct utils_packed CALL
  {
    uint8_t  opcode = 0xE8;
    uint32_t offset = 0;
  };

  struct utils_packed CALL_ABS
  {
    uint8_t   opcode = 0xFF;
    uint8_t   modrm  = 0x15;
    uint32_t  imm    = 2;
    JMP_SHORT jmp    = {
         .offset = 8
    }; // needed to skip the 64 bit address when call returns
    uint64_t address = 0;
  };

  struct utils_packed JCC
  {
    uint8_t  opcode1 = 0x0F;
    uint8_t  opcode2 = 0x80;
    uint32_t offset  = 0;
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
  };

  utils_pack_end()
}
