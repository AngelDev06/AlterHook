#include <iostream>
#include <optional>
#include <array>
#include <gtest/gtest.h>
#include "trampolines_general.h"

#if utils_gcc
  #pragma GCC push_options
  #pragma GCC optimize("O0")
#endif

#ifdef TEST_TARGET_ARM
  #define test_target()         target("arm")
  #define test_target_namespace arm
  #define test_group(x)         Arm##x
  #define test_asm_symbol(x)    "ARM" #x
#else
  #define test_target()         target("thumb")
  #define test_target_namespace thumb
  #define test_group(x)         Thumb##x
  #define test_asm_symbol(x)    "THUMB" #x
#endif

#define target_prefix ::test_target_namespace::

namespace test_target_namespace
{
  namespace test1
  {
    __attribute__((naked, optnone, test_target())) void func()
    {
      asm(R"(push { lr }
             add r1, pc, #8
             sub r0, r1, r0
             bl print_uint
             pop { pc })");
    }
  } // namespace test1

  namespace test2
  {
    __attribute__((naked, optnone, test_target())) void func()
    {
      asm(R"(push { lr }
             cmp r0, r1
             it EQ
             bleq print_uint
             pop { pc })");
    }
  } // namespace test2

  namespace test3
  {
    __attribute__((naked, optnone, test_target())) void func()
    {
      asm(R"(push { lr }
             ldrb r0, 0f
             add r0, pc
             bl print_hex
             pop { pc }
             0:
             .byte 15)");
    }
  } // namespace test3

  namespace test4
  {
    __attribute__((naked, optnone, test_target())) void func()
    {
      asm(R"(add r0, pc
             push { r1, r2, lr }
             mov r1, pc
             pop { r1, r2 }
             bl print_hex
             pop { pc })");
    }
  } // namespace test4

  namespace test5
  {
    __attribute__((naked, optnone, test_target())) void func()
    {
      asm(R"(adr r4, 0f
             ldm r4, { r0, r1, r2, r3 }
             b print_4
             .p2align 2
             0:
             .long 268435455
             .long 192943939
             .long 394939294
             .long 399294395)");
    }
  } // namespace test5

  namespace test6
  {
    __attribute__((naked, optnone, test_target())) void func()
    {
      asm(R"(ldr r0, [r0]
             bx r0)");
    }
  } // namespace test6

  namespace test7
  {
    __attribute__((naked, optnone, test_target())) void func()
    {
      asm(R"(mov r0, pc
             add r1, pc, #12
             eor r0, r1
             push { lr }
             bl print_hex
             pop { pc })");
    }
  } // namespace test7

  namespace test8
  {
    __attribute__((naked, optnone, test_target())) void func()
    {
      asm(R"(mov r1, pc
             it AL
             addal r0, pc
             orr r0, r1
             push { lr }
             bl print_hex
             pop { pc })");
    }
  } // namespace test8

  namespace test9
  {
    __attribute__((naked, optnone, test_target())) void func()
    {
      asm(R"(ittt AL
             moval r0, #5
             addal r0, pc
             lsral r0, #8
             push { lr }
             bl print_hex
             pop { pc })");
    }
  } // namespace test9

  namespace test10
  {
    __attribute__((naked, optnone, test_target())) void func()
    {
      asm(R"(itte EQ
             mvneq r0, r0
             addeq r0, pc
             movne r0, pc
             b print_hex)");
    }

    __attribute__((naked, optnone)) void proper_call()
    {
      asm(R"(push { r4, r5, lr }
             mov r4, r0
             mov r5, r1
             mov r0, #85
             cmp r0, r0
             blx r4
             mov r0, #85
             cmp r0, r0
             blx r5
             mov r0, #85
             cmn r0, r0
             blx r4
             mov r0, #85
             cmn r0, r0
             blx r5
             pop { r4, r5, pc })");
    }
  } // namespace test10

  namespace test11
  {
    __attribute__((naked, optnone, test_target())) void func()
    {
      asm(R"(b 0f
             b print_hex
            0:
             b print_uint)");
    }
  } // namespace test11

  namespace test12
  {
    __attribute__((naked, optnone, test_target())) void func()
    {
      asm(R"(beq 1f
             b 0f
            1:
             b print_uint
             nop
            0:
             mov pc, lr)");
    }

    __attribute__((naked, optnone)) void proper_call()
    {
      asm(R"(push { r0, r1, lr }
             cmp r0, r0
             blx r0
             cmp r0, r0
             pop { r0, r1 }
             blx r1 
             pop { pc })");
    }
  } // namespace test12
} // namespace test_target_namespace

#if utils_gcc
  #pragma GCC pop_options
#endif