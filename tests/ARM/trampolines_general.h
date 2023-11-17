#pragma once
#include <iostream>
#include <optional>
#include <gtest/gtest.h>

extern "C"
{
  void print_uint(size_t arg)
  {
    static std::optional<size_t> prev_result{};
    if (prev_result.has_value())
    {
      EXPECT_EQ(prev_result.value(), arg);
      prev_result = std::nullopt;
    }
    else
      prev_result = arg;

    std::cout << "uint: " << arg << '\n';
  }

  void print_hex(size_t arg)
  {
    static std::optional<size_t> prev_result{};
    if (prev_result.has_value())
    {
      EXPECT_EQ(prev_result.value(), arg);
      prev_result = std::nullopt;
    }
    else
      prev_result = arg;

    std::cout << "hex: " << std::hex << arg << std::dec << '\n';
  }

  void print_4(size_t arg1, size_t arg2, size_t arg3, size_t arg4)
  {
    static std::optional<std::array<size_t, 4>> prev_result{};
    if (prev_result.has_value())
    {
      EXPECT_EQ(prev_result.value(), (std::array{ arg1, arg2, arg3, arg4 }));
      prev_result = std::nullopt;
    }
    else
      prev_result = std::array{ arg1, arg2, arg3, arg4 };

    std::cout << "data: " << arg1 << ' ' << arg2 << ' ' << arg3 << ' ' << arg4
              << '\n';
  }

  uintptr_t get_pc()
  {
    uintptr_t pc = 0;
    asm("mov %0, pc;"
        : "=r"(pc));
    return pc;
  }
}

namespace switches
{
  namespace test
  {
    __attribute__((naked, optnone, target("arm"))) void func()
    {
      asm(".arm;"
          "sub pc, #3;"
          ".thumb;"
          "movs r0, #3;"
          "b print_hex;");
    }
  } // namespace test
} // namespace switches