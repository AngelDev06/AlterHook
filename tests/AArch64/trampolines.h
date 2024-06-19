#include <iostream>
#include <optional>
#include <gtest/gtest.h>
#include <alterhook/trampoline.h>

template <typename T>
void print_arg(T&& arg)
{
  std::cout << ' ' << arg;
}

template <typename... types>
void print_args(types&&... args)
{
  typedef std::tuple<alterhook::utils::remove_cvref_t<types>...> tuple_t;
  static std::optional<tuple_t> prev = std::nullopt;
  if (prev)
  {
    EXPECT_EQ(prev.value(), std::tuple(std::forward<types>(args)...));
    prev = std::nullopt;
  }
  else
    prev = std::tuple(std::forward<types>(args)...);

  std::cout << "data:";
  (print_arg(std::forward<types>(args)), ...);
  std::cout << '\n';
}

extern "C"
{
  void print_uint(size_t arg) { print_args(arg); }

  void print_signed(int64_t arg) { print_args(arg); }

  void print_hex(size_t arg)
  {
    static std::optional<size_t> prev = std::nullopt;
    if (prev)
    {
      EXPECT_EQ(prev.value(), arg);
      prev = std::nullopt;
    }
    else
      prev = arg;

    std::cout << "hex: " << std::hex << arg << std::dec << '\n';
  }

  void print_empty() { std::cout << "empty\n"; }

  void print_float(float arg) { print_args(arg); }
}

namespace aarch64
{
  namespace test1
  {
    [[gnu::naked, clang::optnone, gnu::aligned(8)]] void func()
    {
      asm(R"(brk 0xf000
             stp fp, lr, [sp, #-16]!
             ldr X0, 0f
             bl print_hex
             ldp fp, lr, [sp], #16
             ret
             .p2align 3
             0:
             .xword 281474976710655)");
    }

    static const volatile auto func_ptr = reinterpret_cast<void (*)()>(
        reinterpret_cast<uintptr_t>(func) + sizeof(uint32_t));
  } // namespace test1

  namespace test2
  {
    [[gnu::naked, clang::optnone, gnu::aligned(8)]] void func()
    {
      asm(R"(cbz X0, 0f
             b print_hex
             0:
             stp fp, lr, [sp, #-16]!
             bl print_empty
             ldp fp, lr, [sp], #16
             ret)");
    }

    static const volatile auto func_ptr =
        reinterpret_cast<void (*)(size_t)>(func);
  } // namespace test2

  namespace test3
  {
    [[gnu::naked, clang::optnone, gnu::aligned(8)]] void func()
    {
      asm(R"(brk 0xf000
             tbz X0, #1, 0f
             ldr X0, 2f
             b 1f
             0:
             b print_uint
             1:
             b print_hex
             .p2align 3
             2:
             .xword 281474976710655)");
    }

    static const volatile auto func_ptr = reinterpret_cast<void (*)(size_t)>(
        reinterpret_cast<uintptr_t>(func) + sizeof(uint32_t));
  } // namespace test3

  namespace test4
  {
    [[gnu::naked, clang::optnone, gnu::aligned(8)]] void func()
    {
      asm(R"(ldrsw X1, 0f
             cmp X0, X1
             b.eq print_signed
             b print_hex
             0:
             .word -2)");
    }

    static const volatile auto func_ptr =
        reinterpret_cast<void (*)(int64_t)>(func);
  } // namespace test4

  namespace test5
  {
    [[gnu::naked, clang::optnone, gnu::aligned(8)]] void func()
    {
      asm(R"(cmp X0, #1
             b.eq 0f
             ldr S0, 1f
             b print_float
             0:
             b print_uint
             1:
             .float 3.14159265359)");
    }

    static const volatile auto func_ptr =
        reinterpret_cast<void (*)(size_t)>(func);
  }
} // namespace aarch64
