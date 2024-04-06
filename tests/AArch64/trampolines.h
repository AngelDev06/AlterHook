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
}

extern "C"
{
  void print_uint(size_t arg) { print_args(arg); }

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

    static auto func_ptr = reinterpret_cast<void (*volatile)()>(
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
  } // namespace test2
} // namespace aarch64
