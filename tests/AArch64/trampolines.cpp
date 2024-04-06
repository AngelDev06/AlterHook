#include "trampolines.h"

TEST(TrampolineTest, Test1)
{
  alterhook::trampoline trampoline{ aarch64::test1::func_ptr };
  aarch64::test1::func_ptr();
  trampoline.invoke<void()>();
  std::cout << "CONTENT:\n" << trampoline.str() << '\n';
}

TEST(TrampolineTest, Test2)
{
  volatile auto func = reinterpret_cast<void (*)(size_t)>(aarch64::test2::func);
  alterhook::trampoline trampoline{ func };
  func(0);
  trampoline.invoke<void(size_t)>(0);
  func(8);
  trampoline.invoke<void(size_t)>(8);
  std::cout << "CONTENT:\n" << trampoline.str() << '\n';
}
