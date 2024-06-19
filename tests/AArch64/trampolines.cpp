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
  alterhook::trampoline trampoline{ aarch64::test2::func_ptr };
  aarch64::test2::func_ptr(0);
  trampoline.invoke<void(size_t)>(0);
  aarch64::test2::func_ptr(8);
  trampoline.invoke<void(size_t)>(8);
  std::cout << "CONTENT:\n" << trampoline.str() << '\n';
}

TEST(TrampolineTest, Test3)
{
  alterhook::trampoline trampoline{ aarch64::test3::func_ptr };
  aarch64::test3::func_ptr(1);
  trampoline.invoke<void(size_t)>(1);
  aarch64::test3::func_ptr(0b10);
  trampoline.invoke<void(size_t)>(0b10);
  std::cout << "CONTENT:\n" << trampoline.str() << '\n';
}

TEST(TrampolineTest, Test4) 
{
  alterhook::trampoline trampoline{ aarch64::test4::func_ptr };
  aarch64::test4::func_ptr(-2);
  trampoline.invoke<void(int64_t)>(-2);
  aarch64::test4::func_ptr(0);
  trampoline.invoke<void(int64_t)>(0);
  std::cout << "CONTENT:\n" << trampoline.str() << '\n';
}

TEST(TrampolineTest, Test5)
{
  alterhook::trampoline trampoline{ aarch64::test5::func_ptr };
  aarch64::test5::func_ptr(1);
  trampoline.invoke<void(size_t)>(1);
  aarch64::test5::func_ptr(0);
  trampoline.invoke<void(size_t)>(0);
  std::cout << "CONTENT:\n" << trampoline.str() << '\n';
}
