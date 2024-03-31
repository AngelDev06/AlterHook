#include "trampolines.h"

TEST(TrampolineTest, Test1)
{
  alterhook::trampoline trampoline{ aarch64::test1::func_ptr };
  aarch64::test1::func_ptr();
  trampoline.invoke<void()>();
  std::cout << "CONTENT:\n" << trampoline.str() << '\n';
}
