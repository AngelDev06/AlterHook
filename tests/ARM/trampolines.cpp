#include <alterhook/trampoline.h>
#include <alterhook/exceptions.h>
#include "trampoline_target_tests.h"
#define TEST_TARGET_ARM
#include "trampoline_target_tests.h"

TEST(TrampolineTest, Test)
{
  alterhook::trampoline trampoline{ switches::test::func };
  switches::test::func();
  trampoline.invoke<void()>();
  std::cout << "CONTENT:\n" << trampoline.str() << '\n';
}