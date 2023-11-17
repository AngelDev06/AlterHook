#include <alterhook/trampoline.h>
#include <alterhook/exceptions.h>
#include "trampolines.h"

TEST(test_group(TrampolineTest), Test1)
{
  alterhook::trampoline trampoline{ target_prefix test1::func };
  volatile auto         pc = get_pc();
  volatile auto         func =
      reinterpret_cast<void (*)(uintptr_t)>(target_prefix test1::func);

  func(pc);
  trampoline.invoke<void(uintptr_t)>(pc);
  std::cout << "CONTENT:\n" << trampoline.str() << '\n';
}

TEST(test_group(TrampolineTest), Test2)
{
  alterhook::trampoline trampoline{ target_prefix test2::func };
  volatile auto         func =
      reinterpret_cast<void (*)(size_t, size_t)>(target_prefix test2::func);

  func(3, 3);
  trampoline.invoke<void(size_t, size_t)>(3, 3);

  func(3, 4);
  trampoline.invoke<void(size_t, size_t)>(3, 4);
  std::cout << "CONTENT:\n" << trampoline.str() << '\n';
}

TEST(test_group(TrampolineTest), Test3)
{
  alterhook::trampoline trampoline{ target_prefix test3::func };
  target_prefix         test3::func();
  trampoline.invoke<void()>();
  std::cout << "CONTENT:\n" << trampoline.str() << '\n';
}

TEST(test_group(TrampolineTest), Test4)
{
  alterhook::trampoline trampoline{ target_prefix test4::func };
  volatile auto         pc = get_pc();
  volatile auto         func =
      reinterpret_cast<void (*)(uintptr_t)>(target_prefix test4::func);

  func(pc);
  trampoline.invoke<void(uintptr_t)>(get_pc());
  std::cout << "CONTENT:\n" << trampoline.str() << '\n';
}

TEST(test_group(TrampolineTest), Test5)
{
  alterhook::trampoline trampoline{ target_prefix test5::func };
  target_prefix         test5::func();
  trampoline.invoke<void()>();
  std::cout << "CONTENT:\n" << trampoline.str() << '\n';
}

TEST(test_group(TrampolineTest), Test6)
{
#ifndef TEST_TARGET_ARM
  EXPECT_THROW(alterhook::trampoline trampoline{ target_prefix test6::func },
               alterhook::exceptions::insufficient_function_size);
#else
  alterhook::trampoline trampoline{ target_prefix test6::func };
  volatile auto         callback  = print_hex;
  volatile auto         pcallback = &callback;
  volatile auto func = reinterpret_cast<void (*)(void (*volatile*)(size_t))>(
      target_prefix test6::func);

  func(pcallback);
  trampoline.invoke<void(void (*volatile*)(size_t))>(pcallback);
#endif
}

TEST(test_group(TrampolineTest), Test7)
{
  alterhook::trampoline trampoline{ target_prefix test7::func };
  target_prefix         test7::func();
  trampoline.invoke<void()>();
  std::cout << "CONTENT:\n" << trampoline.str() << '\n';
}

TEST(test_group(TrampolineTest), Test8)
{
  alterhook::trampoline trampoline{ target_prefix test8::func };
  volatile auto         func =
      reinterpret_cast<void (*)(size_t)>(target_prefix test8::func);

  func(0);
  trampoline.invoke<void(size_t)>(0);
  std::cout << "CONTENT:\n" << trampoline.str() << '\n';
}

TEST(test_group(TrampolineTest), Test9)
{
  alterhook::trampoline trampoline{ target_prefix test9::func };
  target_prefix         test9::func();
  trampoline.invoke<void()>();
  std::cout << "CONTENT:\n" << trampoline.str() << '\n';
}

TEST(test_group(TrampolineTest), Test10)
{
  alterhook::trampoline trampoline{ target_prefix test10::func };
  volatile auto trg      = target_prefix test10::func;
  volatile auto callback = trampoline.get_callback<void()>();
  volatile auto func     = reinterpret_cast<void (*)(void (*)(), void (*)())>(
      target_prefix test10::proper_call);

  func(trg, callback);
  std::cout << "CONTENT:\n" << trampoline.str() << '\n';
}

TEST(test_group(TrampolineTest), Test11)
{
#ifndef TEST_TARGET_ARM
  alterhook::trampoline trampoline{ target_prefix test11::func };
  volatile auto         func =
      reinterpret_cast<void (*)(size_t)>(target_prefix test11::func);

  func(15);
  trampoline.invoke<void(size_t)>(15);
#else
  EXPECT_THROW(alterhook::trampoline trampoline{ target_prefix test11::func },
               alterhook::exceptions::insufficient_function_size);
#endif
}

TEST(test_group(TrampolineTest), Test12)
{
#ifndef TEST_TARGET_ARM
  EXPECT_THROW(alterhook::trampoline trampoline{ target_prefix test12::func },
               alterhook::exceptions::instructions_in_branch_handling_fail);
#else
  alterhook::trampoline trampoline{ target_prefix test12::func };
  volatile auto trg      = target_prefix test12::func;
  volatile auto callback = trampoline.get_callback<void()>();
  volatile auto func     = reinterpret_cast<void (*)(void (*)(), void (*)())>(
      target_prefix test12::proper_call);

  func(trg, callback);
  std::cout << "CONTENT:\n" << trampoline.str() << '\n';
#endif
}

#undef test_target
#undef test_target_namespace
#undef test_group
#undef test_asm_symbol