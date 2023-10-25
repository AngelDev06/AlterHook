#include "testcls.h"

class HookChainTest : public testing::Test
{
protected:
  alterhook::hook_chain chain1{ &originalcls::func, &detourcls::func,
                                original,           &detourcls::func2,
                                original2,          &detourcls::func3,
                                original3 };
  alterhook::hook_chain chain2{
    &originalcls::func2, std::forward_as_tuple(&detourcls::func4, original4),
    std::forward_as_tuple(&detourcls::func5, original5),
    std::forward_as_tuple(&detourcls::func6, original6)
  };
  originalcls instance{ 1, 2, 3 };
};

TEST_F(HookChainTest, StatusUpdate)
{
  instance.func();
  verify_call_stack(func_called::originalcls_func, func_called::detourcls_func,
                    func_called::detourcls_func2, func_called::detourcls_func3);
  SAME_ORIG_RESULT(instance);

  std::cout << "-------------------------------------------\n";

  instance.func2();
  verify_call_stack(func_called::originalcls_func2,
                    func_called::detourcls_func4, func_called::detourcls_func5,
                    func_called::detourcls_func6);
  SAME_ORIG_RESULT(instance);

  std::cout << "-------------------------------------------\n";

  chain1[1].disable();
  instance.func();
  verify_call_stack(func_called::originalcls_func, func_called::detourcls_func,
                    func_called::detourcls_func3);
  SAME_ORIG_RESULT(instance);

  std::cout << "-------------------------------------------\n";

  chain1.disable_all();
  instance.func();
  verify_call_stack(func_called::originalcls_func);
  SAME_ORIG_RESULT(instance);

  std::cout << "-------------------------------------------\n";

  chain1[2].enable();
  instance.func();
  verify_call_stack(func_called::originalcls_func,
                    func_called::detourcls_func3);
  SAME_ORIG_RESULT(instance);

  std::cout << "-------------------------------------------\n";

  chain2[0].disable();
  instance.func2();
  verify_call_stack(func_called::originalcls_func2,
                    func_called::detourcls_func5, func_called::detourcls_func6);
  SAME_ORIG_RESULT(instance);

  std::cout << "-------------------------------------------\n";

  chain2.enable_all();
  instance.func2();
  verify_call_stack(func_called::originalcls_func2,
                    func_called::detourcls_func4, func_called::detourcls_func5,
                    func_called::detourcls_func6);
  SAME_ORIG_RESULT(instance);
}

TEST_F(HookChainTest, Swaps)
{
  chain1.swap(chain2);
  EXPECT_EQ(chain1.enabled_size(), 3);
  EXPECT_EQ(chain1.disabled_size(), 0);
  EXPECT_EQ(chain2.enabled_size(), 3);
  EXPECT_EQ(chain2.disabled_size(), 0);

  instance.func();
  verify_call_stack(func_called::originalcls_func, func_called::detourcls_func4,
                    func_called::detourcls_func5, func_called::detourcls_func6);
  SAME_ORIG_RESULT(instance);

  std::cout << "-------------------------------------------\n";

  instance.func2();
  verify_call_stack(func_called::originalcls_func2, func_called::detourcls_func,
                    func_called::detourcls_func2, func_called::detourcls_func3);
  SAME_ORIG_RESULT(instance);

  std::cout << "-------------------------------------------\n";

  chain1.swap(chain1.begin(), chain2, std::prev(chain2.eend()));
  EXPECT_EQ(chain1.enabled_size(), 3);
  EXPECT_EQ(chain1.disabled_size(), 0);
  EXPECT_EQ(chain2.enabled_size(), 3);
  EXPECT_EQ(chain2.disabled_size(), 0);

  instance.func();
  verify_call_stack(func_called::originalcls_func, func_called::detourcls_func3,
                    func_called::detourcls_func5, func_called::detourcls_func6);
  SAME_ORIG_RESULT(instance);

  std::cout << "-------------------------------------------\n";

  instance.func2();
  verify_call_stack(func_called::originalcls_func2, func_called::detourcls_func,
                    func_called::detourcls_func2, func_called::detourcls_func4);
  SAME_ORIG_RESULT(instance);

  chain1[1].disable();
  chain1.swap(chain1.dbegin(), chain2, std::next(chain2.ebegin()));
  EXPECT_EQ(chain1.enabled_size(), 2);
  EXPECT_EQ(chain1.disabled_size(), 1);
  EXPECT_EQ(chain2.enabled_size(), 3);
  EXPECT_EQ(chain2.disabled_size(), 0);

  instance.func();
  verify_call_stack(func_called::originalcls_func, func_called::detourcls_func3,
                    func_called::detourcls_func6);
  SAME_ORIG_RESULT(instance);

  std::cout << "-------------------------------------------\n";

  instance.func2();
  verify_call_stack(func_called::originalcls_func2, func_called::detourcls_func,
                    func_called::detourcls_func5, func_called::detourcls_func4);
  SAME_ORIG_RESULT(instance);

  std::cout << "-------------------------------------------\n";

  chain1.swap(chain1.ebegin(), std::prev(chain1.eend()));
  EXPECT_EQ(chain1.enabled_size(), 2);
  EXPECT_EQ(chain1.disabled_size(), 1);

  instance.func();
  verify_call_stack(func_called::originalcls_func, func_called::detourcls_func6,
                    func_called::detourcls_func3);
  SAME_ORIG_RESULT(instance);

  std::cout << "-------------------------------------------\n";

  chain1.swap(chain1.ebegin(), chain1.dbegin());
  EXPECT_EQ(chain1.enabled_size(), 2);
  EXPECT_EQ(chain1.disabled_size(), 1);

  instance.func();
  verify_call_stack(func_called::originalcls_func, func_called::detourcls_func2,
                    func_called::detourcls_func3);
  SAME_ORIG_RESULT(instance);
}

TEST_F(HookChainTest, Splicers)
{
  chain1.splice(chain1.dend(), chain1.ebegin(), std::prev(chain1.eend()),
                alterhook::hook_chain::transfer::disabled);
  EXPECT_EQ(chain1.enabled_size(), 1);
  EXPECT_EQ(chain1.disabled_size(), 2);

  instance.func();
  verify_call_stack(func_called::originalcls_func,
                    func_called::detourcls_func3);
  SAME_ORIG_RESULT(instance);

  std::cout << "-------------------------------------------\n";

  chain1.splice(chain1.ebegin(), chain1.dbegin());
  EXPECT_EQ(chain1.enabled_size(), 2);
  EXPECT_EQ(chain1.disabled_size(), 1);

  instance.func();
  verify_call_stack(func_called::originalcls_func, func_called::detourcls_func,
                    func_called::detourcls_func3);
  SAME_ORIG_RESULT(instance);

  std::cout << "-------------------------------------------\n";

  chain1.splice(std::next(chain1.begin()), chain1.dbegin());
  EXPECT_EQ(chain1.enabled_size(), 3);
  EXPECT_EQ(chain1.disabled_size(), 0);

  instance.func();
  verify_call_stack(func_called::originalcls_func, func_called::detourcls_func,
                    func_called::detourcls_func2, func_called::detourcls_func3);
  SAME_ORIG_RESULT(instance);

  std::cout << "-------------------------------------------\n";

  chain2.splice(chain2.dend(), chain1, std::next(chain1.ebegin()),
                chain1.eend(), alterhook::hook_chain::transfer::disabled);
  EXPECT_EQ(chain1.enabled_size(), 1);
  EXPECT_EQ(chain1.disabled_size(), 0);
  EXPECT_EQ(chain2.enabled_size(), 3);
  EXPECT_EQ(chain2.disabled_size(), 2);

  instance.func();
  verify_call_stack(func_called::originalcls_func, func_called::detourcls_func);
  SAME_ORIG_RESULT(instance);

  std::cout << "-------------------------------------------\n";

  chain1.splice(chain1.ebegin(), chain2,
                std::prev(chain2.eend())->get_iterator(),
                std::next(chain2.dbegin())->get_iterator());
  EXPECT_EQ(chain1.enabled_size(), 2);
  EXPECT_EQ(chain1.disabled_size(), 1);
  EXPECT_EQ(chain2.enabled_size(), 2);
  EXPECT_EQ(chain2.disabled_size(), 1);

  instance.func();
  verify_call_stack(func_called::originalcls_func, func_called::detourcls_func6,
                    func_called::detourcls_func);
  SAME_ORIG_RESULT(instance);

  std::cout << "-------------------------------------------\n";

  instance.func2();
  verify_call_stack(func_called::originalcls_func2,
                    func_called::detourcls_func4, func_called::detourcls_func5);
  SAME_ORIG_RESULT(instance);

  std::cout << "-------------------------------------------\n";

  chain2.splice(std::next(chain2.ebegin()), chain1);
  EXPECT_EQ(chain1.enabled_size(), 0);
  EXPECT_EQ(chain1.disabled_size(), 0);
  EXPECT_EQ(chain2.enabled_size(), 4);
  EXPECT_EQ(chain2.disabled_size(), 2);

  instance.func();
  verify_call_stack(func_called::originalcls_func);
  SAME_ORIG_RESULT(instance);

  std::cout << "-------------------------------------------\n";

  instance.func2();
  verify_call_stack(func_called::originalcls_func2,
                    func_called::detourcls_func4, func_called::detourcls_func6,
                    func_called::detourcls_func, func_called::detourcls_func5);
  SAME_ORIG_RESULT(instance);
}

TEST_F(HookChainTest, Modifiers)
{
  chain1.append(&detourcls::func7, original7, &detourcls::func8, original8);
  EXPECT_EQ(chain1.enabled_size(), 5);
  EXPECT_EQ(chain1.disabled_size(), 0);

  instance.func();
  verify_call_stack(func_called::originalcls_func, func_called::detourcls_func,
                    func_called::detourcls_func2, func_called::detourcls_func3,
                    func_called::detourcls_func7, func_called::detourcls_func8);
  SAME_ORIG_RESULT(instance);

  std::cout << "-------------------------------------------\n";

  chain1.insert(
      std::next(chain1.ebegin()),
      [](originalcls* self) -> put_cc
      {
        std::cout << "lambda1\n";
        call_stack.push(func_called::lambda);
        original9(self);
        lambda_ret;
      },
      original9);
  EXPECT_EQ(chain1.enabled_size(), 6);
  EXPECT_EQ(chain1.disabled_size(), 0);

  instance.func();
  verify_call_stack(func_called::originalcls_func, func_called::detourcls_func,
                    func_called::lambda, func_called::detourcls_func2,
                    func_called::detourcls_func3, func_called::detourcls_func7,
                    func_called::detourcls_func8);
  SAME_ORIG_RESULT(instance);

  std::cout << "-------------------------------------------\n";
}
