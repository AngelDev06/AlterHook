#include "testcls.h"

class HookTest : public testing::Test
{
protected:
  //! [hook::hook example]
  typedef alterhook::utils::fastcall<void> fastcall_void;
  alterhook::hook hook1{ &originalcls::func, &detourcls::func, original,
                         false };
  alterhook::hook hook2{ &originalcls::func2,
                         [](originalcls* self) -> fastcall_void
                         {
                           std::cout << "lambda\n";
                           call_stack.push(func_called::lambda);
                           original2(self);
                           return fastcall_void();
                         },
                         original2, false };
  //! [hook::hook example]
  originalcls instance{ 1, 2, 3 };
};

TEST_F(HookTest, StatusUpdate)
{
  EXPECT_FALSE(hook1.is_enabled());
  hook1.enable();
  instance.func();
  verify_call_stack(func_called::originalcls_func, func_called::detourcls_func);
  SAME_ORIG_RESULT(instance);

  std::cout << "-------------------------------------------\n";

  hook1.disable();
  instance.func();
  verify_call_stack(func_called::originalcls_func);
  SAME_ORIG_RESULT(instance);

  std::cout << "-------------------------------------------\n";

  EXPECT_FALSE(hook2.is_enabled());
  hook2.enable();
  instance.func2();
  verify_call_stack(func_called::originalcls_func2, func_called::lambda);
  SAME_ORIG_RESULT(instance);

  std::cout << "-------------------------------------------\n";

  hook2.disable();
  instance.func2();
  verify_call_stack(func_called::originalcls_func2);
  SAME_ORIG_RESULT(instance);
}

TEST(StandaloneHookTest, Constructors)
{
  originalcls instance{ 1, 2, 3 };
  {
    static void(__add_fastcall * custom_original1)(
        originalcls*, __cc_specific(void*, ) int)                     = nullptr;
    static void(__add_thiscall * custom_original2)(originalcls*, int) = nullptr;
    alterhook::hook hook{ &originalcls::func3,
                          [](auto* instance_ptr, __cc_specific(auto, ) auto arg)
                          {
                            std::cout << "generic lambda\n";
                            call_stack.push(func_called::generic_lambda);
                            custom_original1(instance_ptr,
                                             __cc_specific(nullptr, ) arg * 2);
                          },
                          custom_original1 };

    instance.func3(8);
    verify_call_stack(func_called::originalcls_func3,
                      func_called::generic_lambda);
    EXPECT_EQ(std::tuple(instance.x + 16, instance.y + 16, instance.z + 16),
              origresult);
  }
  {
    alterhook::hook hook{ &originalcls::func3, custom_callable{},
                          custom_callable::original };
    instance.func3(8);
    verify_call_stack(func_called::originalcls_func3,
                      func_called::custom_callable);
    const auto incrementation = (instance.x * instance.y * instance.z) + 8;
    EXPECT_EQ(std::tuple(instance.x + incrementation,
                         instance.y + incrementation,
                         instance.z + incrementation),
              origresult);
  }
}

TEST_F(HookTest, CopyAssignment)
{
  hook2.enable();
  hook1.enable();
  hook1 = hook2;

  EXPECT_EQ(hook1.get_target(), hook2.get_target());
  EXPECT_EQ(hook1.get_detour(), hook2.get_detour());
  EXPECT_NE(hook1.is_enabled(), hook2.is_enabled());
  EXPECT_FALSE(hook1.is_enabled());

  instance.func();
  verify_call_stack(func_called::originalcls_func);
  SAME_ORIG_RESULT(instance);

  std::cout << "-------------------------------------------\n";

  instance.func2();
  verify_call_stack(func_called::originalcls_func2, func_called::lambda);
  SAME_ORIG_RESULT(instance);

  std::cout << "-------------------------------------------\n";

  hook2.disable();
  hook1.enable();

  instance.func2();
  verify_call_stack(func_called::originalcls_func2, func_called::lambda);
  SAME_ORIG_RESULT(instance);
}

TEST_F(HookTest, MoveAssignment)
{
  hook2.enable();
  hook1 = std::move(hook2);

  EXPECT_FALSE(hook2.get_target());
  EXPECT_FALSE(hook2.get_detour());
  EXPECT_FALSE(hook2.is_enabled());
  EXPECT_FALSE(hook2.trampoline_size());
  EXPECT_TRUE(hook1.get_target());
  EXPECT_TRUE(hook1.get_detour());
  EXPECT_TRUE(hook1.is_enabled());
  EXPECT_TRUE(hook1.trampoline_size());

  instance.func2();
  verify_call_stack(func_called::originalcls_func2, func_called::lambda);
  SAME_ORIG_RESULT(instance);
}

TEST_F(HookTest, CopyConstructor)
{
  hook2.enable();
  alterhook::hook hook{ hook2 };
  EXPECT_EQ(hook.get_target(), hook2.get_target());
  EXPECT_EQ(hook.get_detour(), hook2.get_detour());
  EXPECT_TRUE(hook2.is_enabled());
  EXPECT_FALSE(hook.is_enabled());

  instance.func2();
  verify_call_stack(func_called::originalcls_func2, func_called::lambda);
  SAME_ORIG_RESULT(instance);

  std::cout << "-------------------------------------------\n";

  hook2.disable();
  hook.enable();

  instance.func2();
  verify_call_stack(func_called::originalcls_func2, func_called::lambda);
  SAME_ORIG_RESULT(instance);
}

TEST_F(HookTest, MoveConstructor)
{
  hook2.enable();
  alterhook::hook hook{ std::move(hook2) };

  EXPECT_FALSE(hook2.get_target());
  EXPECT_FALSE(hook2.get_detour());
  EXPECT_FALSE(hook2.is_enabled());
  EXPECT_FALSE(hook2.trampoline_size());
  EXPECT_TRUE(hook.get_target());
  EXPECT_TRUE(hook.get_detour());
  EXPECT_TRUE(hook.is_enabled());
  EXPECT_TRUE(hook.trampoline_size());

  instance.func2();
  verify_call_stack(func_called::originalcls_func2, func_called::lambda);
  SAME_ORIG_RESULT(instance);
}

TEST_F(HookTest, Setters)
{
  hook1.enable();
  instance.func();
  verify_call_stack(func_called::originalcls_func, func_called::detourcls_func);
  SAME_ORIG_RESULT(instance);

  std::cout << "-------------------------------------------\n";

  hook1.set_target(&originalcls::func2);
  EXPECT_TRUE(hook1.is_enabled());
  EXPECT_EQ(hook1.get_target(),
            alterhook::get_target_address(&originalcls::func2));

  instance.func();
  verify_call_stack(func_called::originalcls_func);
  SAME_ORIG_RESULT(instance);

  std::cout << "-------------------------------------------\n";

  instance.func2();
  verify_call_stack(func_called::originalcls_func2,
                    func_called::detourcls_func);
  SAME_ORIG_RESULT(instance);

  std::cout << "-------------------------------------------\n";

  hook1
      .set_detour(
          [](originalcls* self) -> put_cc
          {
            std::cout << "lambda2\n";
            call_stack.push(func_called::lambda2);
            original9(self);
            lambda_ret;
          })
      .set_original(original9);

  instance.func2();
  verify_call_stack(func_called::originalcls_func2, func_called::lambda2);
  SAME_ORIG_RESULT(instance);
}