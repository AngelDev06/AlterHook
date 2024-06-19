#include "testcls.h"
#include <alterhook/hook_map.h>

class HookMapTest : public testing::Test
{
protected:
  originalcls                      instance{ 1, 2, 3 };
  alterhook::hook_map<std::string> map1{
    &originalcls::func, "hook1", &detourcls::func,
    original,           "hook2", &detourcls::func2,
    original2,          "hook3", &detourcls::func3,
    original3
  };
  alterhook::hook_map_using<std::string, std::unordered_multimap> map2{
    &originalcls::func2,
    std::forward_as_tuple("regular", &detourcls::func4, original4),
    std::forward_as_tuple("regular", &detourcls::func5, original5),
    std::forward_as_tuple(
        "lambda",
        [](originalcls* self) -> fastcall_void
        {
          std::cout << "lambda\n";
          call_stack.push_back(func_called::lambda);
          originalx(self);
          return fastcall_void();
        },
        originalx)
  };
  alterhook::concurrent_hook_map<std::string> map3{
    &originalcls::func3, "hook1", &detourcls::func9,
    original9,           "hook2", &detourcls::func10,
    original10,          "hook3", &detourcls::func11,
    original11
  };
};

TEST(StandaloneHookMapTest, Constructors)
{
  originalcls         instance{ 1, 2, 3 };
  alterhook::hook_map map1{ &originalcls::func, "hook1", &detourcls::func,
                            original,           "hook2", &detourcls::func2,
                            original2,          "hook3", &detourcls::func3,
                            original3 };
  instance.func();
  verify_call_stack(func_called::originalcls_func, func_called::detourcls_func,
                    func_called::detourcls_func2, func_called::detourcls_func3);
  SAME_ORIG_RESULT(instance);

  for (auto [str, hook] : map1)
  {
    std::string_view strview = str;
    if (strview == "hook1")
      EXPECT_EQ(address_table["detourcls::func"], hook.get_detour());
    else if (strview == "hook2")
      EXPECT_EQ(address_table["detourcls::func2"], hook.get_detour());
    else if (strview == "hook3")
      EXPECT_EQ(address_table["detourcls::func3"], hook.get_detour());

    EXPECT_EQ(hook.is_enabled(), true);
  }

  std::cout << "-------------------------------------------\n";

  alterhook::hook_map map2{
    &originalcls::func2,
    std::forward_as_tuple("hook1", &detourcls::func4, original4),
    std::forward_as_tuple("hook2", &detourcls::func5, original5),
    std::forward_as_tuple("hook3", &detourcls::func6, original6),
    std::forward_as_tuple(
        "lambda",
        [](originalcls* self) -> fastcall_void
        {
          std::cout << "lambda\n";
          call_stack.push_back(func_called::lambda);
          original7(self);
          return fastcall_void();
        },
        original7)
  };
  instance.func2();
  verify_call_stack(func_called::originalcls_func2,
                    func_called::detourcls_func4, func_called::detourcls_func5,
                    func_called::detourcls_func6, func_called::lambda);
  SAME_ORIG_RESULT(instance);

  for (auto [str, hook] : map2)
  {
    std::string_view strview = str;
    if (strview == "hook1")
      EXPECT_EQ(address_table["detourcls::func4"], hook.get_detour());
    else if (strview == "hook2")
      EXPECT_EQ(address_table["detourcls::func5"], hook.get_detour());
    else if (strview == "hook3")
      EXPECT_EQ(address_table["detourcls::func6"], hook.get_detour());
    EXPECT_EQ(hook.is_enabled(), true);
  }
}

TEST_F(HookMapTest, Modifiers)
{
  originalcls instance{ 1, 2, 3 };
  map1.erase("hook1");
  instance.func();
  verify_call_stack(func_called::originalcls_func, func_called::detourcls_func2,
                    func_called::detourcls_func3);
  SAME_ORIG_RESULT(instance);

  std::cout << "-------------------------------------------\n";

  map1.insert("hook4", &detourcls::func6, original6, "hook5", &detourcls::func7,
              original7);
  instance.func();
  verify_call_stack(func_called::originalcls_func, func_called::detourcls_func2,
                    func_called::detourcls_func3, func_called::detourcls_func6,
                    func_called::detourcls_func7);
  SAME_ORIG_RESULT(instance);

  std::cout << "-------------------------------------------\n";

  map2.insert(std::forward_as_tuple("regular", &detourcls::func8, original8),
              std::forward_as_tuple("free function", free_func, originaly));
  instance.func2();
  verify_call_stack(func_called::originalcls_func2,
                    func_called::detourcls_func4, func_called::detourcls_func5,
                    func_called::lambda, func_called::detourcls_func8,
                    func_called::free_func);
  SAME_ORIG_RESULT(instance);

  for (auto [key, hook] : map2)
  {
    if (key == "regular")
      EXPECT_TRUE(alterhook::utils::any_of(hook.get_detour(),
                                           address_table["detourcls::func4"],
                                           address_table["detourcls::func5"],
                                           address_table["detourcls::func8"]));
    else if (key == "free function")
      EXPECT_EQ(hook.get_detour(), address_table["free_func"]);
    EXPECT_EQ(hook.is_enabled(), true);
  }
}
