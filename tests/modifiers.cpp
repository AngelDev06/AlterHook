#include "modifiers.h"

class modifier(modifier1, originalcls, func, func2)
{
public:
  void func()
  {
    std::cout << "modifier1::func\n";
    call_stack.push(func_called::modifier1_func);
    original::func();
  }

  void func2()
  {
    std::cout << "modifier1::func2\n";
    call_stack.push(func_called::modifier1_func2);
    original::func2();
  }
};

class modifier(second_modifier1, originalcls, func, func2)
{
public:
  void func()
  {
    std::cout << "second_modifier1::func\n";
    call_stack.push(func_called::second_modifier1_func);
    original::func();
  }

  void func2()
  {
    std::cout << "second_modifier1::func2\n";
    call_stack.push(func_called::second_modifier1_func2);
    original::func2();
  }
};

class modifier(modifier2, target, (multiply_by, void(int)),
               (multiply_by, void(float)), private_power_all, return_sum)
{
public:
  void multiply_by(int count)
  {
    std::cout << "modifier2::multiply_by(int)\n";
    call_stack.push(func_called::modifier2_multiply_by_int);
    original::multiply_by(count * 2);
  }

  void multiply_by(float count)
  {
    std::cout << "modifier2::multiply_by(float)\n";
    call_stack.push(func_called::modifier2_multiply_by_float);
    original::multiply_by(count * 2);
  }

  void private_power_all()
  {
    std::cout << "modifier2::private_power_all\n";
    call_stack.push(func_called::modifier2_private_power_all);
    original::private_power_all();
  }

  int return_sum()
  {
    std::cout << "modifier2::return_sum\n";
    call_stack.push(func_called::modifier2_return_sum);
    return original::return_sum() * 2;
  }
};

TEST(ModifierTest, OriginalClsModifier)
{
  std::cout << "modifier1 -> originalcls\n\n";
  originalcls instance{ 1, 2, 3 };
  instance.func();
  verify_call_stack(func_called::originalcls_func);

  std::cout << "-------------------------------------------\n";

  modifier1::enable_modifier();
  instance.func();
  verify_call_stack(func_called::originalcls_func, func_called::modifier1_func);
  SAME_ORIG_RESULT(instance);

  std::cout << "-------------------------------------------\n";

  instance.func2();
  verify_call_stack(func_called::originalcls_func2,
                    func_called::modifier1_func2);
  SAME_ORIG_RESULT(instance);

  std::cout << "-------------------------------------------\n";

  modifier1::disable_modifier();

  instance.func();
  verify_call_stack(func_called::originalcls_func);

  std::cout << "-------------------------------------------\n";

  instance.func2();
  verify_call_stack(func_called::originalcls_func2);

  std::cout << "-------------------------------------------\n";

  second_modifier1::enable_modifier();

  instance.func();
  verify_call_stack(func_called::originalcls_func,
                    func_called::second_modifier1_func);
  SAME_ORIG_RESULT(instance);

  std::cout << "-------------------------------------------\n";

  instance.func2();
  verify_call_stack(func_called::originalcls_func2,
                    func_called::second_modifier1_func2);
  SAME_ORIG_RESULT(instance);

  std::cout << "-------------------------------------------\n";

  modifier1::enable_modifier();

  instance.func();
  verify_call_stack(func_called::originalcls_func, func_called::modifier1_func,
                    func_called::second_modifier1_func);
  SAME_ORIG_RESULT(instance);

  std::cout << "-------------------------------------------\n";

  instance.func2();
  verify_call_stack(func_called::originalcls_func2,
                    func_called::modifier1_func2,
                    func_called::second_modifier1_func2);
  SAME_ORIG_RESULT(instance);

  std::cout << "-------------------------------------------\n";

  second_modifier1::deactivate_modifier();
  modifier1::deactivate_modifier();
}

TEST(ModifierTest, TargetModifier)
{
  std::cout << "modifier2 -> target\n\n";
  target instance{ 1, 2, 3 };
  modifier2::enable_modifier();

  instance.multiply_by(10);
  verify_call_stack(func_called::target_multiply_by_int,
                    func_called::modifier2_multiply_by_int);
  EXPECT_EQ(
      std::forward_as_tuple(instance.x * 20, instance.y * 20, instance.z * 20),
      origresult);

  std::cout << "-------------------------------------------\n";

  instance.multiply_by(2.5f);
  verify_call_stack(func_called::target_multiply_by_float,
                    func_called::modifier2_multiply_by_float);
  EXPECT_EQ(std::forward_as_tuple(instance.x * 5.0f, instance.y * 5.0f,
                                  instance.z * 5.0f),
            forigresult);

  std::cout << "-------------------------------------------\n";

  instance.power_all();
  verify_call_stack(func_called::target_private_power_all,
                    func_called::modifier2_private_power_all);
  EXPECT_EQ(std::forward_as_tuple(instance.x * instance.x,
                                  instance.y * instance.y,
                                  instance.z * instance.z),
            origresult);

  std::cout << "-------------------------------------------\n";

  EXPECT_EQ(instance.return_sum(), (instance.x + instance.y + instance.z) * 2);
  verify_call_stack(func_called::target_return_sum,
                    func_called::modifier2_return_sum);

  modifier2::deactivate_modifier();
}