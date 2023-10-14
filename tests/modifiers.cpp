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

class modifier(modifier2, target, multiply_by)
{
public:
  void multiply_by(int count)
  {
    std::cout << "modifier2::multiply_by\n";
    call_stack.push(func_called::modifier2_multiply_by);
    original::multiply_by(count * 2);
  }
};

int main()
{
  /*
   * test originalcls
   */
  originalcls instance{ 1, 2, 3 };
  instance.func();
  call_stack.pop();

  modifier1::activate_modifier();
  instance.func();
  verify_call_stack(func_called::originalcls_func, func_called::modifier1_func);
  assert(std::tie(instance.x, instance.y, instance.z) == origresult);

  instance.func2();
  verify_call_stack(func_called::originalcls_func2,
                    func_called::modifier1_func2);
  assert(std::tie(instance.x, instance.y, instance.z) == origresult);

  /*
   * test target
   */
  target instance2{ 1, 2, 3 };
  instance2.multiply_by(2);
  call_stack.pop();

  modifier2::activate_modifier();
  instance2.multiply_by(2);
  verify_call_stack(func_called::target_multiply_by,
                    func_called::modifier2_multiply_by);
  assert(std::tuple(instance.x * 4, instance.y * 4, instance.z * 4) ==
         origresult);
}