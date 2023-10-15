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

class modifier(modifier2, target, (multiply_by, void(int)),
               (multiply_by, void(float)), private_power_all, return_sum)
{
public:
  void multiply_by(int count)
  {
    std::cout << "modifier2::multiply_by\n";
    call_stack.push(func_called::modifier2_multiply_by);
    original::multiply_by(count * 2);
  }

  void multiply_by(float count)
  {
    std::cout << "modifier2::multiply_by\n";
    call_stack.push(func_called::modifier2_multiply_by);
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

int main()
{
  /*
   * test originalcls
   */
  {
    std::cout << "modifier1 -> originalcls\n\n";
    originalcls instance{ 1, 2, 3 };
    instance.func();
    instance.func2();
    call_stack.pop();
    call_stack.pop();
    std::cout << "-------------------------------------------\n";

    modifier1::activate_modifier();
    instance.func();
    verify_call_stack(func_called::originalcls_func,
                      func_called::modifier1_func);
    assert(std::tie(instance.x, instance.y, instance.z) == origresult);

    std::cout << "-------------------------------------------\n";

    instance.func2();
    verify_call_stack(func_called::originalcls_func2,
                      func_called::modifier1_func2);
    assert(std::tie(instance.x, instance.y, instance.z) == origresult);
    std::cout
        << "\n-------------------------------------------\n----------------"
           "---------------------------\n\n";
  }

  /*
   * test target
   */
  {
    std::cout << "modifier2 -> target\n\n";
    target instance{ 1, 2, 3 };
    instance.multiply_by(2);
    instance.multiply_by(3.5f);
    instance.power_all();
    instance.return_sum();
    call_stack.pop();
    call_stack.pop();
    call_stack.pop();
    call_stack.pop();
    std::cout << "-------------------------------------------\n";

    modifier2::activate_modifier();
    instance.multiply_by(2);
    verify_call_stack(func_called::target_multiply_by,
                      func_called::modifier2_multiply_by);
    assert(std::tuple(instance.x * 4, instance.y * 4, instance.z * 4) ==
           origresult);

    std::cout << "-------------------------------------------\n";

    instance.multiply_by(3.5f);
    verify_call_stack(func_called::target_multiply_by,
                      func_called::modifier2_multiply_by);
    assert(std::tuple(instance.x * (2 * 3.5f), instance.y * (2 * 3.5f),
                      instance.z * (2 * 3.5f)) == forigresult);

    std::cout << "-------------------------------------------\n";

    instance.power_all();
    verify_call_stack(func_called::target_private_power_all,
                      func_called::modifier2_private_power_all);
    assert(std::tuple(instance.x * instance.x, instance.y * instance.y,
                      instance.z * instance.z) == origresult);

    std::cout << "-------------------------------------------\n";

    int result = instance.return_sum();
    (void)result;
    assert(result == ((instance.x + instance.y + instance.z) * 2));
    verify_call_stack(func_called::target_return_sum,
                      func_called::modifier2_return_sum);
  }
}