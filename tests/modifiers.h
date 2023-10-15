#pragma once
#include "testcls.h"

struct target
{
  int x, y, z;

  noinline void multiply_by(int count)
  {
    origresult = { x * count, y * count, z * count };
    std::cout << "target::multiply_by\n";
    call_stack.push(func_called::target_multiply_by);
  }

  // overloaded method
  noinline void multiply_by(float count)
  {
    forigresult = { x * count, y * count, z * count };
    std::cout << "target::multiply_by\n";
    call_stack.push(func_called::target_multiply_by);
  }

  void power_all() { private_power_all(); }

  noinline int return_sum()
  {
    std::cout << "target::return_sum\n";
    call_stack.push(func_called::target_return_sum);
    return x + y + z;
  }

private:
  noinline void private_power_all()
  {
    origresult = { x * x, y * y, z * z };
    std::cout << "target::private_power_all\n";
    call_stack.push(func_called::target_private_power_all);
  }
};