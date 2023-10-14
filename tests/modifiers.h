#pragma once
#include "testcls.h"

struct target
{
  int x, y, z;

  void multiply_by(int count)
  {
    origresult = { x * count, y * count, z * count };
    std::cout << "target::multiply_by\n";
    call_stack.push(func_called::target_multiply_by);
  }
};