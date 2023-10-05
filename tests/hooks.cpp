#include "testcls.h"

int main()
{
  originalcls instance{ 1, 2, 3 };
  instance.func();
  call_stack.pop();

  alterhook::hook hook{ &originalcls::func, &detourcls::func, original };

  instance.func();
  verify_call_stack(func_called::originalcls_func, func_called::detourcls_func);
  assert(std::tie(instance.x, instance.y, instance.z) == origresult);

  hook.disable();
  instance.func();
  verify_call_stack(func_called::originalcls_func);
}