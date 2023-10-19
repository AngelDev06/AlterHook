#include "testcls.h"

#if utils_x86 && utils_windows
  #define lambda_ret                                                           \
    return {}
  #define put_cc utils::fastcall<void>
#else
  #define lambda_ret return
  #define put_cc     void
#endif

int main()
{
  originalcls instance{ 1, 2, 3 };

  {
    instance.func();
    call_stack.pop();

    std::cout << "-------------------------------------------\n";

    alterhook::hook hook{ &originalcls::func, &detourcls::func, original };

    instance.func();
    verify_call_stack(func_called::originalcls_func,
                      func_called::detourcls_func);
    assert(std::tie(instance.x, instance.y, instance.z) == origresult);

    std::cout << "-------------------------------------------\n";

    hook.disable();
    instance.func();
    verify_call_stack(func_called::originalcls_func);

    std::cout << "-------------------------------------------\n"
              << "-------------------------------------------\n";
  }

  {
    instance.func2();
    call_stack.pop();

    std::cout << "-------------------------------------------\n";

    alterhook::hook hook{ &originalcls::func2,
                          [](originalcls* self) -> put_cc
                          {
                            std::cout << "lambda\n";
                            call_stack.push(func_called::lambda);
                            original2(self);
                            lambda_ret;
                          },
                          original2 };
    instance.func2();
    verify_call_stack(func_called::originalcls_func2, func_called::lambda);
    assert(std::tie(instance.x, instance.y, instance.z) == origresult);

    std::cout << "-------------------------------------------\n";
  }

  instance.func2();
  verify_call_stack(func_called::originalcls_func2);
}