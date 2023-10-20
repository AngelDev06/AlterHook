#include "testcls.h"

int main()
{
  originalcls instance{ 1, 2, 3 };
  instance.func();
  call_stack.pop();
  std::cout << "-------------------------------------------\n";

  alterhook::hook_chain chain1{ &originalcls::func, &detourcls::func,
                                original,           &detourcls::func2,
                                original2,          &detourcls::func3,
                                original3 };
  instance.func();
  verify_call_stack(func_called::originalcls_func, func_called::detourcls_func,
                    func_called::detourcls_func2, func_called::detourcls_func3);
  assert(std::tie(instance.x, instance.y, instance.z) == origresult);
  std::cout << "-------------------------------------------\n";

  chain1.swap(chain1.ebegin(), std::prev(chain1.eend()));
  instance.func();
  verify_call_stack(func_called::originalcls_func, func_called::detourcls_func3,
                    func_called::detourcls_func2, func_called::detourcls_func);
  assert(std::tie(instance.x, instance.y, instance.z) == origresult);
  std::cout << "-------------------------------------------\n";

  chain1.append(&detourcls::func4, original4, &detourcls::func5, original5);
  instance.func();
  verify_call_stack(func_called::originalcls_func, func_called::detourcls_func3,
                    func_called::detourcls_func2, func_called::detourcls_func,
                    func_called::detourcls_func4, func_called::detourcls_func5);
  assert(std::tie(instance.x, instance.y, instance.z) == origresult);
  std::cout << "-------------------------------------------\n";

  chain1.splice(chain1.ebegin(), std::prev(chain1.eend(), 2));
  instance.func();
  verify_call_stack(func_called::originalcls_func, func_called::detourcls_func4,
                    func_called::detourcls_func3, func_called::detourcls_func2,
                    func_called::detourcls_func, func_called::detourcls_func5);
  assert(std::tie(instance.x, instance.y, instance.z) == origresult);
  std::cout << "-------------------------------------------\n";

  auto& hook1 = chain1[2];
  auto& hook2 = *std::next(hook1.get_list_iterator(), 2);
  hook1.disable();
  hook2.disable();

  instance.func();
  verify_call_stack(func_called::originalcls_func, func_called::detourcls_func4,
                    func_called::detourcls_func3, func_called::detourcls_func);
  assert(std::tie(instance.x, instance.y, instance.z) == origresult);
  std::cout << "-------------------------------------------\n";

  chain1.enable_all();
  instance.func();
  verify_call_stack(func_called::originalcls_func, func_called::detourcls_func4,
                    func_called::detourcls_func3, func_called::detourcls_func2,
                    func_called::detourcls_func, func_called::detourcls_func5);
  assert(std::tie(instance.x, instance.y, instance.z) == origresult);
  std::cout << "-------------------------------------------\n";

  chain1.splice(chain1.dend(), std::next(chain1.ebegin()),
                std::prev(chain1.eend()),
                alterhook::hook_chain::transfer::disabled);
  instance.func();
  verify_call_stack(func_called::originalcls_func, func_called::detourcls_func4,
                    func_called::detourcls_func5);
  assert(std::tie(instance.x, instance.y, instance.z) == origresult);
  std::cout << "-------------------------------------------\n";

  chain1.splice(chain1.ebegin(), std::next(chain1.ebegin())->get_iterator(),
                chain1.end());
  instance.func();
  verify_call_stack(func_called::originalcls_func, func_called::detourcls_func5,
                    func_called::detourcls_func4);
  assert(std::tie(instance.x, instance.y, instance.z) == origresult);
  std::cout << "-------------------------------------------\n";

  chain1.insert(std::next(chain1.ebegin()), &detourcls::func6, original6);
  instance.func();
  verify_call_stack(func_called::originalcls_func, func_called::detourcls_func5,
                    func_called::detourcls_func6, func_called::detourcls_func4);
  assert(std::tie(instance.x, instance.y, instance.z) == origresult);
  std::cout << "-------------------------------------------\n";
}