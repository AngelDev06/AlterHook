#pragma once
#include <iostream>
#include <stack>
#include <functional>
#include <sstream>
#include <alterhook.h>

#define __add_case(arg, name)                                                  \
  case name::arg: return #name "::" #arg;

#define make_enum(name, ...)                                                   \
  enum class name                                                              \
  {                                                                            \
    __VA_ARGS__                                                                \
  };                                                                           \
  const char* name##_str(name arg)                                             \
  {                                                                            \
    switch (arg)                                                               \
    {                                                                          \
      utils_map_ud(__add_case, name, __VA_ARGS__)                              \
    }                                                                          \
  }

// clang-format off

make_enum(func_called, originalcls_func, originalcls_func2, detourcls_func,
          detourcls_func2, detourcls_func3, detourcls_func4, detourcls_func5,
          detourcls_func6)

std::stack<func_called> call_stack;
std::tuple<int, int, int> origresult;

// clang-format on

void check_corrupted_call_stack(size_t size, size_t index, func_called expected,
                                func_called got)
{
  if (expected == got)
  {
    call_stack.pop();
    return;
  }
  std::stringstream stream{};
  stream << "Call stack of size " << size << " was corrupted: expected "
         << func_called_str(expected) << " but got " << func_called_str(got)
         << " at index " << index << '\n';
  const std::string& result = stream.str();
  assert(!result.c_str());
}

template <typename... types>
void verify_call_stack(types... args)
{
  const size_t current_size = call_stack.size();
  (check_corrupted_call_stack(current_size, call_stack.size() - 1, args,
                              call_stack.top()),
   ...);
}

struct originalcls
{
  int x, y, z;

  void func()
  {
    origresult = { x, y, z };
    std::cout << "originalcls::func\n";
    call_stack.push(func_called::originalcls_func);
  }

  void func2()
  {
    origresult = { x, y, z };
    std::cout << "originalcls::func2\n";
    call_stack.push(func_called::originalcls_func2);
  }
};

#if utils_windows
  #define __add_fastcall __fastcall
#else
  #define __add_fastcall
#endif

std::function<void __add_fastcall(originalcls*)> original;
std::function<void __add_fastcall(originalcls*)> original2;
std::function<void __add_fastcall(originalcls*)> original3;
std::function<void __add_fastcall(originalcls*)> original4;
std::function<void __add_fastcall(originalcls*)> original5;
std::function<void __add_fastcall(originalcls*)> original6;

struct detourcls : originalcls
{
  void func()
  {
    std::cout << "detourcls::func\n";
    call_stack.push(func_called::detourcls_func);
    original(this);
  }

  void func2()
  {
    std::cout << "detourcls::func2\n";
    call_stack.push(func_called::detourcls_func2);
    original2(this);
  }

  void func3()
  {
    std::cout << "detourcls::func3\n";
    call_stack.push(func_called::detourcls_func3);
    original3(this);
  }

  void func4()
  {
    std::cout << "detourcls::func4\n";
    call_stack.push(func_called::detourcls_func4);
    original4(this);
  }

  void func5()
  {
    std::cout << "detourcls::func5\n";
    call_stack.push(func_called::detourcls_func5);
    original5(this);
  }

  void func6()
  {
    std::cout << "detourcls::func6\n";
    call_stack.push(func_called::detourcls_func6);
    original6(this);
  }
};
