#pragma once
#include <iostream>
#include <stack>
#include <functional>
#include <sstream>
#include <alterhook.h>
#include <gtest/gtest.h>

#if utils_msvc
  #define noinline __declspec(noinline)
#else
  #define noinline __attribute__((noinline))
#endif

#define __add_case(arg, name)                                                  \
  case name::arg: return #name "::" #arg;

#define make_enum(name, ...)                                                   \
  enum class name                                                              \
  {                                                                            \
    __VA_ARGS__                                                                \
  };                                                                           \
  inline const char* name##_str(name arg)                                      \
  {                                                                            \
    switch (arg)                                                               \
    {                                                                          \
      utils_map_ud(__add_case, name, __VA_ARGS__)                              \
    }                                                                          \
    return nullptr;                                                            \
  }

#define SAME_ORIG_RESULT(instance)                                             \
  EXPECT_EQ(std::tie(instance.x, instance.y, instance.z), origresult)

#if utils_x86 && utils_windows
  #define lambda_ret                                                           \
    return {}
  #define put_cc alterhook::utils::fastcall<void>
#else
  #define lambda_ret return
  #define put_cc     void
#endif

// clang-format off

make_enum(func_called, originalcls_func, originalcls_func2, detourcls_func,
          detourcls_func2, detourcls_func3, detourcls_func4, detourcls_func5,
          detourcls_func6, detourcls_func7, detourcls_func8, modifier1_func,
          modifier1_func2, target_multiply_by_int, target_multiply_by_float,
          modifier2_multiply_by_int, modifier2_multiply_by_float,
          target_private_power_all, modifier2_private_power_all,
          target_return_sum, modifier2_return_sum, lambda, lambda2,
          second_modifier1_func, second_modifier1_func2)

inline std::stack<func_called> call_stack;
inline std::tuple<int, int, int> origresult;
inline std::tuple<float, float, float> forigresult;

// clang-format on

inline void check_corrupted_call_stack(size_t size, size_t index,
                                       func_called expected, func_called got)
{
  ASSERT_EQ(expected, got) << "Call stack of size " << size
                           << " was corrupted: expected "
                           << func_called_str(expected) << " but got "
                           << func_called_str(got) << " at index " << index;
  call_stack.pop();
}

template <typename... types>
void verify_call_stack(types... args)
{
  const size_t current_size = call_stack.size();
  (check_corrupted_call_stack(current_size, call_stack.size() - 1, args,
                              call_stack.top()),
   ...);
  ASSERT_EQ(call_stack.size(), 0)
      << "Call stack of size " << current_size
      << " was not of the expected size but instead was "
      << (call_stack.size() + sizeof...(args));
}

struct originalcls
{
  int x, y, z;

  noinline void func()
  {
    origresult = { x, y, z };
    std::cout << "originalcls::func\n";
    call_stack.push(func_called::originalcls_func);
  }

  noinline void func2()
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

inline std::function<void __add_fastcall(originalcls*)> original;
inline std::function<void __add_fastcall(originalcls*)> original2;
inline std::function<void __add_fastcall(originalcls*)> original3;
inline std::function<void __add_fastcall(originalcls*)> original4;
inline std::function<void __add_fastcall(originalcls*)> original5;
inline std::function<void __add_fastcall(originalcls*)> original6;
inline std::function<void __add_fastcall(originalcls*)> original7;
inline std::function<void __add_fastcall(originalcls*)> original8;
inline std::function<void __add_fastcall(originalcls*)> original9;

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

  void func7()
  {
    std::cout << "detourcls::func7\n";
    call_stack.push(func_called::detourcls_func7);
    original7(this);
  }

  void func8()
  {
    std::cout << "detourcls::func8\n";
    call_stack.push(func_called::detourcls_func8);
    original8(this);
  }
};