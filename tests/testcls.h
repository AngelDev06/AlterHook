#pragma once
#include <iostream>
#include <vector>
#include <functional>
#include <sstream>
#include <alterhook/utilities/utils.h>
#include <alterhook/tools.h>
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

#define __gen_address_table_impl(name)                                         \
  {                                                                            \
    #name, alterhook::get_target_address(&name)                                \
  }

#define gen_address_table(...)                                                 \
  inline std::unordered_map<std::string_view, std::byte*> address_table = {    \
    utils_map_list(__gen_address_table_impl, __VA_ARGS__)                      \
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

make_enum(func_called, originalcls_func, originalcls_func2, originalcls_func3,
          detourcls_func, detourcls_func2, detourcls_func3, detourcls_func4,
          detourcls_func5, detourcls_func6, detourcls_func7, detourcls_func8,
          detourcls_func9, detourcls_func10, detourcls_func11, free_func,
          modifier1_func, modifier1_func2, target_multiply_by_int,
          target_multiply_by_float, modifier2_multiply_by_int,
          modifier2_multiply_by_float, target_private_power_all,
          modifier2_private_power_all, target_return_sum, modifier2_return_sum,
          lambda, lambda2, generic_lambda, custom_callable,
          second_modifier1_func, second_modifier1_func2)

inline std::vector<func_called> call_stack;
inline std::tuple<int, int, int> origresult;
inline std::tuple<float, float, float> forigresult;

typedef alterhook::utils::fastcall<void> fastcall_void;

// clang-format on

inline void check_corrupted_call_stack(size_t size, size_t index,
                                       func_called expected, func_called got)
{
  ASSERT_EQ(expected, got) << "Call stack of size " << size
                           << " was corrupted: expected "
                           << func_called_str(expected) << " but got "
                           << func_called_str(got) << " at index " << index;
  call_stack.pop_back();
}

template <typename... types>
void verify_call_stack(types... args)
{
  const size_t current_size = call_stack.size();
  (check_corrupted_call_stack(current_size, call_stack.size() - 1, args,
                              call_stack.back()),
   ...);
  ASSERT_EQ(call_stack.size(), 0)
      << "Call stack of size " << current_size
      << " was not of the expected size, should have been: " << sizeof...(args);
  call_stack.clear();
}

struct originalcls
{
  int x, y, z;

  noinline void func()
  {
    origresult = { x, y, z };
    std::cout << "originalcls::func\n";
    call_stack.push_back(func_called::originalcls_func);
  }

  noinline void func2()
  {
    origresult = { x, y, z };
    std::cout << "originalcls::func2\n";
    call_stack.push_back(func_called::originalcls_func2);
  }

  noinline void func3(int increment)
  {
    origresult = { x + increment, y + increment, z + increment };
    std::cout << "originalcls::func3\n";
    call_stack.push_back(func_called::originalcls_func3);
  }
};

#if utils_cc_assertions
  #define __add_fastcall     __fastcall
  #define __add_thiscall     __thiscall
  #define __cc_specific(...) __VA_ARGS__
#else
  #define __add_fastcall
  #define __add_thiscall
  #define __cc_specific(...)
#endif

inline std::function<void __add_fastcall(originalcls*)> original;
inline std::function<void __add_fastcall(originalcls*)> original2;
inline std::function<void __add_fastcall(originalcls*)> original3;
inline std::function<void __add_fastcall(originalcls*)> original4;
inline std::function<void __add_fastcall(originalcls*)> original5;
inline std::function<void __add_fastcall(originalcls*)> original6;
inline std::function<void __add_fastcall(originalcls*)> original7;
inline std::function<void __add_fastcall(originalcls*)> original8;
inline void (originalcls::*original9)(int)  = nullptr;
inline void (originalcls::*original10)(int) = nullptr;
inline void (originalcls::*original11)(int) = nullptr;
inline std::function<void __add_fastcall(originalcls*)> originalx;
inline std::function<void __add_fastcall(originalcls*)> originaly;
inline void (originalcls::*originalz)(int) = nullptr;

struct custom_callable : originalcls
{
  inline static void (originalcls::*original)(int) = nullptr;

  template <typename T>
  void operator()(T arg)
  {
    std::cout << "custom_callable\n";
    call_stack.push_back(func_called::custom_callable);
    (this->*original)((x * y * z) + arg);
  }
};

struct detourcls : originalcls
{
  void func()
  {
    std::cout << "detourcls::func\n";
    call_stack.push_back(func_called::detourcls_func);
    original(this);
  }

  void func2()
  {
    std::cout << "detourcls::func2\n";
    call_stack.push_back(func_called::detourcls_func2);
    original2(this);
  }

  void func3()
  {
    std::cout << "detourcls::func3\n";
    call_stack.push_back(func_called::detourcls_func3);
    original3(this);
  }

  void func4()
  {
    std::cout << "detourcls::func4\n";
    call_stack.push_back(func_called::detourcls_func4);
    original4(this);
  }

  void func5()
  {
    std::cout << "detourcls::func5\n";
    call_stack.push_back(func_called::detourcls_func5);
    original5(this);
  }

  void func6()
  {
    std::cout << "detourcls::func6\n";
    call_stack.push_back(func_called::detourcls_func6);
    original6(this);
  }

  void func7()
  {
    std::cout << "detourcls::func7\n";
    call_stack.push_back(func_called::detourcls_func7);
    original7(this);
  }

  void func8()
  {
    std::cout << "detourcls::func8\n";
    call_stack.push_back(func_called::detourcls_func8);
    original8(this);
  }

  void func9(int increment)
  {
    std::cout << "detourcls::func9\n";
    call_stack.push_back(func_called::detourcls_func9);
    (this->*original9)(increment);
  }

  void func10(int increment)
  {
    std::cout << "detourcls::func10\n";
    call_stack.push_back(func_called::detourcls_func10);
    (this->*original10)(increment);
  }

  void func11(int increment)
  {
    std::cout << "detourcls::func11\n";
    call_stack.push_back(func_called::detourcls_func11);
    (this->*original11)(increment);
  }
};

inline void __add_fastcall free_func(originalcls* self)
{
  std::cout << "free_func\n";
  call_stack.push_back(func_called::free_func);
  originaly(self);
}

gen_address_table(detourcls::func, detourcls::func2, detourcls::func3,
                  detourcls::func4, detourcls::func5, detourcls::func6,
                  detourcls::func7, detourcls::func8, detourcls::func9,
                  detourcls::func10, detourcls::func11, free_func);
