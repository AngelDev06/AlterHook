# Exceptions

A hierarchy of exceptions that the library may throw when an error occurs. All of the exceptions mentioned here are thrown very rarely and most of the time it's not the programmer's fault but rather an out-of-control problem caused by other sources such as the system API the library uses. Nevertheless, the library is designed with a strong exception guarantee in mind or basic if that's not possible for specific scenarios.

The hierarchy is as follows:

- [alterhook::exceptions::alterhook_exception](../include/alterhook/exceptions.h#L17-L20)
  - [alterhook::exceptions::trampoline_exception](../include/alterhook/exceptions.h#L22-L28)
    - [alterhook::exceptions::trampoline::unsupported_instruction_handling](../include/alterhook/exceptions.h#L81-94)
    - [alterhook::exceptions::trampoline::it_block_exception](../include/alterhook/exceptions.h#L97-L120) (**<ins>ARM specific</ins>**)
      - [alterhook::exceptions::trampoline::it_block::invalid_it_block](../include/alterhook/exceptions.h#L124-L137)
      - [alterhook::exceptions::trampoline::it_block::incomplete_it_block](../include/alterhook/exceptions.h#L139-L153)
    - [alterhook::exceptions::trampoline::unused_register_not_found](../include/alterhook/exceptions.h#L156-L166) (**<ins>ARM specific</ins>**)
    - [alterhook::exceptions::trampoline::pc_relative_handling_fail](../include/alterhook/exceptions.h#L168-L195) (**<ins>ARM specific</ins>**)
    - [alterhook::exceptions::trampoline::instructions_in_branch_handling_fail](../include/alterhook/exceptions.h#L198-L208)
    - [alterhook::exceptions::trampoline::trampoline_max_size_exceeded](../include/alterhook/exceptions.h#L210-L224)
    - [alterhook::exceptions::trampoline::insufficient_function_size](../include/alterhook/exceptions.h#L226-L241)
  - [alterhook::exceptions::disassembler_exception](../include/alterhook/exceptions.h#L30-L43)
    - [alterhook::exceptions::disassembler::disassembler_init_fail](../include/alterhook/exceptions.h#L248-L258)
    - [alterhook::exceptions::disassembler::disassembler_iter_init_fail](../include/alterhook/exceptions.h#L260-L270)
    - [alterhook::exceptions::disassembler::disassembler_disasm_fail](../include/alterhook/exceptions.h#L272-L283)
  - [alterhook::exceptions::os_exception](../include/alterhook/exceptions.h#L45-L53)
    - [alterhook::exceptions::os::virtual_alloc_exception](../include/alterhook/exceptions.h#L289-L305) (**<ins>Windows specific</ins>**)
    - [alterhook::exceptions::os::thread_list_traversal_fail](../include/alterhook/exceptions.h#L307-L321) (**<ins>Windows specific</ins>**)
    - [alterhook::exceptions::os::virtual_protect_exception](../include/alterhook/exceptions.h#L323-L340) (**<ins>Windows specific</ins>**)
    - [alterhook::exceptions::os::mmap_exception](../include/alterhook/exceptions.h#L342-L360) (**<ins>Linux/Android specific</ins>**)
    - [alterhook::exceptions::os::sigaction_exception](../include/alterhook/exceptions.h#L362-L378) (**<ins>Linux/Android specific</ins>**)
    - [alterhook::exceptions::os::mprotect_exception](../include/alterhook/exceptions.h#L380-L396) (**<ins>Linux/Android specific</ins>**)
  - [alterhook::exceptions::misc_exception](../include/alterhook/exceptions.h#L55)
    - [alterhook::exceptions::misc::thread_process_fail](../include/alterhook/exceptions.h#L403-L415) (**<ins>Linux/Android specific</ins>**)
    - [alterhook::exceptions::misc::invalid_address](../include/alterhook/exceptions.h#L418-L428)

To understand what the above links point to you should take a look at [exception codegen](#exception-class-generation)

## Synopsis

```cpp
namespace alterhook
{
  class alterhook_exception : public std::exception
  {
  public:
    alterhook_exception();

    alterhook_exception(const alterhook_exception& other)            = default;
    alterhook_exception& operator=(const alterhook_exception& other) = default;

    virtual std::string info() const = 0;
  };

  class trampoline_exception : public alterhook_exception
  {
  public:
    trampoline_exception(const std::byte* target);

    trampoline_exception(const trampoline_exception& other)            = default;
    trampoline_exception& operator=(const trampoline_exception& other) = default;

    const std::byte*    get_target() const;
    virtual std::string info() const;
  };

  class disassembler_exception : public alterhook_exception
  {
  public:
    disassembler_exception(const std::byte* target, int flag);

    disassembler_exception(const std::byte* target);

    disassembler_exception(const disassembler_exception& other) = default;
    disassembler_exception&
      operator=(const disassembler_exception& other) = default;

    const char*      get_error_string() const noexcept;
    std::string      info() const override;
    const char*      what() const noexcept override;
    const std::byte* get_target() const;
  };

  class os_exception : public alterhook_exception
  {
  public:
    os_exception(std::error_code error_code);
    os_exception(int code);

    os_exception(const os_exception& other)            = default;
    os_exception& operator=(const os_exception& other) = default;

    std::error_code     get_error_code() const;
    virtual std::string error_function() const = 0;
    std::string         info() const override;
  };

  class misc_exception : public alterhook_exception
  {
  public:
    misc_exception();

    misc_exception(const misc_exception& other)            = default;
    misc_exception& operator=(const misc_exception& other) = default;
  };
}
```

## alterhook_exception

### Description

The base of every exception that can be thrown from the library. So if you would like to catch any exception specifically from this library you can catch a reference to this abstract base class like:

```cpp
int main()
{
  try
  {
    alterhook::hook hook{ &target::func, &detour::func, original };
    hook.enable();
  }
  catch (const alterhook::exceptions::alterhook_exception& exception)
  {
    std::cout << exception.what() << '\n' << exception.info();
    return 1;
  }
}
```

It itself doesn't have any members so its virtual methods are expected to be overridden by its derived classes mentioned in the hierarchy tree. The methods included are `what()` and `info()`. The one is inherited from `std::exception` and the other is defined as a pure virtual function inside `alterhook_exception`.

### what

Returns a constant c string that represents an error message. That error message is human-friendly and it briefly describes what happened in a single sentence.

### info

Returns some exception-specific information stored in an instance of `std::string`. It can contain any information considered useful for identifying the issue. For example, any child of `alterhook::exceptions::os_exception` will include the stringified error of the system API call as well as the call itself with the arguments that were called with as a string. This is usually a heavy function so try not to call it more than once.

## trampoline_exception

### Description

A base class for many of the exceptions that can be thrown during the initialization of the trampoline. It is used to denote that the relocation operation can't be completed safely for a number of reasons, such as high code complexity or too small buffer. The library tries its best to handle most of the edge cases you will ever encounter but there may be still things it can't properly deal with. You can catch this exception and extract as much information as possible about what went wrong when initializing the trampoline.

### get_target

In addition to the overrides of [info](#info) and [what](#what) which are inherited from [alterhook_exception](#alterhook_exception) this additionally includes a small getter that returns a pointer to the target function that the trampoline was to be initialized with.

## disassembler_exception

### Description

A base class for any exception that can be thrown when capstone returns an error. It is very rare as capstone generally doesn't fail when it encounters a broken instruction and instead iteration just ends. Leaving the trampoline with all the instructions that it had before that happened. So in most cases, it may be worth capturing [trampoline_exception](#trampoline_exception) instead.

### get_target

Returns a pointer to the trampoline's target function.

### get_error_string

Returns a stringified version of the capstone error code returned from the capstone API. The stringified version is obtained via a call to `cs_strerror`.

## os_exception

### Description

A base class for every exception that is related to errors returned from the system API. For each system API call that the library checks the result of it throws a unique exception when an error occurs. The `os_exception` base holds the error code as `std::error_code` and any derived classes may hold additional information (such as the arguments the system API function was called with).

### get_error_code

Returns the instance of `std::error_code` that it currently holds. You can use the API it has to extract more information such as the `message` method which returns a system-specific string explaining the error based on the error code.

### error_function

Returns a stringified version of the system function call with the arguments evaluated. For example `VirtualAlloc(0x00ff, 4000, 0, 0)`.

## misc_exception

### Description

Nothing special about this one, it's a base class for exceptions that don't fit to the other categories. It inherits all methods from `alterhook_exception` and doesn't add new ones. So it expects its base classes to override the virtual methods to add meaning to them.

## Exception Class Generation

### Description

If you take a look at [exceptions.h](../include/alterhook/exceptions.h) you will see a lot of macro calls instead of classes representing the exceptions specified. That is because of the amount of boilerplate required to properly define the classes themselves which is time-wasting and annoying. The library instead uses a few nice utilities to generate the classes at prepossess time with just a few macro calls. The macros used are the following:

- [utils_generate_exception(exception_name, base, fields, base_args, ...)](#utils_generate_exception)
- utils_generate_exception_no_fields(exception_name, base, base_args, ...)
- utils_generate_exception_no_base_args(exception_name, base, fields, ...)
- utils_generate_empty_exception(exception_name, base, ...)

### utils_generate_exception

Generates an exception class with the following properties:

- exception_name: the name of the exception (aka the name of the class)
- base: the class to inherit from
- fields: a "list" of type and identifier "pairs" that represents the fields to add to the class. For each field, a constructor argument and member initializer are added as well as a getter to the field with the name being `get_<field name>()`.
- base_args: a "list" of type and identifier "pairs" that represents the arguments to forward to the base class. They are all added to the constructor as arguments before the arguments that the fields will be initialized with and they are forwarded to the base class.
- `__VA_ARGS__`: Any additional content to add to the class. For example, user-defined methods.

### utils_generate_exception_no_fields

Same as [utils_generate_exception](#utils_generate_exception) but without the fields argument.

### utils_generate_exception_no_base_args

Same as [utils_generate_exception](#utils_generate_exception) but without the base_args argument.

### utils_generate_empty_exception

Same as [utils_generate_exception](#utils_generate_exception) but without the fields and base_args arguments.

### Example

```cpp
utils_generate_exception(
  my_exception, my_base,
  (
    (int, member1),
    (float, member2)
  ),
  (
    (double, base_arg1),
    (char, base_arg2)
  ),
  void my_custom_method();
)
```

This will generate an exception with two members, two getters for them, and a constructor to initialize both the members and forward the arguments to the base class. It will also include the custom method declaration. This will effectively expand to the following:

```cpp
class my_exception : public my_base
{
public:
  void my_custom_method();

private:
  int   m_member1;
  float m_member2;

public:
  my_exception(double base_arg1, char base_arg2, int member1, float member2)
      : my_base(base_arg1, base_arg2), m_member1(member1), m_member2(member2)
  {
  }

  my_exception(const my_exception& other)            = default;
  my_exception& operator=(const my_exception& other) = default;

  int get_member1() const { return m_member1; }

  float get_member2() const { return m_member2; }
};
```
