# Exceptions
A hierarchy of exceptions that the library may throw when an error occurs. All of the exceptions mentioned here are thrown very rarely and most of the time it's not the programmer's fault but rather an out of control problem caused by other sources such as the system api the library uses. But nevertheless the library is designed with strong exception guarantee in mind or basic if that's not possible for specific scenarios.

The hierarchy is as follows:
- [alterhook::exceptions::alterhook_exception](../include/alterhook/exceptions.h#L16-L19)
    - [alterhook::exceptions::trampoline_exception](../include/alterhook/exceptions.h#L21-L27)
        - [alterhook::exceptions::trampoline::unsupported_instruction_handling](../include/alterhook/exceptions.h#L91-L104)
        - [alterhook::exceptions::trampoline::it_block_exception](../include/alterhook/exceptions.h#L107-L130) (**<ins>ARM specific</ins>**)
            - [alterhook::exceptions::trampoline::it_block::invalid_it_block](../include/alterhook/exceptions.h#L134-L147)
            - [alterhook::exceptions::trampoline::it_block::incomplete_it_block](../include/alterhook/exceptions.h#L149-L163)
        - [alterhook::exceptions::trampoline::unused_register_not_found](../include/alterhook/exceptions.h#L166-L176) (**<ins>ARM specific</ins>**)
        - [alterhook::exceptions::trampoline::pc_relative_handling_fail](../include/alterhook/exceptions.h#L178-L205) (**<ins>ARM specific</ins>**)
        - [alterhook::exceptions::trampoline::instructions_in_branch_handling_fail](../include/alterhook/exceptions.h#L208-L218)
        - [alterhook::exceptions::trampoline::trampoline_max_size_exceeded](../include/alterhook/exceptions.h#L220-L234)
        - [alterhook::exceptions::trampoline::insufficient_function_size](../include/alterhook/exceptions.h#L236-L251)
    - [alterhook::exceptions::disassembler_exception](../include/alterhook/exceptions.h#L29-L42)
        - [alterhook::exceptions::disassembler::disassembler_init_fail](../include/alterhook/exceptions.h#L258-L268)
        - [alterhook::exceptions::disassembler::disassembler_iter_init_fail](../include/alterhook/exceptions.h#L270-L280)
        - [alterhook::exceptions::disassembler::disassembler_disasm_fail](../include/alterhook/exceptions.h#L282-L293)
    - [alterhook::exceptions::os_exception](../include/alterhook/exceptions.h#L54-L63)
        - [alterhook::exceptions::os::virtual_alloc_exception](../include/alterhook/exceptions.h#L299-L315) (**<ins>Windows specific</ins>**)
        - [alterhook::exceptions::os::thread_list_traversal_fail](../include/alterhook/exceptions.h#L317-L331) (**<ins>Windows specific</ins>**)
        - [alterhook::exceptions::os::virtual_protect_exception](../include/alterhook/exceptions.h#L333-L350) (**<ins>Windows specific</ins>**)
        - [alterhook::exceptions::os::mmap_exception](../include/alterhook/exceptions.h#L352-L370) (**<ins>Linux specific</ins>**)
        - [alterhook::exceptions::os::sigaction_exception](../include/alterhook/exceptions.h#L372-L388) (**<ins>Linux/Android specific</ins>**)
        - [alterhook::exceptions::os::mprotect_exception](../include/alterhook/exceptions.h#L390-L406) (**<ins>Linux/Android specific</ins>**)
    - [alterhook::exceptions::misc_exception](../include/alterhook/exceptions.h#L65)
        - [alterhook::exceptions::misc::thread_process_fail](../include/alterhook/exceptions.h#L413-L425) (**<ins>Linux/Android specific</ins>**)
        - [alterhook::exceptions::misc::invalid_address](../include/alterhook/exceptions.h#L428-L438)

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
    os_exception(uint64_t error_code);

    os_exception(const os_exception& other)            = default;
    os_exception& operator=(const os_exception& other) = default;

    const char*         get_error_string() const noexcept;
    virtual std::string error_function() const = 0;
    std::string         info() const override;
    uint64_t            get_error_code() const;
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
Returns some exception specific information stored in an instance of `std::string`. It can contain any information considered useful for identifying the issue. For example any child of `alterhook::exceptions::os_exception` will include the stringified error of the system api call as well as the call itself with the arguments it that was called with as a string. This is usually a heavy function so try not to call it more than once.