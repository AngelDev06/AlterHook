# Exception Groups

## Trampoline Initialization Exceptions

Consists of exceptions generated during the initialization of the trampoline:

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
  - [alterhook::exceptions::os::mmap_exception](../include/alterhook/exceptions.h#L352-L370) (**<ins>Linux/Android specific</ins>**)
- [alterhook::exceptions::misc_exception](../include/alterhook/exceptions.h#L65)
  - [alterhook::exceptions::misc::invalid_address](../include/alterhook/exceptions.h#L428-L438)

## Trampoline Copy Exceptions

Consists of exceptions generated when copying another trampoline instance:

- [alterhook::exceptions::disassembler_exception](../include/alterhook/exceptions.h#L29-L42) (**<ins>x86 specific</ins>**)
  - [alterhook::exceptions::disassembler::disassembler_init_fail](../include/alterhook/exceptions.h#L258-L268)
  - [alterhook::exceptions::disassembler::disassembler_iter_init_fail](../include/alterhook/exceptions.h#L270-L280)
  - [alterhook::exceptions::disassembler::disassembler_disasm_fail](../include/alterhook/exceptions.h#L282-L293)
- [alterhook::exceptions::os_exception](../include/alterhook/exceptions.h#L54-L63)
  - [alterhook::exceptions::os::virtual_alloc_exception](../include/alterhook/exceptions.h#L299-L315) (**<ins>Windows specific</ins>**)
  - [alterhook::exceptions::os::mmap_exception](../include/alterhook/exceptions.h#L352-L370) (**<ins>Linux/Android specific</ins>**)

## Trampoline Stringification Exceptions

Consists of exceptions generated during a call to [trampoline::str](trampoline.md#str):

- [alterhook::exceptions::disassembler_exception](../include/alterhook/exceptions.h#L29-L42)
  - [alterhook::exceptions::disassembler::disassembler_init_fail](../include/alterhook/exceptions.h#L258-L268)
  - [alterhook::exceptions::disassembler::disassembler_iter_init_fail](../include/alterhook/exceptions.h#L270-L280)
  - [alterhook::exceptions::disassembler::disassembler_disasm_fail](../include/alterhook/exceptions.h#L282-L293)

## Thread Freezer Exceptions

Consists of exceptions generated when attempting to block other threads from execution for safety reasons:

- [alterhook::exceptions::os_exception](../include/alterhook/exceptions.h#L54-L63)
  - [alterhook::exceptions::os::thread_list_traversal_fail](../include/alterhook/exceptions.h#L317-L331) (**<ins>Windows specific</ins>**)
  - [alterhook::exceptions::os::sigaction_exception](../include/alterhook/exceptions.h#L372-L388) (**<ins>Linux/Android specific</ins>**)
- [alterhook::exceptions::misc_exception](../include/alterhook/exceptions.h#L65) (**<ins>Linux/Android specific</ins>**)
  - [alterhook::exceptions::misc::thread_process_fail](../include/alterhook/exceptions.h#L413-L425)

## Target Injection Exceptions

Consists of exceptions generated when the library attempts to modify the target function:

- [alterhook::exceptions::os_exception](../include/alterhook/exceptions.h#L54-L63)
  - [alterhook::exceptions::os::virtual_protect_exception](../include/alterhook/exceptions.h#L333-L350) (**<ins>Windows specific</ins>**)
  - [alterhook::exceptions::os::mprotect_exception](../include/alterhook/exceptions.h#L390-L406) (**<ins>Linux/Android specific</ins>**)

## Memory Allocation and Address Validation Exceptions

- [alterhook::exceptions::os_exception](../include/alterhook/exceptions.h#L54-L63)
  - [alterhook::exceptions::os::virtual_alloc_exception](../include/alterhook/exceptions.h#L299-L315) (**<ins>Windows specific</ins>**)
  - [alterhook::exceptions::os::mmap_exception](../include/alterhook/exceptions.h#L352-L370) (**<ins>Linux/Android specific</ins>**)
- [alterhook::exceptions::misc_exception](../include/alterhook/exceptions.h#L65)
  - [alterhook::exceptions::misc::invalid_address](../include/alterhook/exceptions.h#L428-L438)
