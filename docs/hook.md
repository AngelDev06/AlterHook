# Hook

A class that represents a hook, i.e. function detouring achieved by inline code injection in the first few bytes of the function while also providing a trampoline function to call back the original successfully. A hook instance is responsible for taking care of the above as well as making sure no hooks are leaked which means hooks are always disabled on destruction. It has two states, enabled and disabled which are self-explanatory. One can switch states and/or modify the properties of the hook such as the detour, the target and the original callback at any time in a thread-safe way using its simple API.

## Synopsis

<pre>
 <code>
namespace alterhook
{
  class hook : trampoline
  {
  public:
    template &lt;typename dtr, typename orig&gt;
    <a href="#hookstdbyte-target-dtr-detour-orig-original-bool-enable_hook--true">hook</a>(std::byte* target, dtr&& detour, orig& original,
         bool enable_hook = true);

    template &lt;typename dtr&gt;
    <a href="#hookstdbyte-target-dtr-detour-bool-enable_hook--true">hook</a>(std::byte* target, dtr&& detour, bool enable_hook = true);

    template &lt;typename trg, typename dtr, typename orig&gt;
    <a href="#hooktrg-target-dtr-detour-orig-original-bool-enable_hook--true">hook</a>(trg&& target, dtr&& detour, orig& original, bool enable_hook = true);

    template &lt;typename trg, typename dtr&gt;
    <a href="#hooktrg-target-dtr-detour-bool-enable_hook--true">hook</a>(trg&& target, dtr&& detour, bool enable_hook = true);

    <a href="#copy-constructor">hook</a>(const hook& other);
    <a href="#move-constructor">hook</a>(hook&& other) noexcept;

    <a href="#hookconst-trampoline-tramp">hook</a>(const trampoline& tramp);

    <a href="#hooktrampoline-tramp">hook</a>(trampoline&& tramp) noexcept;

    <a href="#default-constructor">hook</a>() noexcept {}

    ~hook() noexcept;

    hook& <a href="#copy-assignment-operator">operator=</a>(const hook& other);
    hook& <a href="#move-assignment-operator">operator=</a>(hook&& other) noexcept;
    hook& <a href="#operatorconst-trampoline-other">operator=</a>(const trampoline& other);
    hook& <a href="#operatortrampoline-other">operator=</a>(trampoline&& other);

    void <a href="#enable">enable</a>();
    void <a href="#disable">disable</a>();

    using <a href="trampoline.md#get_target">trampoline::get_target</a>;

    const std::byte* <a href="#get_detour">get_detour</a>() const noexcept;

    size_t <a href="#trampoline_size">trampoline_size</a>() const noexcept;

    size_t <a href="#trampoline_count">trampoline_count</a>() const noexcept;

    std::string <a href="#trampoline_str">trampoline_str</a>() const;

    bool <a href="#is_enabled">is_enabled</a>() const noexcept;

    explicit <a href="#operator-bool">operator bool</a>() const noexcept;

    void <a href="#set_targetstdbyte-target">set_target</a>(std::byte* target);

    template &lt;typename trg&gt;
    void <a href="#set_targettrg-target">set_target</a>(trg&& target);

    template &lt;typename dtr&gt;
    void <a href="#set_detour">set_detour</a>(dtr&& detour);

    template &lt;typename orig&gt;
    void <a href="#set_original">set_original</a>(orig& original);

    void <a href="#reset_original">reset_original</a>();

    bool <a href="#comparison">operator==</a>(const hook& other) const noexcept;
    bool <a href="#comparison">operator!=</a>(const hook& other) const noexcept;
  };
}
 </code>
</pre>

## Constructors

### default constructor

#### Description

Constructs an empty hook, i.e. a hook that has no target, detour, trampoline etc. It is left as stateless waiting to be initialized properly. Calling methods such as enable/disable while it is left stateless will result in debug assertion failures.

### copy constructor

#### Description

The copy constructor of the hook class. This will result in a full copy of all of the properties of the `other` instance such as target, detour, and original callback except for the state. However, this means that it will also allocate a new trampoline buffer to hold the relocated instructions as it calls the trampoline's copy constructor.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| other | const hook& | the instance to copy |

#### Exceptions

- [Trampoline Copy Exceptions](exception_groups.md#trampoline-copy-exceptions)

#### Notes

As mentioned the copy constructor doesn't copy state. Therefore `*this` will remain disabled after copy construction till it is manually enabled.

### move constructor

#### Description

The move constructor of the hook class. This will transfer ownership of the trampoline buffer as well as copy all of the properties of the `other` instance into the current one. It is a fast and exception-free operation which should be preferred when two separate copies of the same hook aren't needed.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| other | hook&& | the instance to move |

### hook(std::byte* target, dtr&& detour, orig& original, bool enable_hook = true)

#### Description

Constructs a hook instance with the specified target, detour and reference to the original callback. It will by default also enable the hook unless specified otherwise in the enable_hook argument.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| target | std::byte* | the pointer to the target function |
| detour | dtr&& (forwarding reference, any) | the detour callback to use (can be any callable type) |
| original | orig& (any) | the reference to the original callback that the detour will invoke |
| enable_hook | bool | whether to enable the hook after initialization (defaults to true) |

#### Exceptions

- [Trampoline Initialization Exceptions](exception_groups.md#trampoline-initialization-exceptions)
- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions) (**<ins>Only when `enable_hook == true`</ins>**)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions) (**<ins>Only when `enable_hook == true`</ins>**)

#### Notes

Compile time assertions are performed to make sure the detour passed is compatible with the reference to the original callback in order to avoid runtime issues.

### hook(std::byte* target, dtr&& detour, bool enable_hook = true)

#### Description

Constructs a hook instance with the specified target and detour. It is left without an original callback to use and will by default be enabled unless specified otherwise in the enable_hook argument.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| target | std::byte* | the pointer to the target function |
| detour | dtr&& (forwarding reference, any) | the detour callback to use (can be any callable type) |
| enable_hook | bool | whether to enable the hook after initialization (defaults to true) |

#### Exceptions

- [Trampoline Initialization Exceptions](exception_groups.md#trampoline-initialization-exceptions)
- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions) (**<ins>Only when `enable_hook == true`</ins>**)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions) (**<ins>Only when `enable_hook == true`</ins>**)

#### Notes

No compile time assertions are performed here as the only callable type given to the library is the detour one.

### hook(trg&& target, dtr&& detour, orig& original, bool enable_hook = true)

#### Description

Constructs a hook instance with the specified target, detour and original callback. It will by default also enable the hook unless specified otherwise in the enable_hook argument.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| target | trg&& (forwarding reference, any) | the target callback to use (can be any callable type) |
| detour | dtr&& (forwarding reference, any) | the detour callback to use (can be any callable type) |
| original | orig& (any) | the reference to the original callback that the detour will invoke |
| enable_hook | bool | whether to enable the hook after initialization (defaults to true) |

#### Exceptions

- [Trampoline Initialization Exceptions](exception_groups.md#trampoline-initialization-exceptions)
- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions) (**<ins>Only when `enable_hook == true`</ins>**)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions) (**<ins>Only when `enable_hook == true`</ins>**)

#### Notes

Compile time assertions are performed for all of the three callable types given to prevent potential runtime issues from happening. Such as when the target has a non-compatible calling convention with the detour.

### hook(trg&& target, dtr&& detour, bool enable_hook = true)

#### Description

Constructs a hook instance with the specified target and detour. It will be left without an original callback and will be enabled by default unless specified otherwise in the enable_hook argument.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| target | trg&& (forwarding reference, any) | the target callback to use (can be any callable type) |
| detour | dtr&& (forwarding reference, any) | the detour callback to use (can be any callable type) |
| enable_hook | bool | whether to enable the hook after initialization (defaults to true) |

#### Exceptions

- [Trampoline Initialization Exceptions](exception_groups.md#trampoline-initialization-exceptions)
- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions) (**<ins>Only when `enable_hook == true`</ins>**)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions) (**<ins>Only when `enable_hook == true`</ins>**)

#### Notes

Compile time assertions are performed between the target and the detour callable type to prevent potential runtime issues.

### hook(const trampoline& tramp)

#### Description

Constructs a hook instance using the target of the `tramp` instance and by copying all of its instructions to a newly allocated trampoline buffer. It is left without a detour or an original callback so using enable/disable will not work.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| tramp | const trampoline& | the trampoline to copy from |

#### Exceptions

- [Trampoline Copy Exceptions](exception_groups.md#trampoline-copy-exceptions)

### hook(trampoline&& tramp)

#### Description

Constructs a hook instance by taking ownership of the trampoline buffer from `tramp` leaving it empty and initializing the current instance with its target.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| tramp | trampoline&& | the trampoline to move from |

## Assignment operator

### copy assignment operator

#### Description

The copy assignment operator of the hook class. This will disable the currently existing hook (if enabled) as well as reuse the trampoline buffer it maintains to store the newly relocated instructions (it will allocate one if not initialized). This will result in two separate hooks "copies" with the same target/detour/original but different trampoline.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| tramp | const hook& | the hook to copy assign from |

#### Returns

A reference to `*this` allowing for chain assignments.

#### Exceptions

- [Trampoline Copy Exceptions](exception_groups.md#trampoline-copy-exceptions)

#### Notes

The instance that gets assigned will remain disabled after the assignment even if it was enabled before.

### move assignment operator

#### Description

The move assignment operator of the hook class. It will disable the current hook (if enabled) and de-allocate the existing buffer. It will then claim ownership of the trampoline buffer and leave the other hook uninitialized.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| tramp | hook&& | the hook to move assign from |

#### Returns

A reference to `*this` allowing for chain assignments.

#### Notes

The instance that gets assigned will also claim the status of the other hook. So the hook will remain enabled if `other` was enabled.

### operator=(const trampoline& other)

#### Description

Copy assigns the hook with a trampoline instance. It will redirect the current hook to the new target provided by `other` as well as copy its contents across to the current buffer replacing any existing ones.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| tramp | const trampoline& | the trampoline to copy assign from |

#### Returns

A reference to `*this` allowing for chain assignments.

#### Exceptions

- [Trampoline Copy Exceptions](exception_groups.md#trampoline-copy-exceptions)

#### Notes

Before doing the assignment the current hook will be disabled (if enabled) and after it's done it will then proceed to re-enable it (if it was previously enabled). Also, note that the detour and original callback are left untouched and will be reused.

### operator=(trampoline&& other)

#### Description

Move assigns the hook with a trampoline instance. It will deallocate the existing trampoline buffer and claim ownership of the one `other` holds, leaving `other` empty. The current hook instance will also be redirected to the new target.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| tramp | trampoline&& | the trampoline to move assign from |

#### Returns

A reference to `*this` allowing for chain assignments.

#### Notes

Before doing the assignment the current hook will be disabled (if enabled) and after it's done it will then proceed to re-enable it (if it was previously enabled) while also having set the original callback to point to the new trampoline. Also, note that the detour is left untouched and will be reused.

## Methods

### enable

#### Description

Enables the hook by injecting an ASM jump pointing to the detour on the first few instructions of the target.

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)

### disable

#### Description

Disables the hook by injecting back the first few bytes to the target function that was replaced earlier.

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)

## Getters

### get_detour

#### Returns

A `const std::byte*` to the detour function.

### trampoline_size

#### Returns

The amount of bytes the instructions in the trampoline buffer occupy. Basically [trampoline::size](trampoline.md#size).

### trampoline_count

#### Returns

The number of instructions in the trampoline buffer. Basically [trampoline::count](trampoline.md#count).

### trampoline_str

#### Returns

The disassembled instructions of the trampoline buffer, represented as a string. Basically [trampoline::str](trampoline.md#str)

### is_enabled

#### Returns

A boolean which denotes whether the hook is enabled or disabled.

### operator bool

#### Returns

Same as [is_enabled](#is_enabled).

## Setters

### set_target(std::byte* target)

#### Description

Sets the target function to point to. May also be used as an initializer of an uninitialized hook.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| target | std::byte* | the target to use |

#### Exceptions

- [Trampoline Initialization Exceptions](exception_groups.md#trampoline-initialization-exceptions)
- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions) (**<ins>Only when already enabled</ins>**)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions) (**<ins>Only when already enabled</ins>**)

#### Notes

May disable the current hook if it's already enabled and re-enable it afterward using the same detour and original callback. It does nothing if the hook already uses the target specified.

### set_target(trg&& target)

#### Description

Sets the target function to point to. May also be used as an initializer of an uninitialized hook.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| target | trg&& (forwarding reference, any) | the target to use |

#### Exceptions

- [Trampoline Initialization Exceptions](exception_groups.md#trampoline-initialization-exceptions)
- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions) (**<ins>Only when already enabled</ins>**)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions) (**<ins>Only when already enabled</ins>**)

#### Notes

May disable the current hook if it's already enabled and re-enable it afterward using the same detour and original callback. It does nothing if the hook already uses the target specified.

### set_detour

#### Description

Sets the detour.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| detour | dtr&& (forwarding reference, any) | the detour to use |

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions) (**<ins>Only when already enabled, 32-bit specific</ins>**)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions) (**<ins>Only when already enabled, 32-bit specific</ins>**)

#### Notes

If the hook is already enabled it will simply patch the jump to point to the new detour.

### set_original

#### Description

Sets `original` to point to the trampoline buffer, obtains a reference to it and sets the old original callback to `nullptr` if it exists. Can be used to switch original callbacks.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| original | orig& (any) | the original callback reference to use |

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions) (**<ins>Only when already enabled</ins>**)

#### Notes

It does not disable the hook if it's already enabled but instead switches callbacks while it is enabled. This will happen in a thread-safe manner as threads are blocked from execution when it sets the original callback. If the hook instance already holds a reference to the provided callback it does nothing.

### reset_original

#### Description

Resets the reference to the original callback if it exists. That means setting the callback to `nullptr` and erasing the reference from the instance.

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions) (**<ins>Only when already enabled</ins>**)

#### Notes

It does not disable the hook if it's already enabled so be careful when using it. Calling an empty callback can crash your program.

## Comparison

Equality is determined by the following factors:

- the pointer to the target
- the pointer to the detour
- the status (enabled/disabled)

If the above compare equal then:

- operator== returns true.
- operator!= returns false.

Otherwise, it's the other way around.

Note that the original callback is not a comparison factor.
