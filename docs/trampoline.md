# Trampoline

A class that is responsible for maintaining a buffer of executable memory that stores the first few relocated instructions of the target function. It may also have to generate ASM at runtime to make sure relocation doesn't break any instructions (as some instructions depend on their position). All it requires is a pointer to the target function, it does NOT keep reference to the detour or the original callback.

## Synopsis

<pre>
 <code>
namespace alterhook
{
  class trampoline
  {
  public:
    <a href="#default-constructor">trampoline</a>() noexcept;

    <a href="#trampolinestdbyte">trampoline</a>(std::byte* target);

    <a href="#copy-constructor">trampoline</a>(const trampoline& other);
    <a href="#move-constructor">trampoline</a>(trampoline&& other) noexcept;
    trampoline& <a href="#copy-assignment-operator">operator=</a>(const trampoline& other);
    trampoline& <a href="#move-assignment-operator">operator=</a>(trampoline&& other) noexcept;

    ~trampoline() noexcept;

    void <a href="#init">init</a>(std::byte* target);

    template &lt;typename fn, typename... types&gt;
    auto <a href="#invoke">invoke</a>(types&&... values) const;

    std::byte* <a href="#get_target">get_target</a>() const noexcept;

    size_t <a href="#size">size</a>() const noexcept;

    size_t <a href="#count">count</a>() const noexcept;

    std::string <a href="#str">str</a>() const;
  };
}
 </code>
</pre>

## Constructors

### default constructor

#### Description

The default constructor of the trampoline class. All it does is default construct all member fields with null values. It will remain inactivated with no target until you invoke [init](#init).

### copy constructor

#### Description

The copy constructor of the trampoline class. The new instance will allocate a new executable block of memory and use it to relocate the instructions from the `other` trampoline. The instructions `other` holds will not be erased as this is a move-only operation and the new instructions generated will be treated accordingly so that they work in the location they were placed in. The pointer to the target will also be copied so [invoke](#invoke) will call the same target function and should have the same effect.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| other | const trampoline& | The instance to copy |

#### Exceptions

- [Trampoline Copy Exceptions](exception_groups.md#trampoline-copy-exceptions)

### move constructor

#### Description

The move constructor of the trampoline class. The new instance will claim responsibility for maintaining the executable buffer the `other` instance holds and it will leave the `other` empty (i.e. without target or buffer to manage). Unlike the [copy constructor](#copy-constructor) the move one doesn't do any memory allocations or other expensive tasks, so it should be preferred when there is no need of having two separate copies of the same target and executable buffer.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| other | trampoline&& | The instance to move |

### trampoline(std::byte*)

#### Description

The constructor is responsible for initializing the trampoline. It uses the `target` argument to set up the underlying executable buffer and relocate the instructions across.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| target | std::byte* | The target to initialize it with |

#### Exceptions

- [Trampoline Initialization Exceptions](exception_groups.md#trampoline-initialization-exceptions)

## Assignment operators

### copy assignment operator

#### Description

The copy assignment operator of the trampoline class. It will redirect the current instance to the target of `other` while effectively reusing the existing executable buffer. It will handle relocations properly and modify any instructions needed to make it work. Just like with the [copy constructor](#copy-constructor) it will leave `other` untouched and the operation will result in two trampolines sharing the same target.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| other | const trampoline& | The instance to copy assign from |

#### Returns

A reference to `*this` allowing for chain assignments.

#### Exceptions

- [Trampoline Copy Exceptions](exception_groups.md#trampoline-copy-exceptions)

#### Exception Guarantee

**<ins>STRONG:</ins>** always

### move assignment operator

#### Description

The move assignment operator of the trampoline class. Just like the [move constructor](#move-constructor) it will take ownership of the executable buffer of the `other` instance, redirect itself to the new target and clean up the existing buffer. It will leave `other` uninitialized which you reuse via [init](#init).

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| other | trampoline&& | The instance to move assign from |

#### Returns

A reference to `*this` allowing for chain assignments.

## Methods

### init

#### Description

Initializes the trampoline using `target` as the target function. That means setting up the buffer (or reusing an existing one) and relocating instructions.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| target | std::byte* | The target to initialize the trampoline with |

#### Exceptions

- [Trampoline Initialization Exceptions](exception_groups.md#trampoline-initialization-exceptions)

#### Exception Guarantee

**<ins>STRONG:</ins>** Only when `alterhook::exceptions::misc::invalid_address` or memory allocation related exceptions are thrown (i.e. `alterhook::exceptions::os::virtual_alloc_exception` for windows and `alterhook::exceptions::os::mmap_exception` for Android/Linux)

**<ins>BASIC:</ins>** On any other exception. The container is guaranteed to be left in an uninitialized but reusable state.

#### Notes

This method does nothing if the trampoline is already initialized with the target specified. If it is initialized but with a different target, it will simply redirect itself to the new target while reusing the old buffer (so no memory allocations happen in that case). Therefore this method can be called more than once unlike most init methods classes provide. Also, the exceptions mentioned above are very unlikely to ever happen so depending on your case it may not be necessary to add handling code.

### invoke

#### Description

Invokes the currently owning executable buffer using the function signature specified as a template parameter and the args passed.

#### Parameters

| Template Parameter | Description |
| --- | --- |
| fn | the function type to use to call the executable buffer |

| Parameter | Type | Description |
| --- | --- | --- |
| values | types&& (forwarding reference, variadic args) | The arguments to forward to the function call |

#### Returns

The return value of the trampoline call which of the type specified in `fn` template argument. If void then it returns nothing.

#### Notes

It does NOT check if the function type specified matches the one that the trampoline should be invoked with. So you need to verify you are using the correct one if you don't wish to get UB.

## Getters

### get_target

#### Returns

A pointer of type `std::byte*` to the target that the trampoline is initialized with. If not initialized it returns `nullptr`.

### size

#### Returns

The amount of bytes that the instructions included in the executable buffer take.

### count

#### Returns

The amount of instructions included in the executable buffer.

### str

#### Returns

Returns an instance of `std::string` containing the disassembled content of the executable buffer which of course is architecture-specific.

#### Notes

This is a heavy function so avoid calling it multiple times.
