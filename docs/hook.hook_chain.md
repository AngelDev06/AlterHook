# Hook

Represents an element of the [hook_chain](hook_chain.md) container. Unlike the [hook](hook.md) class, this one is container-aware, meaning it keeps track of its position in the container by holding its respective list iterator and a pointer to the container it belongs to. This is required for the hook to modify its neighboring elements when it changes state so that the order is maintained and no other hooks are affected. This allows for each element to be able to change state or other properties (such as the detour and the original callback) from just a single reference to the element.

## Synopsis
<!-- markdownlint-disable MD037 -->
<pre>
 <code>
class hook_chain::hook
{
public:
  // constructors
  <a href="#default-constructor">hook</a>() noexcept;

  // state update
  void <a href="#enable">enable</a>();
  void <a href="#disable">disable</a>();

  // getters
  iterator            <a href="#get_iterator">get_iterator</a>() noexcept;
  const_iterator      <a href="#get_iterator-const">get_iterator</a>() const noexcept;
  const_iterator      <a href="#get_const_iterator-const">get_const_iterator</a>() const noexcept;
  list_iterator       <a href="#get_list_iterator">get_list_iterator</a>() noexcept;
  const_list_iterator <a href="#get_list_iterator-const">get_list_iterator</a>() const noexcept;
  const_list_iterator <a href="#get_const_list_iterator-const">get_const_list_iterator</a>() const noexcept;
  hook_chain&         <a href="#get_chain-const">get_chain</a>() const noexcept;
  std::byte*          <a href="#get_target-const">get_target</a>() const noexcept;
  const std::byte*    <a href="#get_detour-const">get_detour</a>() const noexcept;
  bool                <a href="#is_enabled-const">is_enabled</a>() const noexcept;
  explicit            <a href="#operator-bool-const">operator bool</a>() const noexcept;

  // setters
  template &lt;typename dtr&gt;
  void <a href="#set_detour">set_detour</a>(dtr&& detour);
  template &lt;typename orig&gt;
  void <a href="#set_original">set_original</a>(orig& original);

  bool <a href="#comparison">operator==</a>(const hook& other) const noexcept;
  bool <a href="#comparison">operator!=</a>(const hook& other) const noexcept;
};
 </code>
</pre>
<!-- markdownlint-enable MD037 -->
## Constructors

### default constructor

#### Description

Default constructs a temporary hook instance.

#### Notes

This is not meant to be used by the client but is still provided because the standard library needs to use it. Using it in code outside the library would be pointless anyway as an instance of `hook_chain::hook` can't be copied/moved or assigned and therefore a default constructed instance would forever be empty.

## Methods

### enable

#### Description

Enables the hook.

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)

#### Exception Guarantee

**<ins>STRONG:</ins>** Always.

#### Notes

This apart from enabling the current hook is also responsible for maintaining the iteration order of the hook chain instance it belongs to as well as modifying the neighboring hooks to make sure no other hooks are affected by the operation.

### disable

#### Description

Disables the hook.

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)

#### Exception Guarantee

**<ins>STRONG:</ins>** Always.

#### Notes

This apart from disabling the current hook is also responsible for maintaining the iteration order of the hook chain instance it belongs to as well as modifying the neighboring hooks to make sure no other hooks are affected by the operation.

## Getters

### get_iterator()

#### Returns

An `iterator` to `*this`.

### get_iterator() const

#### Returns

A `const_iterator` to `*this`.

### get_const_iterator() const

#### Returns

A `const_iterator` to `*this`.

### get_list_iterator()

#### Returns

A `list_iterator` to `*this`.

### get_list_iterator() const

#### Returns

A `const_list_iterator` to `*this`.

### get_const_list_iterator() const

#### Returns

A `const_list_iterator` to `*this`.

### get_chain() const

#### Returns

A reference to the hook chain instance that `*this` belongs to.

### get_target() const

#### Returns

A pointer to the target function.

### get_detour() const

#### Returns

A pointer to the detour of `*this`.

### is_enabled() const

#### Returns

`true` if the state of `*this` is enabled, else `false`.

### operator bool() const

#### Returns

`true` if the state of `*this` is enabled, else `false`.

## Setters

### set_detour

#### Description

Sets the detour of the hook.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| detour | dtr&& (forwarding reference, any) | the detour to use |

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)

#### Exception Guarantee

**<ins>STRONG:</ins>** Always.

#### Notes

This will also have to link the new detour to the chain via modifying the neighboring elements if any but no other hook is affected except the current one.

### set_original

#### Description

Sets the reference passed to a pointer to the next detour (or the trampoline if none) and stores it in the object itself overriding any existing one. The reference to the original callback that was set previously to the hook is set to `nullptr` before getting overridden.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| original | orig& (any) | the detour to use |

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)

#### Exception Guarantee

**<ins>STRONG:</ins>** Always.

## Comparison

Equality is determined by the following factors:

- The pointer to the target function.
- The pointer to the detour.
- The state (enabled or disabled)

If all of the above compare equal then:

- operator==: returns `true`
- operator!=: returns `false`

Otherwise, it's the other way around.

Note that the original callback is not a comparison factor.
