# Hook Chain

A class that represents a chain of hooks. It allows a target to be hooked more than once and makes sure that each hook in the chain can change status without affecting the rest of the hooks. It offers features such as splicing, iteration, swapping, insertion, and deletion both inside the same instance and across instances. Under the hood, it maintains two linked lists, one for the disabled hooks and one for the enabled ones. Each time a hook changes status it gets spliced from the one list to the other and all the operations mentioned might as well be performed on one of the two lists individually.

## Synopsis
<!-- markdownlint-disable MD037 -->
<pre>
 <code>
class hook_chain : trampoline
{
public:
  // member types
  class hook;
  class const_iterator;
  class iterator;
  enum class transfer
  {
    disabled,
    enabled,
    both
  };
  typedef transfer                                include;
  typedef std::list&lt;hook&gt;::const_iterator         const_list_iterator;
  typedef std::list&lt;hook&gt;::iterator               list_iterator;
  typedef std::list&lt;hook&gt;::const_reverse_iterator const_reverse_list_iterator;
  typedef std::list&lt;hook&gt;::reverse_iterator       reverse_list_iterator;
  typedef hook                                    value_type;
  typedef size_t                                  size_type;
  typedef ptrdiff_t                               difference_type;
  typedef hook*                                   pointer;
  typedef const hook*                             const_pointer;
  typedef hook&                                   reference;
  typedef const hook&                             const_reference;

  // constructors/destructors/assignment operators
  template &lt;typename detour, typename orig, typename... types&gt;
  <a href="#hook_chainstdbyte-target-dtr-detour-orig-original-types-rest">hook_chain</a>(std::byte* target, dtr&& detour, orig& original, types&&... rest);

  template &lt;typename trg, typename dtr, typename orig, typename... types&gt;
  <a href="#hook_chaintrg-target-dtr-detour-orig-original-types-rest">hook_chain</a>(trg&& target, dtr&& detour, orig& original, types&&... rest);

  template &lt;typename pair, typename... types&gt;
  <a href="#hook_chainstdbyte-target-pair-first-types-rest">hook_chain</a>(std::byte* target, pair&& first, types&&... rest);

  template &lt;typename trg, typename pair, typename... types&gt;
  <a href="#hook_chaintrg-target-pair-first-types-rest">hook_chain</a>(trg&& target, pair&& first, types&&... rest);

  <a href="#hook_chainstdbyte-target">hook_chain</a>(std::byte* target);

  template &lt;typename trg&gt;
  <a href="#hook_chaintrg-target">hook_chain</a>(trg&& target);

  template &lt;typename orig&gt;
  <a href="#hook_chainconst-alterhookhook-other-orig-original">hook_chain</a>(const alterhook::hook& other, orig& original);

  <a href="#hook_chainalterhookhook-other">hook_chain</a>(alterhook::hook&& other);

  <a href="#hook_chainconst-trampoline-other">hook_chain</a>(const trampoline& other);

  <a href="#hook_chaintrampoline-other">hook_chain</a>(trampoline&& other) noexcept;

  <a href="#copy-constructor">hook_chain</a>(const hook_chain& other);
  <a href="#move-constructor">hook_chain</a>(hook_chain&& other) noexcept;

  <a href="#default-constructor">hook_chain</a>() noexcept {}

  ~hook_chain() noexcept;

  hook_chain& operator=(const hook_chain& other);
  hook_chain& operator=(hook_chain&& other) noexcept;
  hook_chain& operator=(const trampoline& other);
  hook_chain& operator=(trampoline&& other);

  // status update
  void enable_all();
  void disable_all();

  // container modifiers
  void          clear(include trg = include::both);
  void          pop_back(include trg = include::both);
  void          pop_front(include trg = include::both);
  list_iterator erase(list_iterator position);
  list_iterator erase(list_iterator first, list_iterator last);
  iterator      erase(iterator position);
  iterator      erase(iterator first, iterator last);

  template &lt;typename dtr, typename orig, typename... types&gt;
  void append(transfer to, dtr&& detour, orig& original, types&&... rest);

  template &lt;typename dtr, typename orig, typename... types&gt;
  void append(dtr&& detour, orig& original, types&&... rest);

  template &lt;typename pair, typename... types&gt;
  void append(transfer to, pair&& first, types&&... rest);

  template &lt;typename pair, typename... types&gt;
  void append(pair&& first, types&&... rest);

  template &lt;typename dtr, typename orig&gt;
  void push_back(dtr&& detour, orig& original, bool enable_hook = true);

  template &lt;typename dtr, typename orig&gt;
  void push_front(dtr&& detour, orig& original, bool enable_hook = true);

  template &lt;typename dtr, typename orig&gt;
  hook& insert(list_iterator position, dtr&& detour, orig& original,
                include trg = include::enabled);

  template &lt;typename dtr, typename orig&gt;
  hook& insert(iterator position, dtr&& detour, orig& original);

  void  swap(list_iterator left, hook_chain& other, list_iterator right);

  void swap(list_iterator left, list_iterator right);

  void swap(hook_chain& other);
  void merge(hook_chain& other, bool at_back = true);

  void merge(hook_chain&& other, bool at_back = true);

  void splice(list_iterator newpos, hook_chain& other,
              transfer to   = transfer::enabled,
              transfer from = transfer::both);

  void splice(list_iterator newpos, hook_chain&& other,
              transfer to = transfer::enabled, transfer from = transfer::both);

  void splice(iterator newpos, hook_chain& other,
              transfer from = transfer::both);

  void splice(iterator newpos, hook_chain&& other,
              transfer from = transfer::both);

  void splice(list_iterator newpos, hook_chain& other, list_iterator oldpos,
              transfer to = transfer::enabled);

  void splice(list_iterator newpos, hook_chain&& other, list_iterator oldpos,
              transfer to = transfer::enabled);

  void splice(iterator newpos, hook_chain& other, list_iterator oldpos);

  void splice(iterator newpos, hook_chain&& other, list_iterator oldpos);

  void splice(list_iterator newpos, hook_chain& other, list_iterator first,
              list_iterator last, transfer to = transfer::enabled);

  void splice(list_iterator newpos, hook_chain&& other, list_iterator first,
              list_iterator last, transfer to = transfer::enabled);

  void splice(iterator newpos, hook_chain& other, list_iterator first,
              list_iterator last);

  void splice(iterator newpos, hook_chain&& other, list_iterator first,
              list_iterator last);

  void splice(list_iterator newpos, hook_chain& other, iterator first,
              iterator last, transfer to = transfer::enabled);

  void splice(list_iterator newpos, hook_chain&& other, iterator first,
              iterator last, transfer to = transfer::enabled);

  void splice(iterator newpos, hook_chain& other, iterator first,
              iterator last);

  void splice(iterator newpos, hook_chain&& other, iterator first,
              iterator last);

  void splice(list_iterator newpos, list_iterator oldpos,
              transfer to = transfer::enabled);

  void splice(iterator newpos, list_iterator oldpos);

  void splice(list_iterator newpos, list_iterator first, list_iterator last,
              transfer to = transfer::enabled);

  void splice(iterator newpos, list_iterator first, list_iterator last);

  void splice(list_iterator newpos, iterator first, iterator last,
              transfer to = transfer::enabled);

  void splice(iterator newpos, iterator first, iterator last);

  // element access
  reference       operator[](size_t n) noexcept;
  const_reference operator[](size_t n) const noexcept;
  reference       at(size_t n);
  const_reference at(size_t n) const;
  reference       front() noexcept;
  const_reference front() const noexcept;
  reference       efront() noexcept;
  const_reference efront() const noexcept;
  reference       dfront() noexcept;
  const_reference dfront() const noexcept;
  reference       back() noexcept;
  const_reference back() const noexcept;
  reference       eback() noexcept;
  const_reference eback() const noexcept;
  reference       dback() noexcept;
  const_reference dback() const noexcept;

  // setters
  void set_target(std::byte* target);

  template &lt;typename trg&gt;
  void set_target(trg&& target);

  // getters
  bool empty() const noexcept;

  bool empty_enabled() const noexcept;

  bool empty_disabled() const noexcept;

  explicit operator bool() const noexcept;

  size_t size() const noexcept;

  size_t enabled_size() const noexcept;

  size_t disabled_size() const noexcept;

  using trampoline::get_target;

  // iterators
  iterator                    begin() noexcept;
  iterator                    end() noexcept;
  const_iterator              begin() const noexcept;
  const_iterator              end() const noexcept;
  const_iterator              cbegin() const noexcept;
  const_iterator              cend() const noexcept;
  list_iterator               ebegin() noexcept;
  list_iterator               eend() noexcept;
  const_list_iterator         ebegin() const noexcept;
  const_list_iterator         eend() const noexcept;
  reverse_list_iterator       rebegin() noexcept;
  reverse_list_iterator       reend() noexcept;
  const_reverse_list_iterator rebegin() const noexcept;
  const_reverse_list_iterator reend() const noexcept;
  const_list_iterator         cebegin() const noexcept;
  const_list_iterator         ceend() const noexcept;
  const_reverse_list_iterator crebegin() const noexcept;
  const_reverse_list_iterator creend() const noexcept;
  list_iterator               dbegin() noexcept;
  list_iterator               dend() noexcept;
  const_list_iterator         dbegin() const noexcept;
  const_list_iterator         dend() const noexcept;
  reverse_list_iterator       rdbegin() noexcept;
  reverse_list_iterator       rdend() noexcept;
  const_reverse_list_iterator rdbegin() const noexcept;
  const_reverse_list_iterator rdend() const noexcept;
  const_list_iterator         cdbegin() const noexcept;
  const_list_iterator         cdend() const noexcept;
  const_reverse_list_iterator crdbegin() const noexcept;
  const_reverse_list_iterator crdend() const noexcept;

  // comparison
  bool operator==(const hook_chain& other) const noexcept;
  bool operator!=(const hook_chain& other) const noexcept;
};
 </code>
</pre>
<!-- markdownlint-enable MD037 -->
## Constructors

### default constructor

#### Description

Constructs an empty hook_chain, i.e. a target-less instance with the two lists being empty.

#### Notes

It is considered uninitialized as it's left without a target so don't attempt to do any operations to the container before setting the target.

### copy constructor

#### Description

Constructs a copy of `other`. That copy consists of all of the hooks from `other` in the same order with the same properties (i.e. detour & original callback) and the same target.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| other | const hook_chain& | the instance to copy |

#### Exceptions

- [Trampoline Copy Exceptions](exception_groups.md#trampoline-copy-exceptions)

#### Notes

The new instance has put all of the hooks that were copied in the disabled list. Therefore their order is maintained but they are all left as disabled. You need to manually enable them afterward.

### move constructor

#### Description

Constructs a new instance that claims ownership of all of the properties of the `other` instance. These properties include the trampoline, the target and all of the hooks in the same order with the same status left untouched.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| other | hook_chain&& | the instance to move |

#### Notes

The `other` instance remains uninitialized which means target-less and without hooks in the lists. If you are planning on reusing it you should first set the target.

### hook_chain(std::byte* target, dtr&& detour, orig& original, types&&... rest)

#### Description

Constructs a new instance using the target and the list of detour-original pairs specified. This overload requires that all arguments are passed 'as is' and not grouped into pair-like objects. The new hooks are added in the same order as specified in the argument list.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| target | std::byte* | the target to use |
| detour | dtr&& (forwarding reference, any) | the first detour to add to the chain |
| original | orig& (any) | the first reference to the original callback to add to the chain |
| rest | types&& (variadic args, forwarding reference) | the rest of the arguments to construct hooks with |

#### Exceptions

- [Trampoline Initialization Exceptions](exception_groups.md#trampoline-initialization-exceptions)
- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)

#### Notes

After construction, the hooks are always enabled immediately. If you wish to enable them later then proceed to construct the chain using just the target and insert them to the disabled list.

### hook_chain(trg&& target, dtr&& detour, orig& original, types&&... rest)

#### Description

Constructs a new instance using the target and the list of detour-original pairs specified. This overload requires that all arguments are passed 'as is' and not grouped into pair-like objects. The new hooks are added in the same order as specified in the argument list.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| target | trg&& (forwarding reference, any) | the target to use |
| detour | dtr&& (forwarding reference, any) | the first detour to add to the chain |
| original | orig& (any) | the first reference to the original callback to add to the chain |
| rest | types&& (variadic args, forwarding reference) | the rest of the arguments to construct hooks with |

#### Exceptions

- [Trampoline Initialization Exceptions](exception_groups.md#trampoline-initialization-exceptions)
- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)

#### Notes

After construction, the hooks are always enabled immediately. If you wish to enable them later then proceed to construct the chain using just the target and insert them to the disabled list.

### hook_chain(std::byte* target, pair&& first, types&&... rest)

#### Description

Constructs a new instance using the target and the list of detour-original pairs specified. This overload requires that all arguments (apart from the target) are grouped in pair-like objects such as `std::pair`. The new hooks are added in the same order as specified in the argument list.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| target | std::byte* | the target to use |
| first | pair&& (forwarding reference, any) | the first pair of detour-original to add to the chain |
| rest | types&& (variadic args, forwarding reference) | the rest of the detour-original pairs to construct hooks with |

#### Exceptions

- [Trampoline Initialization Exceptions](exception_groups.md#trampoline-initialization-exceptions)
- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)

#### Notes

After construction, the hooks are always enabled immediately. If you wish to enable them later then proceed to construct the chain using just the target and insert them to the disabled list.

### hook_chain(trg&& target, pair&& first, types&&... rest)

#### Description

Constructs a new instance using the target and the list of detour-original pairs specified. This overload requires that all arguments (apart from the target) are grouped in pair-like objects such as `std::pair`. The new hooks are added in the same order as specified in the argument list.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| target | trg&& (forwarding reference, any) | the target to use |
| first | pair&& (forwarding reference, any) | the first pair of detour-original to add to the chain |
| rest | types&& (variadic args, forwarding reference) | the rest of the detour-original pairs to construct hooks with |

#### Exceptions

- [Trampoline Initialization Exceptions](exception_groups.md#trampoline-initialization-exceptions)
- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)

#### Notes

After construction, the hooks are always enabled immediately. If you wish to enable them later then proceed to construct the chain using just the target and insert them to the disabled list.

### hook_chain(std::byte* target)

#### Description

Constructs a new instance using the target specified.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| target | std::byte* | the target to use |

#### Exceptions

- [Trampoline Initialization Exceptions](exception_groups.md#trampoline-initialization-exceptions)

### hook_chain(trg&& target)

#### Description

Constructs a new instance using the target specified.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| target | trg&& (forwarding reference, any) | the target to use |

#### Exceptions

- [Trampoline Initialization Exceptions](exception_groups.md#trampoline-initialization-exceptions)

### hook_chain(const alterhook::hook& other, orig& original)

#### Description

Constructs a new instance with the first hook added to the chain being a copy of the `other` instance including the reference to the original callback specified. It uses the same target as the one the `other` holds.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| other | const alterhook::hook& | the hook instance to copy from |
| original | orig& (any) | the reference to the original callback to set in the first hook |

#### Exceptions

- [Trampoline Copy Exceptions](exception_groups.md#trampoline-copy-exceptions)

#### Notes

The first hook is added to the disabled list meaning it will stay disabled after construction. You can enable it afterward using the API.

### hook_chain(alterhook::hook&& other)

#### Description

Constructs a new instance with the first hook claiming ownership of the contents of the `other` instance. It uses the same target as `other` does and the first hook it adds uses its detour and reference to the original callback.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| other | alterhook::hook&& | the hook instance to move from |

#### Notes

The `other` instance is left uninitialized (i.e. no target/detour/original) after construction and the chain is now responsible for taking ownership of its properties. Also, note that the status of the hook doesn't change meaning it will be added to the enabled or disabled list according to its status.

### hook_chain(const trampoline& other)

#### Description

Constructs a new instance with a copy of the trampoline specified.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| other | const trampoline& | the trampoline to copy from |

#### Exceptions

- [Trampoline Copy Exceptions](exception_groups.md#trampoline-copy-exceptions)

### hook_chain(trampoline&& other)

#### Description

Constructs a new instance by claiming ownership of the trampoline specified by `other`.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| other | trampoline&& | the trampoline to move from |

#### Notes

After construction, the `other` trampoline instance is left uninitialized while the hook chain uses its target and maintains the buffer.
