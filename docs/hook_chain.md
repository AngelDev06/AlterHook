# Hook Chain

A class that represents a chain of hooks. It allows a target to be hooked more than once and makes sure that each hook in the chain can change status without affecting the rest of the hooks. It offers features such as splicing, iteration, swapping, insertion, and deletion both inside the same instance and across instances. Under the hood, it maintains two linked lists, one for the disabled hooks and one for the enabled ones. Each time a hook changes status it gets spliced from the one list to the other and all the operations mentioned might as well be performed on one of the two lists individually. Before reading about the modifiers though it is recommended that you read [iteration](#iteration) since their documentation uses some specific terms a lot.

## Synopsis
<!-- markdownlint-disable MD037 -->
<pre>
 <code>
class hook_chain : trampoline
{
public:
  // member types
  class <a href="hook.hook_chain.md">hook</a>;
  class <a href="iterators.hook_chain.md">const_iterator</a>;
  class <a href="iterators.hook_chain.md">iterator</a>;
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

  hook_chain& <a href="#copy-assignment-operator">operator=</a>(const hook_chain& other);
  hook_chain& <a href="#move-assignment-operator">operator=</a>(hook_chain&& other) noexcept;
  hook_chain& <a href="#operatorconst-trampoline-other">operator=</a>(const trampoline& other);
  hook_chain& <a href="#operatortrampoline-other">operator=</a>(trampoline&& other);

  // state update
  void <a href="#enable_all">enable_all</a>();
  void <a href="#disable_all">disable_all</a>();

  // container modifiers
  void          <a href="#clear">clear</a>(include trg = include::both);
  void          <a href="#pop_back">pop_back</a>(include trg = include::both);
  void          <a href="#pop_front">pop_front</a>(include trg = include::both);
  list_iterator <a href="#eraselist_iterator-position">erase</a>(list_iterator position);
  list_iterator <a href="#eraselist_iterator-first-list_iterator-last">erase</a>(list_iterator first, list_iterator last);
  iterator      <a href="#eraseiterator-position">erase</a>(iterator position);
  iterator      <a href="#eraseiterator-first-iterator-last">erase</a>(iterator first, iterator last);

  template &lt;typename dtr, typename orig, typename... types&gt;
  void <a href="#appendtransfer-to-dtr-detour-orig-original-types-rest">append</a>(transfer to, dtr&& detour, orig& original, types&&... rest);

  template &lt;typename dtr, typename orig, typename... types&gt;
  void <a href="#appenddtr-detour-orig-original-types-rest">append</a>(dtr&& detour, orig& original, types&&... rest);

  template &lt;typename pair, typename... types&gt;
  void <a href="#appendtransfer-to-pair-first-types-rest">append</a>(transfer to, pair&& first, types&&... rest);

  template &lt;typename pair, typename... types&gt;
  void <a href="#appendpair-first-types-rest">append</a>(pair&& first, types&&... rest);

  template &lt;typename dtr, typename orig&gt;
  void <a href="#push_back">push_back</a>(dtr&& detour, orig& original, bool enable_hook = true);

  template &lt;typename dtr, typename orig&gt;
  void <a href="#push_front">push_front</a>(dtr&& detour, orig& original, bool enable_hook = true);

  template &lt;typename dtr, typename orig&gt;
  hook& <a href="#insertlist_iterator-position-dtr-detour-orig-original-include-trg--includeenabled">insert</a>(list_iterator position, dtr&& detour, orig& original,
                include trg = include::enabled);

  template &lt;typename dtr, typename orig&gt;
  hook& <a href="#insertiterator-position-dtr-detour-orig-original">insert</a>(iterator position, dtr&& detour, orig& original);

  void <a href="#swaplist_iterator-left-hook_chain-other-list_iterator-right">swap</a>(list_iterator left, hook_chain& other, list_iterator right);

  void <a href="#swaplist_iterator-left-list_iterator-right">swap</a>(list_iterator left, list_iterator right);

  void <a href="#swaphook_chain-other">swap</a>(hook_chain& other);
  void <a href="#mergehook_chain-other-bool-at_back--true">merge</a>(hook_chain& other, bool at_back = true);

  void <a href="#mergehook_chain-other-bool-at_back--true-1">merge</a>(hook_chain&& other, bool at_back = true);

  void <a href="#splicelist_iterator-newpos-hook_chain-other-transfer-to-transfer-from--transferboth">splice</a>(list_iterator newpos, hook_chain& other, transfer to,
            transfer from = transfer::both);

  void <a href="#splicelist_iterator-newpos-hook_chain-other-transfer-to-transfer-from--transferboth-1">splice</a>(list_iterator newpos, hook_chain&& other, transfer to,
              transfer from = transfer::both);

  void <a href="#spliceiterator-newpos-hook_chain-other-transfer-from--transferboth">splice</a>(iterator newpos, hook_chain& other,
              transfer from = transfer::both);

  void <a href="#splicelist_iterator-newpos-hook_chain-other-transfer-to-transfer-from--transferboth-1">splice</a>(iterator newpos, hook_chain&& other,
              transfer from = transfer::both);

  void <a href="#splicelist_iterator-newpos-hook_chain-other-list_iterator-oldpos-transfer-to">splice</a>(list_iterator newpos, hook_chain& other, list_iterator oldpos,
              transfer to);

  void <a href="#splicelist_iterator-newpos-hook_chain-other-list_iterator-oldpos-transfer-to-1">splice</a>(list_iterator newpos, hook_chain&& other, list_iterator oldpos,
              transfer to);

  void <a href="#spliceiterator-newpos-hook_chain-other-list_iterator-oldpos">splice</a>(iterator newpos, hook_chain& other, list_iterator oldpos);

  void <a href="#spliceiterator-newpos-hook_chain-other-list_iterator-oldpos-1">splice</a>(iterator newpos, hook_chain&& other, list_iterator oldpos);

  void <a href="#splicelist_iterator-newpos-hook_chain-other-list_iterator-first-list_iterator-last-transfer-to">splice</a>(list_iterator newpos, hook_chain& other, list_iterator first,
              list_iterator last, transfer to);

  void <a href="#splicelist_iterator-newpos-hook_chain-other-list_iterator-first-list_iterator-last-transfer-to-1">splice</a>(list_iterator newpos, hook_chain&& other, list_iterator first,
              list_iterator last, transfer to);

  void <a href="#spliceiterator-newpos-hook_chain-other-list_iterator-first-list_iterator-last">splice</a>(iterator newpos, hook_chain& other, list_iterator first,
              list_iterator last);

  void <a href="#spliceiterator-newpos-hook_chain-other-list_iterator-first-list_iterator-last-1">splice</a>(iterator newpos, hook_chain&& other, list_iterator first,
              list_iterator last);

  void <a href="#splicelist_iterator-newpos-hook_chain-other-iterator-first-iterator-last-transfer-to">splice</a>(list_iterator newpos, hook_chain& other, iterator first,
              iterator last, transfer to);

  void <a href="#splicelist_iterator-newpos-hook_chain-other-iterator-first-iterator-last-transfer-to-1">splice</a>(list_iterator newpos, hook_chain&& other, iterator first,
              iterator last, transfer to);

  void <a href="#spliceiterator-newpos-hook_chain-other-iterator-first-iterator-last">splice</a>(iterator newpos, hook_chain& other, iterator first,
              iterator last);

  void <a href="#spliceiterator-newpos-hook_chain-other-iterator-first-iterator-last-1">splice</a>(iterator newpos, hook_chain&& other, iterator first,
              iterator last);

  void <a href="#splicelist_iterator-newpos-list_iterator-oldpos-transfer-to">splice</a>(list_iterator newpos, list_iterator oldpos, transfer to);

  void <a href="#spliceiterator-newpos-list_iterator-oldpos">splice</a>(iterator newpos, list_iterator oldpos);

  void <a href="#splicelist_iterator-newpos-list_iterator-first-list_iterator-last-transfer-to">splice</a>(list_iterator newpos, list_iterator first, list_iterator last,
              transfer to);

  void <a href="#spliceiterator-newpos-list_iterator-first-list_iterator-last">splice</a>(iterator newpos, list_iterator first, list_iterator last);

  void <a href="#splicelist_iterator-newpos-iterator-first-iterator-last-transfer-to">splice</a>(list_iterator newpos, iterator first, iterator last,
              transfer to);

  void <a href="#spliceiterator-newpos-iterator-first-iterator-last">splice</a>(iterator newpos, iterator first, iterator last);

  // element access
  reference       <a href="#operatorsize_t-n">operator[]</a>(size_t n) noexcept;
  const_reference <a href="#operatorsize_t-n-const">operator[]</a>(size_t n) const noexcept;
  reference       <a href="#atsize_t-n">at</a>(size_t n);
  const_reference <a href="#atsize_t-n-const">at</a>(size_t n) const;
  reference       <a href="#front">front</a>() noexcept;
  const_reference <a href="#front-const">front</a>() const noexcept;
  const_reference <a href="#cfront-const">cfront</a>() const noexcept;
  reference       <a href="#efront">efront</a>() noexcept;
  const_reference <a href="#efront-const">efront</a>() const noexcept;
  const_reference <a href="#cefront-const">cefront</a>() const noexcept;
  reference       <a href="#dfront">dfront</a>() noexcept;
  const_reference <a href="#dfront-const">dfront</a>() const noexcept;
  const_reference <a href="#cdfront-const">cdfront</a>() const noexcept;
  reference       <a href="#back">back</a>() noexcept;
  const_reference <a href="#back-const">back</a>() const noexcept;
  const_reference <a href="#cback-const">cback</a>() const noexcept;
  reference       <a href="#eback">eback</a>() noexcept;
  const_reference <a href="#eback-const">eback</a>() const noexcept;
  const_reference <a href="#ceback-const">ceback</a>() const noexcept;
  reference       <a href="#dback">dback</a>() noexcept;
  const_reference <a href="#dback-const">dback</a>() const noexcept;
  const_reference <a href="#cdback-const">cdback</a>() const noexcept;

  // setters
  void <a href="#set_targetstdbyte-target">set_target</a>(std::byte* target);

  template &lt;typename trg&gt;
  void <a href="#set_targettrg-target">set_target</a>(trg&& target);

  // getters
  bool <a href="#empty">empty</a>() const noexcept;

  bool <a href="#empty_enabled">empty_enabled</a>() const noexcept;

  bool <a href="#empty_disabled">empty_disabled</a>() const noexcept;

  explicit <a href="#operator-bool">operator bool</a>() const noexcept;

  size_t <a href="#size">size</a>() const noexcept;

  size_t <a href="#enabled_size">enabled_size</a>() const noexcept;

  size_t <a href="#disabled_size">disabled_size</a>() const noexcept;

  using <a href="trampoline.md#get_target">trampoline::get_target</a>;

  // iterators
  iterator                    <a href="#begin">begin</a>() noexcept;
  iterator                    <a href="#end">end</a>() noexcept;
  const_iterator              <a href="#begin-const">begin</a>() const noexcept;
  const_iterator              <a href="#end-const">end</a>() const noexcept;
  const_iterator              <a href="#cbegin-const">cbegin</a>() const noexcept;
  const_iterator              <a href="#cend-const">cend</a>() const noexcept;
  list_iterator               <a href="#ebegin">ebegin</a>() noexcept;
  list_iterator               <a href="#eend">eend</a>() noexcept;
  const_list_iterator         <a href="#ebegin-const">ebegin</a>() const noexcept;
  const_list_iterator         <a href="#eend-const">eend</a>() const noexcept;
  reverse_list_iterator       <a href="#rebegin">rebegin</a>() noexcept;
  reverse_list_iterator       <a href="#reend">reend</a>() noexcept;
  const_reverse_list_iterator <a href="#rebegin-const">rebegin</a>() const noexcept;
  const_reverse_list_iterator <a href="#reend-const">reend</a>() const noexcept;
  const_list_iterator         <a href="#cebegin-const">cebegin</a>() const noexcept;
  const_list_iterator         <a href="#ceend-const">ceend</a>() const noexcept;
  const_reverse_list_iterator <a href="#crebegin-const">crebegin</a>() const noexcept;
  const_reverse_list_iterator <a href="#creend-const">creend</a>() const noexcept;
  list_iterator               <a href="#dbegin">dbegin</a>() noexcept;
  list_iterator               <a href="#dend">dend</a>() noexcept;
  const_list_iterator         <a href="#dbegin-const">dbegin</a>() const noexcept;
  const_list_iterator         <a href="#dend-const">dend</a>() const noexcept;
  reverse_list_iterator       <a href="#rdbegin">rdbegin</a>() noexcept;
  reverse_list_iterator       <a href="#rdend">rdend</a>() noexcept;
  const_reverse_list_iterator <a href="#rdbegin-const">rdbegin</a>() const noexcept;
  const_reverse_list_iterator <a href="#rdend-const">rdend</a>() const noexcept;
  const_list_iterator         <a href="#cdbegin-const">cdbegin</a>() const noexcept;
  const_list_iterator         <a href="#cdend-const">cdend</a>() const noexcept;
  const_reverse_list_iterator <a href="#crdbegin-const">crdbegin</a>() const noexcept;
  const_reverse_list_iterator <a href="#crdend-const">crdend</a>() const noexcept;

  // comparison
  bool <a href="#comparison">operator==</a>(const hook_chain& other) const noexcept;
  bool <a href="#comparison">operator!=</a>(const hook_chain& other) const noexcept;
};
 </code>
</pre>
<!-- markdownlint-enable MD037 -->
## Iteration

As can be told from the amount of iterator getters that this container provides there really isn't just a single way to iterate the contents of the container. As mentioned already the container consists of two lists, one for the enabled hooks and one for the disabled ones. The default iterator offered (which is also a [custom one](iterators.hook_chain.md)) iterates over all the hooks from both lists in the specific order they are placed. This means that at any time it will switch from the enabled to the disabled list and vise versa to eventually cover all elements one by one.

The order in which the elements appear when iterating over the container using the default iterator type is refered to by the documentation as the **<ins>iteration order</ins>**. This order can only change via a few specific modifiers such as the splice methods and the swappers. Operations that are just for changing the state of one or more hooks (such as [enable_all](#enable_all)/[disable_all](#disable_all)) do not affect the iteration order so a hook that is on position 5 will remain at position 5 regardless if it gets transfered from the enabled to the disabled list or vise versa.

Apart from the default iterators there are iterators provided to iterate each list (enabled or disabled) individually! So if you want to iterate for example over all the enabled hooks specifically you can use the `list_iterator`. Underlying the `list_iterator` is just `std::list<hook>::iterator` which gives a better understanding about its purpose. The order in which the elements appear when iterating over one of the two lists using a list iterator is refered to by the documentation as the **<ins>list iteration order</ins>**. This order is entirely based on the order of the hooks in the specific list that is iterated, meaning that when a hook changes state it disappears from the list as it is transferred to the other one. It may also be affected by the modifiers that affect the *iteration order*.

A big difference between the `iterator` and the `list_iterator` is that `iterator` is not a bidirectional iterator, meaning you can't iterate backwards. On the other hand since the `list_iterator` comes from an instance of `std::list` it does allow backwards stepping which explains why typedefs like `reverse_list_iterator` exist but `reverse_iterator` don't.

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

## Assignment Operators

### copy assignment operator

#### Description

Copy assigns all hooks from `other` to `*this` in iteration order leaving them in disabled state (i.e. in the disabled list). It will also copy assign the underlying trampoline of `other` and redirect itself to the new target.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| other | const hook_chain& | the hook_chain to copy assign from |

#### Returns

A reference to `*this` allowing for chain assignments.

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)
- [Trampoline Copy Exceptions](exception_groups.md#trampoline-copy-exceptions)
- [std::bad_alloc](https://en.cppreference.com/w/cpp/memory/new/bad_alloc)

#### Exception Guarantee

**<ins>STRONG:</ins>** The operation yields strong exception guarantee if and only if the following properties are true:

- There was at least one enabled hook in the container and an attempt to disable it failed. When this happens an exception that belongs to either [Target Injection Exceptions](exception_groups.md#target-injection-exceptions) or [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions) will be thrown.
- There were no enabled hooks in the container and an exception of group [Memory Allocation and Address Validation Exceptions](exception_groups.md#memory-allocation-and-address-validation-exceptions) was thrown denoting an error during the copy assignment of the trampoline.

**<ins>BASIC:</ins>** The operation yields basic guarantee for the rest of the possible outcomes which are:

- An exception thrown when copy assigning the trampoline which therefore belongs on the [Trampoline Copy Exceptions](exception_groups.md#trampoline-copy-exceptions) group. If there was at least one hook enabled at the container then the exception can belong to the subgroup [Memory Allocation and Address Validation Exceptions](exception_groups.md#memory-allocation-and-address-validation-exceptions) otherwise an exception of that subgroup would imply strong guarantee.
- If the trampoline assignment operation didn't fail the only thing that can afterward is potential heap allocations done by `std::list` when `other` is of greater size than `*this`. In this case, the container stops copy assigning any further, therefore the hooks that will be left in the container are guaranteed to be at least the size of the container before the assignment plus any extra hooks that were successfully inserted before `std::bad_alloc` was thrown. You can query this information by the size methods.

#### Notes

After the operation is completed, the hooks will all be left in the disabled list and therefore in disabled state and all of the hooks that were previously in the container will have been replaced or erased.

### move assignment operator

#### Description

Claims ownership of all the hooks that `other` contains and erases all the hooks it currently holds, resulting in `other` being left as uninitialized but reusable.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| other | hook_chain&& | the hook_chain to move from |

#### Returns

A reference to `*this` allowing for chain assignments.

#### Notes

The hooks of `other` will remain in the same state they had before the assignment unmodified.

### operator=(const trampoline& other)

#### Description

Copy assigns the underlying trampoline `*this` holds with `other`. Results in the hook chain redirected to the target of `other` as well as all of its hooks.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| other | const trampoline& | the trampoline to copy from |

#### Returns

A reference to `*this` allowing for chain assignments.

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)
- [Trampoline Copy Exceptions](exception_groups.md#trampoline-copy-exceptions)

#### Exception Guarantee

**<ins>STRONG:</ins>** The operation yields strong exception guarantee if and only if the following properties are true:

- There was at least one enabled hook in the container and an attempt to disable it failed. When this happens an exception that belongs to either [Target Injection Exceptions](exception_groups.md#target-injection-exceptions) or [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions) will be thrown.
- There were no enabled hooks in the container and an exception of group [Memory Allocation and Address Validation Exceptions](exception_groups.md#memory-allocation-and-address-validation-exceptions) was thrown denoting an error during the copy assignment of the trampoline.

**<ins>BASIC:</ins>** The operation yields basic guarantee for the rest of the possible outcomes which are:

- An exception thrown when copy assigning the trampoline which therefore belongs on the [Trampoline Copy Exceptions](exception_groups.md#trampoline-copy-exceptions) group. If there was at least one hook enabled at the container then the exception can belong to the subgroup [Memory Allocation and Address Validation Exceptions](exception_groups.md#memory-allocation-and-address-validation-exceptions) otherwise an exception of that subgroup would imply strong guarantee.
- If the trampoline assignment operation didn't fail the only thing that can afterward is the attempt of re-enabling the disabled hooks. If that fails then all hooks will be moved to the disabled list (and therefore will have disabled state) and will maintain the same order as before. So if injecting them back fails an exception will be thrown of either [Target Injection Exceptions](exception_groups.md#target-injection-exceptions) or [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions) group and you can use the [empty_enabled](#empty_enabled) method to determine whether the hooks are left as disabled (and therefore assigning the trampoline succeeded) or are still enabled (which implies that nothing happened and therefore strong guarantee was provided).

#### Notes

If the container has hooks that are already enabled then it will make sure to disable them before assigning the trampoline and re-enable them afterward while also maintaining the same order.

### operator=(trampoline&& other)

#### Description

Claims ownership of the `other` trampoline, redirects its target and erases the currently held trampoline.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| other | trampoline&& | the trampoline to move assign from |

#### Returns

A reference to `*this` allowing for chain assignments.

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)

#### Exception Guarantee

**<ins>STRONG:</ins>** Only provided when an attempt to disable all hooks failed. So you should expect the exception to be either of group [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions) or [Target Injection Exceptions](exception_groups.md#target-injection-exceptions).

**<ins>BASIC:</ins>** When an attempt to re-enable the hooks after they were disabled fails it yields basic exception guarantee. In that case, all hooks are moved to the disabled list (and therefore their state is set to disabled). You can use the api to determine whether all hooks were disabled, otherwise, it means strong guarantee was instead provided.

## Methods

### enable_all

#### Description

Enables all the hooks in the container. Does nothing if the container is empty or all of the hooks are already enabled.

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)

#### Exception Guarantee

**<ins>STRONG:</ins>** Always.

### disable_all

#### Description

Disables all the hooks in the container. Does nothing if the container is empty or all of the hooks are already disabled.

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)

#### Exception Guarantee

**<ins>STRONG:</ins>** Always.

### clear

#### Description

Removes one of the two lists or both (based on the parameter) from the container. Enabled hooks are always disabled before removal.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| trg | include | the target list to clear. defaults to both. |

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)

#### Exception Guarantee

**<ins>STRONG:</ins>** Always.

### pop_back

#### Description

Removes the last hook of one of the two lists or both (based on the parameter) from the container. The enabled hook is always disabled before removal.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| trg | include | the target list to remove its last hook. defaults to both. |

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)

#### Exception Guarantee

**<ins>STRONG:</ins>** Always.

### pop_front

#### Description

Removes the first hook of one of the two lists or both (based on the parameter) from the container. The enabled hook is always disabled before removal.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| trg | include | the target list to remove its first hook. defaults to both. |

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)

#### Exception Guarantee

**<ins>STRONG:</ins>** Always.

### erase(list_iterator position)

#### Description

Erases the hook at `position` from the container. If enabled it also makes sure to disable it before removal.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| position | list_iterator | the list iterator to the hook to be erased |

#### Returns

A `list_iterator` to the hook after the one erased in list iteration order. This means that the iterator may not necessarily point to the next hook in the order you iterate through the use of `iterator`.

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)

#### Exception Guarantee

**<ins>STRONG:</ins>** Always.

### erase(list_iterator first, list_iterator last)

#### Description

Erases all the hooks in the range [first, last). If the range consists of enabled hooks it makes sure to disable them first.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| first | list_iterator | the list iterator to the first hook in the range |
| last | list_iterator | the list iterator to the hook after the last one in the range |

#### Returns

Returns `last`.

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)

#### Exception Guarantee

**<ins>STRONG:</ins>** Always.

#### Notes

The range specified should be a valid range for *list iteration*. This means that this range is not iterated the way you would iterate using an `iterator` but rather a `list_iterator`. Therefore both `first` and `last` must refer to the same underlying list.

### erase(iterator position)

#### Description

Erases the hook at `position`. If it's enabled it will be disabled before removal.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| position | iterator | the iterator to the hook to be erased |

#### Returns

An `iterator` to the hook after the one erased in *iteration order*. This means that the next hook will be the one you would get via iterating using an `iterator`.

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)

#### Exception Guarantee

**<ins>STRONG:</ins>** Always.

### erase(iterator first, iterator last)

#### Description

Erases all the hooks in the range [first, last). If there are any enabled hooks in the range it makes sure to disable them first.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| first | iterator | the iterator to the first hook in the range |
| last | iterator | the iterator to the hook after the last one in the range |

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)

#### Exception Guarantee

**<ins>BASIC:</ins>** If an exception occurred it's because an attempt to disable the enabled hooks in the range failed. When that happens it's guaranteed that all the disabled hooks in the range will have been erased successfully and the enabled ones will remain unmodified.

#### Notes

The range erased should be in *iterator order*. That means that the hooks that are part of the range are the ones retrieved by iterating using an `iterator`. Therefore the range can consist of both enabled and disabled hooks.

### append(transfer to, dtr&& detour, orig& original, types&&... rest)

#### Description

Inserts a list of detour-original pairs specified *as is* at the end of the list specified by `to`. If the list is the enabled one then the new hooks will also be enabled.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| to | transfer | the list to insert the new hooks to |
| detour | dtr&& (forwarding reference, any) | the detour of the first hook to be inserted |
| original | orig& (any) | the reference to the original callback of the first hook to be inserted |
| rest | types&& (forwarding reference, variadic args) | the rest of the detour-original pairs to insert new hooks with |

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)
- [std::bad_alloc](https://en.cppreference.com/w/cpp/memory/new/bad_alloc)

#### Exception Guarantee

**<ins>STRONG:</ins>** Always.

### append(dtr&& detour, orig& original, types&&... rest)

#### Description

Inserts a list of detour-original pairs specified *as is* at the end of the enabled list, therefore enabling them as well.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| detour | dtr&& (forwarding reference, any) | the detour of the first hook to be inserted |
| original | orig& (any) | the reference to the original callback of the first hook to be inserted |
| rest | types&& (forwarding reference, variadic args) | the rest of the detour-original pairs to insert new hooks with |

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)
- [std::bad_alloc](https://en.cppreference.com/w/cpp/memory/new/bad_alloc)

#### Exception Guarantee

**<ins>STRONG:</ins>** Always.

### append(transfer to, pair&& first, types&&... rest)

#### Description

Inserts a list of detour-original pairs grouped into [pair-like objects](https://en.cppreference.com/w/cpp/utility/tuple/tuple-like) at the end of the list specified by `to`. If `to` refers to the enabled list it also makes sure to enable the inserted hooks.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| to | transfer | the list to insert the hooks to |
| first | pair&& (forwarding reference, any) | the first detour-original pair to insert a hook with |
| rest | types&& (forwarding reference, variadic args) | the rest of the detour-original pairs to insert hooks with |

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)
- [std::bad_alloc](https://en.cppreference.com/w/cpp/memory/new/bad_alloc)

#### Exception Guarantee

**<ins>STRONG:</ins>** Always.

### append(pair&& first, types&&... rest)

#### Description

Inserts a list of detour-original pairs grouped into [pair-like objects](https://en.cppreference.com/w/cpp/utility/tuple/tuple-like) at the end of the enabled list, therefore enabling the hooks too.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| first | pair&& (forwarding reference, any) | the first detour-original pair to insert a hook with |
| rest | types&& (forwarding reference, variadic args) | the rest of the detour-original pairs to insert hooks with |

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)
- [std::bad_alloc](https://en.cppreference.com/w/cpp/memory/new/bad_alloc)

#### Exception Guarantee

**<ins>STRONG:</ins>** Always.

### push_back

#### Description

Inserts a new hook at the end of the list determined by `enable_hook` which also determines whether to enable the hook or not.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| detour | dtr&& (forwarding reference, any) | the detour of the hook to insert |
| original | orig& (any) | the reference to the original callback of the hook to insert |
| enable_hook | bool | whether to insert the hook in the enabled list or not. defaults to true |

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)
- [std::bad_alloc](https://en.cppreference.com/w/cpp/memory/new/bad_alloc)

#### Exception Guarantee

**<ins>STRONG:</ins>** Always.

### push_front

#### Description

Inserts a new hook at the beginning of the list determined by `enable_hook` which also determines whether to enable the hook or not.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| detour | dtr&& (forwarding reference, any) | the detour of the hook to insert |
| original | orig& (any) | the reference to the original callback of the hook to insert |
| enable_hook | bool | whether to insert the hook in the enabled list or not. defaults to true |

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)
- [std::bad_alloc](https://en.cppreference.com/w/cpp/memory/new/bad_alloc)

#### Exception Guarantee

**<ins>STRONG:</ins>** Always.

### insert(list_iterator position, dtr&& detour, orig& original, include trg = include::enabled)

#### Description

Inserts a new hook before `position` which is a `list_iterator` to the list specified by `trg`.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| position | list_iterator | the list iterator to the hook before which a new one will be inserted |
| detour | dtr&& (forwarding reference, any) | the detour of the hook to insert |
| original | orig& (any) | the reference to the original callback of the hook to insert |
| trg | include | The list that `position` points to. Cannot be the both flag |

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)
- [std::bad_alloc](https://en.cppreference.com/w/cpp/memory/new/bad_alloc)

#### Exception Guarantee

**<ins>STRONG:</ins>** Always.

### insert(iterator position, dtr&& detour, orig& original)

#### Description

Inserts a new hook before `position`.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| position | iterator | the iterator to the hook before which a new one will be inserted |
| detour | dtr&& (forwarding reference, any) | the detour of the hook to insert |
| original | orig& (any) | the reference to the original callback of the hook to insert |

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)
- [std::bad_alloc](https://en.cppreference.com/w/cpp/memory/new/bad_alloc)

#### Exception Guarantee

**<ins>STRONG:</ins>** Always.

### swap(list_iterator left, hook_chain& other, list_iterator right)

#### Description

Swaps the hook pointed to by `left` and belongs to `*this` with that pointed to by `right` and belongs to `other`. `other` can also be `*this` in which case the function will simply swap two hooks of the same container.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| left | list_iterator | a list iterator to the hook that belongs to `*this` and is going to be swapped |
| other | hook_chain& | a reference to the chain that `right` belongs to. it can also be `*this` |
| right | list_iterator | a list iterator to the hook that belongs to `other` and is going to be swapped |

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)

#### Exception Guarantee

**<ins>STRONG:<ins>** Provided only when one of the following properties is true:

- The exception thrown belongs to the group [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions).
- Only one of the two is enabled and an exception of group [Target Injection Exceptions](exception_groups.md#target-injection-exceptions) is thrown.
- Both hooks are enabled but in an attempt to inject the first one into the new location an exception of group [Target Injection Exceptions](exception_groups.md#target-injection-exceptions) is thrown.
- Both hooks are enabled but after the first one was already injected, the second one failed to be injected to the new location. In that case, the function tries to inject the first one back to its previous location and if that succeeds strong guarantee is provided.

**<ins>NONE:</ins>** It can only ever happen if both hooks are enabled, one of them gets injected to the new location successfully, the other one fails to be injected and an attempt to inject the first one back to its previous location has also failed. In that case, a nested exception is thrown that consists of the exception thrown by the injection of the second hook and the exception of the failed attempt to inject the first one back. At this point, the operation corrupted both `*this` and `other` and is not fixable. You can tell whether this happened (i.e. whether the attempt to inject the first hook back has failed) by checking whether the exception received is a nested exception. It is recommended that you use the [std::rethrow_if_nested](https://en.cppreference.com/w/cpp/error/rethrow_if_nested) standard function and let the program terminate if the guarantee provided is none.

#### Notes

`left` and `right` can be of the same state (i.e. both enabled or both disabled) or of a different one. If they are of a different state then states are also swapped in this case, which means that one gets enabled and the other gets disabled.

### swap(list_iterator left, list_iterator right)

#### Description

Swaps the hook pointed to by `left` with the one pointed to by `right`. Both `left` and `right` should be valid list iterators to `*this`.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| left | list_iterator | a list iterator to the first hook to be swapped |
| right | list_iterator | a list iterator to the second hook to be swapped |

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)

#### Exception Guarantee

**<ins>STRONG:<ins>** Always.

#### Notes

`left` and `right` can be of the same state (i.e. both enabled or both disabled) or of a different one. If they are of a different state then states are also swapped in this case, which means that one gets enabled and the other gets disabled.

### swap(hook_chain& other)

#### Description

Swaps all the hooks of `*this` with those of `other`. Does nothing if `*this` and `other` refer to the same container.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| other | hook_chain& | the chain to swap the current one with |

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)

#### Exception Guarantee

**<ins>STRONG:<ins>** Provided only when one of the following properties is true:

- The exception thrown belongs to the group [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions).
- Only one of the two chains has enabled hooks and an exception of group [Target Injection Exceptions](exception_groups.md#target-injection-exceptions) is thrown.
- Both chains have enabled hooks but in an attempt to inject the hooks of one of them into the new location an exception of group [Target Injection Exceptions](exception_groups.md#target-injection-exceptions) is thrown.
- Both chains have enabled hooks but after the first one's hooks were already injected, the second one's failed to be injected into the new location. In that case, the function tries to inject the first chains' hooks back into their previous location and if that succeeds strong guarantee is provided.

**<ins>NONE:</ins>** It can only ever happen if both chains have enabled hooks, one of them has its hooks injected successfully to the new location, the other's ones fail to be injected and an attempt to inject the hooks of the first one back to their previous location has also failed. In that case, a nested exception is thrown that consists of the exception thrown by the injection of the second chain's hooks and the exception of the failed attempt to inject the first one's hooks back. At this point, the operation corrupted both `*this` and `other` and is not fixable. You can tell whether this happened (i.e. whether the attempt to inject the first hook back has failed) by checking whether the exception received is a nested exception. It is recommended that you use the [std::rethrow_if_nested](https://en.cppreference.com/w/cpp/error/rethrow_if_nested) standard function and let the program terminate if the guarantee provided is none.

### merge(hook_chain& other, bool at_back = true)

#### Description

Merges `other` with `*this` resulting in a new chain that consists of the hooks of both with the target and trampoline of `*this`. `other` is left empty after the operation and its hooks are placed depending on the value of `at_back`, either at the end of the hook chain of `*this` or at the beginning.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| other | hook_chain& | the chain to merge with `*this` |
| at_back | bool | whether to place the hooks of `other` at the beginning or at the end of `*this`, defaults to true |

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)

#### Exception Guarantee

**<ins>STRONG:</ins>** Provided when an attempt to uninject the hooks from `other` fails, or when the attempt to inject the hooks of `other` to the new location fails but reverting the operation succeeds (i.e. injecting them back successfully). Or when `other` has no enabled hooks and therefore no exception will be thrown at all.

**<ins>BASIC:</ins>** Provided when the hooks of `other` were removed successfully but failed to be injected into the new location and at the same time an attempt of reverting the operation also failed. When that happens, all the hooks of `other` are not transferred to `*this` and remain disabled regardless of the state they had before. Order however is maintained. You can determine whether basic guarantee was provided by whether the exception thrown was a nested exception in which case it means the attempt to provide strong guarantee failed as well. It is recommended that you use the standard function [std::rethrow_if_nested](https://en.cppreference.com/w/cpp/error/rethrow_if_nested) and optionally handle the situation when the guarantee provided is basic.

### merge(hook_chain&& other, bool at_back = true)

#### Description

Merges `other` with `*this` resulting in a new chain that consists of the hooks of both with the target and trampoline of `*this`. `other` is left empty after the operation and its hooks are placed depending on the value of `at_back`, either at the end of the hook chain of `*this` or at the beginning.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| other | hook_chain&& | the chain to merge with `*this` |
| at_back | bool | whether to place the hooks of `other` at the beginning or at the end of `*this`, defaults to true |

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)

#### Exception Guarantee

**<ins>STRONG:</ins>** Provided when an attempt to uninject the hooks from `other` fails, or when the attempt to inject the hooks of `other` to the new location fails but reverting the operation succeeds (i.e. injecting them back successfully). Or when `other` has no enabled hooks and therefore no exception will be thrown at all.

**<ins>BASIC:</ins>** Provided when the hooks of `other` were removed successfully but failed to be injected into the new location and at the same time an attempt of reverting the operation also failed. When that happens, all the hooks of `other` are not transferred to `*this` and remain disabled regardless of the state they had before. Order however is maintained. You can determine whether basic guarantee was provided by whether the exception thrown was a nested exception in which case it means the attempt to provide strong guarantee failed as well. It is recommended that you use the standard function [std::rethrow_if_nested](https://en.cppreference.com/w/cpp/error/rethrow_if_nested) and optionally handle the situation when the guarantee provided is basic.

### splice(list_iterator newpos, hook_chain& other, transfer to, transfer from = transfer::both)

#### Description

Places one of the two or both lists of `other` before the position pointed to by `newpos` on `*this`. Which list to transfer is determined by `from` and the list that `newpos` points to is determined by `to`. `other` can also refer to the same container as `*this`.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| newpos | list_iterator | the position before which the enabled hook list pointed to by `from` will be spliced to. Can be the end list iterator |
| other | hook_chain& other | the instance from which the enabled hook list will be spliced. Can also be `*this` |
| to | transfer | Specifies whether `newpos` points to the enabled or the disabled list. Must not be `transfer::both` |
| from | transfer | specifies the list (enabled or disabled) of `other` from which the hooks will be spliced. When set as `both` it splices both lists (i.e. the whole container) |

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)

#### Exception Guarantee

**<ins>STRONG:</ins>** Provided when either of the following properties is true:

- An attempt to remove the enabled hook list from `other` failed.
- An attempt to inject the enabled hook list pointed to by `from` to the new location failed, but reverting the operation succeeded (i.e. successfully linked back the enabled hook list to its previous location).
- `newpos` refers to the enabled list (determined by `to`), `from` refers to the disabled one of other and an attempt to inject the enabled hook list to the new location failed.
- both `newpos` and `from` refer to the respective disabled list in which case no exceptions are thrown at all.

**<ins>BASIC:</ins>** Provided when the enabled hook list pointed to by `from` was removed successfully from `other` but failed to be injected into the new location and at the same time an attempt of reverting the operation also failed. When that happens, the enabled hook list's state becomes disabled and it's therefore transferred to the disabled list while also maintaining order. You can determine whether basic guarantee was provided by whether the exception thrown was a nested exception in which case it means the attempt to provide strong guarantee failed as well. It is recommended that you use the standard function [std::rethrow_if_nested](https://en.cppreference.com/w/cpp/error/rethrow_if_nested) and optionally handle the situation when the guarantee provided is basic.

#### Notes

The following properties should be taken into account:

- The state of the enabled hook list pointed to by `from` may change according to which list `from` refers to (i.e. enabled or disabled).
- The enabled hook list pointed to by `from` is placed right before `newpos` in *list iteration order*. However, the hook currently before `newpos` in *iteration order* (if any) will be linked with the spliced enabled hook list instead.
- If the value of `to` specifies a different list than the one `newpos` points to then the behavior is undefined. Unless `to == transfer::both` in which case you are guaranteed a run-time assertion on debug builds only.
- If `newpos` is either `this->eend()` or `this->dend()` then the enabled hook list pointed to by `from` will be put last in *iteration order* with state based on the list `newpos` refers to just like previously. This is always true regardless of the state of the current last hook in the chain.

### splice(list_iterator newpos, hook_chain&& other, transfer to, transfer from = transfer::both)

#### Description

Places one of the two or both lists of `other` before the position pointed to by `newpos` on `*this`. Which list to transfer is determined by `from` and the list that `newpos` points to is determined by `to`. `other` can also refer to the same container as `*this`.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| newpos | list_iterator | the position before which the enabled hook list pointed to by `from` will be spliced to. Can be the end list iterator |
| other | hook_chain&& other | the instance from which the enabled hook list will be spliced. Can also be `*this` |
| to | transfer | Specifies whether `newpos` points to the enabled or the disabled list. Must not be `transfer::both` |
| from | transfer | specifies the list (enabled or disabled) of `other` from which the hooks will be spliced. When set as `both` it splices both lists (i.e. the whole container) |

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)

#### Exception Guarantee

**<ins>STRONG:</ins>** Provided when either of the following properties is true:

- An attempt to remove the enabled hook list from `other` failed.
- An attempt to inject the enabled hook list pointed to by `from` to the new location failed, but reverting the operation succeeded (i.e. successfully linked back the enabled hook list to its previous location).
- `newpos` refers to the enabled list (determined by `to`), `from` refers to the disabled one of other and an attempt to inject the enabled hook list to the new location failed.
- both `newpos` and `from` refer to the respective disabled list in which case no exceptions are thrown at all.

**<ins>BASIC:</ins>** Provided when the enabled hook list pointed to by `from` was removed successfully from `other` but failed to be injected into the new location and at the same time an attempt of reverting the operation also failed. When that happens, the enabled hook list's state becomes disabled and it's therefore transferred to the disabled list while also maintaining order. You can determine whether basic guarantee was provided by whether the exception thrown was a nested exception in which case it means the attempt to provide strong guarantee failed as well. It is recommended that you use the standard function [std::rethrow_if_nested](https://en.cppreference.com/w/cpp/error/rethrow_if_nested) and optionally handle the situation when the guarantee provided is basic.

#### Notes

The following properties should be taken into account:

- The state of the enabled hook list pointed to by `from` may change according to which list `from` refers to (i.e. enabled or disabled).
- The enabled hook list pointed to by `from` is placed right before `newpos` in *list iteration order*. However, the hook currently before `newpos` in *iteration order* (if any) will be linked with the spliced enabled hook list instead.
- If the value of `to` specifies a different list than the one `newpos` points to then the behavior is undefined. Unless `to == transfer::both` in which case you are guaranteed a run-time assertion on debug builds only.
- If `newpos` is either `this->eend()` or `this->dend()` then the enabled hook list pointed to by `from` will be put last in *iteration order* with state based on the list `newpos` refers to just like previously. This is always true regardless of the state of the current last hook in the chain.

### splice(iterator newpos, hook_chain& other, transfer from = transfer::both)

#### Description

Places one of the two or both lists of `other` before the position pointed to by `newpos` on `*this`. Which list to transfer is determined by `from` and the list that `newpos` points to is determined by `to`. `other` can also refer to the same container as `*this`.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| newpos | iterator | the position before which the enabled hook list pointed to by `from` will be spliced to. Can be the end iterator |
| other | hook_chain& other | the instance from which the enabled hook list will be spliced. Can also be `*this` |
| from | transfer | specifies the list (enabled or disabled) of `other` from which the hooks will be spliced. When set as `both` it splices both lists (i.e. the whole container) |

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)

#### Exception Guarantee

**<ins>STRONG:</ins>** Provided when either of the following properties is true:

- An attempt to remove the enabled hook list from `other` failed.
- An attempt to inject the enabled hook list pointed to by `from` to the new location failed, but reverting the operation succeeded (i.e. successfully linked back the enabled hook list to its previous location).
- `newpos` refers to the enabled list, `from` refers to the disabled one of other and an attempt to inject the enabled hook list to the new location failed.
- both `newpos` and `from` refer to the respective disabled list in which case no exceptions are thrown at all.

**<ins>BASIC:</ins>** Provided when the enabled hook list pointed to by `from` was removed successfully from `other` but failed to be injected into the new location and at the same time an attempt of reverting the operation also failed. When that happens, the enabled hook list's state becomes disabled and it's therefore transferred to the disabled list while also maintaining order. You can determine whether basic guarantee was provided by whether the exception thrown was a nested exception in which case it means the attempt to provide strong guarantee failed as well. It is recommended that you use the standard function [std::rethrow_if_nested](https://en.cppreference.com/w/cpp/error/rethrow_if_nested) and optionally handle the situation when the guarantee provided is basic.

#### Notes

The following properties should be taken into account:

- The state of the enabled hook list pointed to by `from` may change according to which list `from` refers to (i.e. enabled or disabled).
- The enabled hook list pointed to by `from` is placed right before `newpos` in *list iteration order*. However, the hook currently before `newpos` in *iteration order* (if any) will be linked with the spliced enabled hook list instead.

### splice(iterator newpos, hook_chain&& other, transfer from = transfer::both)

#### Description

Places one of the two or both lists of `other` before the position pointed to by `newpos` on `*this`. Which list to transfer is determined by `from` and the list that `newpos` points to is determined by `to`. `other` can also refer to the same container as `*this`.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| newpos | iterator | the position before which the enabled hook list pointed to by `from` will be spliced to. Can be the end iterator |
| other | hook_chain&& other | the instance from which the enabled hook list will be spliced. Can also be `*this` |
| from | transfer | specifies the list (enabled or disabled) of `other` from which the hooks will be spliced. When set as `both` it splices both lists (i.e. the whole container) |

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)

#### Exception Guarantee

**<ins>STRONG:</ins>** Provided when either of the following properties is true:

- An attempt to remove the enabled hook list from `other` failed.
- An attempt to inject the enabled hook list pointed to by `from` to the new location failed, but reverting the operation succeeded (i.e. successfully linked back the enabled hook list to its previous location).
- `newpos` refers to the enabled list, `from` refers to the disabled one of other and an attempt to inject the enabled hook list to the new location failed.
- both `newpos` and `from` refer to the respective disabled list in which case no exceptions are thrown at all.

**<ins>BASIC:</ins>** Provided when the enabled hook list pointed to by `from` was removed successfully from `other` but failed to be injected into the new location and at the same time an attempt of reverting the operation also failed. When that happens, the enabled hook list's state becomes disabled and it's therefore transferred to the disabled list while also maintaining order. You can determine whether basic guarantee was provided by whether the exception thrown was a nested exception in which case it means the attempt to provide strong guarantee failed as well. It is recommended that you use the standard function [std::rethrow_if_nested](https://en.cppreference.com/w/cpp/error/rethrow_if_nested) and optionally handle the situation when the guarantee provided is basic.

#### Notes

The following properties should be taken into account:

- The state of the enabled hook list pointed to by `from` may change according to which list `from` refers to (i.e. enabled or disabled).
- The enabled hook list pointed to by `from` is placed right before `newpos` in *list iteration order*. However, the hook currently before `newpos` in *iteration order* (if any) will be linked with the spliced enabled hook list instead.

### splice(list_iterator newpos, hook_chain& other, list_iterator oldpos, transfer to)

#### Description

Splices a hook from `other` pointed to by `oldpos` to `newpos`. If `newpos` points to an existing element then the hook is placed right before that in *list iteration order*.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| newpos | list_iterator | the position before which the hook pointed to by `oldpos` will be spliced to. Can be the end list iterator |
| other | hook_chain& other | the instance from which the hook will be spliced. Can also be `*this` |
| oldpos | list_iterator | the list iterator to the hook that is going to be spliced |
| to | transfer | Specifies whether `newpos` points to the enabled or the disabled list. Must not be `transfer::both` |

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)

#### Exception Guarantee

**<ins>STRONG:</ins>** Provided when either of the following properties is true:

- An attempt to remove the hook from `other` failed.
- An attempt to inject the hook pointed to by `oldpos` to the new location failed, but reverting the operation succeeded (i.e. successfully linked back the hook to its previous location).
- `newpos` refers to the enabled list (determined by `to`), `oldpos` refers to the disabled one of other and an attempt to inject the hook to the new location failed.
- both `newpos` and `oldpos` refer to the respective disabled list in which case no exceptions are thrown at all.

**<ins>BASIC:</ins>** Provided when the hook pointed to by `oldpos` was removed successfully from `other` but failed to be injected into the new location and at the same time an attempt of reverting the operation also failed. When that happens, the hook's state becomes disabled and it's therefore transferred to the disabled list while also maintaining order. You can determine whether basic guarantee was provided by whether the exception thrown was a nested exception in which case it means the attempt to provide strong guarantee failed as well. It is recommended that you use the standard function [std::rethrow_if_nested](https://en.cppreference.com/w/cpp/error/rethrow_if_nested) and optionally handle the situation when the guarantee provided is basic.

#### Notes

The following properties should be taken into account:

- The state of the hook pointed to by `oldpos` may change according to which list `oldpos` refers to (i.e. enabled or disabled).
- The hook pointed to by `oldpos` is placed right before `newpos` in *list iteration order*. However, the hook currently before `newpos` in *iteration order* (if any) will be linked with the spliced hook instead.
- If the value of `to` specifies a different list than the one `newpos` points to then the behavior is undefined. Unless `to == transfer::both` in which case you are guaranteed a run-time assertion on debug builds only.
- If `newpos` is either `this->eend()` or `this->dend()` then the hook pointed to by `oldpos` will be put last in *iteration order* with state based on the list `newpos` refers to just like previously. This is always true regardless of the state of the current last hook in the chain.

### splice(list_iterator newpos, hook_chain&& other, list_iterator oldpos, transfer to)

#### Description

Splices a hook from `other` pointed to by `oldpos` to `newpos`. If `newpos` points to an existing element then the hook is placed right before that in *list iteration order*.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| newpos | list_iterator | the position before which the hook pointed to by `oldpos` will be spliced to. Can be the end list iterator |
| other | hook_chain&& other | the instance from which the hook will be spliced. Can also be `*this` |
| oldpos | list_iterator | the list iterator to the hook that is going to be spliced |
| to | transfer | Specifies whether `newpos` points to the enabled or the disabled list. Must not be `transfer::both` |

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)

#### Exception Guarantee

**<ins>STRONG:</ins>** Provided when either of the following properties is true:

- An attempt to remove the hook from `other` failed.
- An attempt to inject the hook pointed to by `oldpos` to the new location failed, but reverting the operation succeeded (i.e. successfully linked back the hook to its previous location).
- `newpos` refers to the enabled list (determined by `to`), `oldpos` refers to the disabled one of other and an attempt to inject the hook to the new location failed.
- both `newpos` and `oldpos` refer to the respective disabled list in which case no exceptions are thrown at all.

**<ins>BASIC:</ins>** Provided when the hook pointed to by `oldpos` was removed successfully from `other` but failed to be injected into the new location and at the same time an attempt of reverting the operation also failed. When that happens, the hook's state becomes disabled and it's therefore transferred to the disabled list while also maintaining order. You can determine whether basic guarantee was provided by whether the exception thrown was a nested exception in which case it means the attempt to provide strong guarantee failed as well. It is recommended that you use the standard function [std::rethrow_if_nested](https://en.cppreference.com/w/cpp/error/rethrow_if_nested) and optionally handle the situation when the guarantee provided is basic.

#### Notes

The following properties should be taken into account:

- The state of the hook pointed to by `oldpos` may change according to which list `oldpos` refers to (i.e. enabled or disabled).
- The hook pointed to by `oldpos` is placed right before `newpos` in *list iteration order*. However, the hook currently before `newpos` in *iteration order* (if any) will be linked with the spliced hook instead.
- If the value of `to` specifies a different list than the one `newpos` points to then the behavior is undefined. Unless `to == transfer::both` in which case you are guaranteed a run-time assertion on debug builds only.
- If `newpos` is either `this->eend()` or `this->dend()` then the hook pointed to by `oldpos` will be put last in *iteration order* with state based on the list `newpos` refers to just like previously. This is always true regardless of the state of the current last hook in the chain.

### splice(list_iterator newpos, list_iterator oldpos, transfer to)

#### Description

Splices a hook pointed to by `oldpos` to `newpos`. If `newpos` points to an existing element then the hook is placed right before that in *list iteration order*.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| newpos | list_iterator | the position before which the hook pointed to by `oldpos` will be spliced to. Can be the end list iterator |
| oldpos | list_iterator | the list iterator to the hook that is going to be spliced |
| to | transfer | Specifies whether `newpos` points to the enabled or the disabled list. Must not be `transfer::both` |

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)

#### Exception Guarantee

**<ins>STRONG:</ins>** Provided when either of the following properties is true:

- An attempt to remove the hook failed.
- An attempt to inject the hook pointed to by `oldpos` to the new location failed, but reverting the operation succeeded (i.e. successfully linked back the hook to its previous location).
- `newpos` refers to the enabled list (determined by `to`), `oldpos` refers to the disabled one and an attempt to inject the hook to the new location failed.
- both `newpos` and `oldpos` refer to the respective disabled list in which case no exceptions are thrown at all.

**<ins>BASIC:</ins>** Provided when the hook pointed to by `oldpos` was removed successfully but failed to be injected into the new location and at the same time an attempt of reverting the operation also failed. When that happens, the hook's state becomes disabled and it's therefore transferred to the disabled list while also maintaining order. You can determine whether basic guarantee was provided by whether the exception thrown was a nested exception in which case it means the attempt to provide strong guarantee failed as well. It is recommended that you use the standard function [std::rethrow_if_nested](https://en.cppreference.com/w/cpp/error/rethrow_if_nested) and optionally handle the situation when the guarantee provided is basic.

#### Notes

The following properties should be taken into account:

- The state of the hook pointed to by `oldpos` may change according to which list `oldpos` refers to (i.e. enabled or disabled).
- The hook pointed to by `oldpos` is placed right before `newpos` in *list iteration order*. However, the hook currently before `newpos` in *iteration order* (if any) will be linked with the spliced hook instead.
- If the value of `to` specifies a different list than the one `newpos` points to then the behavior is undefined. Unless `to == transfer::both` in which case you are guaranteed a run-time assertion on debug builds only.
- If `newpos` is either `this->eend()` or `this->dend()` then the hook pointed to by `oldpos` will be put last in *iteration order* with state based on the list `newpos` refers to just like previously. This is always true regardless of the state of the current last hook in the chain.

### splice(iterator newpos, hook_chain& other, list_iterator oldpos)

#### Description

Splices a hook from `other` pointed to by `oldpos` to `newpos`. If `newpos` points to an existing element then the hook is placed right before that in *list iteration order*.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| newpos | iterator | the position before which the hook pointed to by `oldpos` will be spliced to. Can be the end iterator |
| other | hook_chain& other | the instance from which the hook will be spliced. Can also be `*this` |
| oldpos | list_iterator | the list iterator to the hook that is going to be spliced |

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)

#### Exception Guarantee

**<ins>STRONG:</ins>** Provided when either of the following properties is true:

- An attempt to remove the hook from `other` failed.
- An attempt to inject the hook pointed to by `oldpos` to the new location failed, but reverting the operation succeeded (i.e. successfully linked back the hook to its previous location).
- `newpos` refers to the enabled list, `oldpos` refers to the disabled one of other and an attempt to inject the hook to the new location failed.
- both `newpos` and `oldpos` refer to the respective disabled list in which case no exceptions are thrown at all.

**<ins>BASIC:</ins>** Provided when the hook pointed to by `oldpos` was removed successfully from `other` but failed to be injected into the new location and at the same time an attempt of reverting the operation also failed. When that happens, the hook's state becomes disabled and it's therefore transferred to the disabled list while also maintaining order. You can determine whether basic guarantee was provided by whether the exception thrown was a nested exception in which case it means the attempt to provide strong guarantee failed as well. It is recommended that you use the standard function [std::rethrow_if_nested](https://en.cppreference.com/w/cpp/error/rethrow_if_nested) and optionally handle the situation when the guarantee provided is basic.

#### Notes

The following properties should be taken into account:

- The state of the hook pointed to by `oldpos` may change according to which list `oldpos` refers to (i.e. enabled or disabled).
- The hook pointed to by `oldpos` is placed right before `newpos` in *list iteration order*. However, the hook currently before `newpos` in *iteration order* (if any) will be linked with the spliced hook instead.

### splice(iterator newpos, hook_chain&& other, list_iterator oldpos)

#### Description

Splices a hook from `other` pointed to by `oldpos` to `newpos`. If `newpos` points to an existing element then the hook is placed right before that in *list iteration order*.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| newpos | iterator | the position before which the hook pointed to by `oldpos` will be spliced to. Can be the end iterator |
| other | hook_chain&& other | the instance from which the hook will be spliced. Can also be `*this` |
| oldpos | list_iterator | the list iterator to the hook that is going to be spliced |

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)

#### Exception Guarantee

**<ins>STRONG:</ins>** Provided when either of the following properties is true:

- An attempt to remove the hook from `other` failed.
- An attempt to inject the hook pointed to by `oldpos` to the new location failed, but reverting the operation succeeded (i.e. successfully linked back the hook to its previous location).
- `newpos` refers to the enabled list, `oldpos` refers to the disabled one of other and an attempt to inject the hook to the new location failed.
- both `newpos` and `oldpos` refer to the respective disabled list in which case no exceptions are thrown at all.

**<ins>BASIC:</ins>** Provided when the hook pointed to by `oldpos` was removed successfully from `other` but failed to be injected into the new location and at the same time an attempt of reverting the operation also failed. When that happens, the hook's state becomes disabled and it's therefore transferred to the disabled list while also maintaining order. You can determine whether basic guarantee was provided by whether the exception thrown was a nested exception in which case it means the attempt to provide strong guarantee failed as well. It is recommended that you use the standard function [std::rethrow_if_nested](https://en.cppreference.com/w/cpp/error/rethrow_if_nested) and optionally handle the situation when the guarantee provided is basic.

#### Notes

The following properties should be taken into account:

- The state of the hook pointed to by `oldpos` may change according to which list `oldpos` refers to (i.e. enabled or disabled).
- The hook pointed to by `oldpos` is placed right before `newpos` in *list iteration order*. However, the hook currently before `newpos` in *iteration order* (if any) will be linked with the spliced hook instead.

### splice(iterator newpos, list_iterator oldpos)

#### Description

Splices a hook pointed to by `oldpos` to `newpos`. If `newpos` points to an existing element then the hook is placed right before that in *list iteration order*.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| newpos | iterator | the position before which the hook pointed to by `oldpos` will be spliced to. Can be the end iterator |
| oldpos | list_iterator | the list iterator to the hook that is going to be spliced |

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)

#### Exception Guarantee

**<ins>STRONG:</ins>** Provided when either of the following properties is true:

- An attempt to remove the hook failed.
- An attempt to inject the hook pointed to by `oldpos` to the new location failed, but reverting the operation succeeded (i.e. successfully linked back the hook to its previous location).
- `newpos` refers to the enabled list, `oldpos` refers to the disabled one and an attempt to inject the hook to the new location failed.
- both `newpos` and `oldpos` refer to the respective disabled list in which case no exceptions are thrown at all.

**<ins>BASIC:</ins>** Provided when the hook pointed to by `oldpos` was removed successfully but failed to be injected into the new location and at the same time an attempt of reverting the operation also failed. When that happens, the hook's state becomes disabled and it's therefore transferred to the disabled list while also maintaining order. You can determine whether basic guarantee was provided by whether the exception thrown was a nested exception in which case it means the attempt to provide strong guarantee failed as well. It is recommended that you use the standard function [std::rethrow_if_nested](https://en.cppreference.com/w/cpp/error/rethrow_if_nested) and optionally handle the situation when the guarantee provided is basic.

#### Notes

The following properties should be taken into account:

- The state of the hook pointed to by `oldpos` may change according to which list `oldpos` refers to (i.e. enabled or disabled).
- The hook pointed to by `oldpos` is placed right before `newpos` in *list iteration order*. However, the hook currently before `newpos` in *iteration order* (if any) will be linked with the spliced hook instead.

### splice(list_iterator newpos, hook_chain& other, list_iterator first, list_iterator last, transfer to)

#### Description

Splices a range from `other` pointed to by [`first`, `last`) to `newpos`. If `newpos` points to an existing element then the range is placed right before that in *list iteration order*.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| newpos | list_iterator | the position before which the range pointed to by [`first`, `last`) will be spliced to. Can be the end list iterator |
| other | hook_chain& other | the instance from which the range will be spliced. Can also be `*this` |
| first | list_iterator | the list iterator to the first element of the range to be spliced |
| last | list_iterator | the list iterator to the end of the range to be spliced. It is not included in the range |
| to | transfer | Specifies whether `newpos` points to the enabled or the disabled list. Must not be `transfer::both` |

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)

#### Exception Guarantee

**<ins>STRONG:</ins>** Provided when either of the following properties is true:

- An attempt to remove the range from `other` failed.
- An attempt to inject the range pointed to by [`first`, `last`) to the new location failed, but reverting the operation succeeded (i.e. successfully linked back the range to its previous location).
- `newpos` refers to the enabled list (determined by `to`), [`first`, `last`) refers to the disabled one of other and an attempt to inject the range to the new location failed.
- both `newpos` and [`first`, `last`) refer to the respective disabled list in which case no exceptions are thrown at all.

**<ins>BASIC:</ins>** Provided when the range pointed to by [`first`, `last`) was removed successfully from `other` but failed to be injected into the new location and at the same time an attempt of reverting the operation also failed. When that happens, the range's state becomes disabled and it's therefore transferred to the disabled list while also maintaining order. You can determine whether basic guarantee was provided by whether the exception thrown was a nested exception in which case it means the attempt to provide strong guarantee failed as well. It is recommended that you use the standard function [std::rethrow_if_nested](https://en.cppreference.com/w/cpp/error/rethrow_if_nested) and optionally handle the situation when the guarantee provided is basic.

#### Notes

The following properties should be taken into account:

- The state of the range pointed to by [`first`, `last`) may change according to which list [`first`, `last`) refers to (i.e. enabled or disabled).
- The range pointed to by [`first`, `last`) is placed right before `newpos` in *list iteration order*. However, the hook currently before `newpos` in *iteration order* (if any) will be linked with the spliced range instead.
- If the value of `to` specifies a different list than the one `newpos` points to then the behavior is undefined. Unless `to == transfer::both` in which case you are guaranteed a run-time assertion on debug builds only.
- If `newpos` is either `this->eend()` or `this->dend()` then the range pointed to by [`first`, `last`) will be put last in *iteration order* with state based on the list `newpos` refers to just like previously. This is always true regardless of the state of the current last hook in the chain.

### splice(list_iterator newpos, hook_chain&& other, list_iterator first, list_iterator last, transfer to)

#### Description

Splices a range from `other` pointed to by [`first`, `last`) to `newpos`. If `newpos` points to an existing element then the range is placed right before that in *list iteration order*.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| newpos | list_iterator | the position before which the range pointed to by [`first`, `last`) will be spliced to. Can be the end list iterator |
| other | hook_chain&& other | the instance from which the range will be spliced. Can also be `*this` |
| first | list_iterator | the list iterator to the first element of the range to be spliced |
| last | list_iterator | the list iterator to the end of the range to be spliced. It is not included in the range |
| to | transfer | Specifies whether `newpos` points to the enabled or the disabled list. Must not be `transfer::both` |

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)

#### Exception Guarantee

**<ins>STRONG:</ins>** Provided when either of the following properties is true:

- An attempt to remove the range from `other` failed.
- An attempt to inject the range pointed to by [`first`, `last`) to the new location failed, but reverting the operation succeeded (i.e. successfully linked back the range to its previous location).
- `newpos` refers to the enabled list (determined by `to`), [`first`, `last`) refers to the disabled one of other and an attempt to inject the range to the new location failed.
- both `newpos` and [`first`, `last`) refer to the respective disabled list in which case no exceptions are thrown at all.

**<ins>BASIC:</ins>** Provided when the range pointed to by [`first`, `last`) was removed successfully from `other` but failed to be injected into the new location and at the same time an attempt of reverting the operation also failed. When that happens, the range's state becomes disabled and it's therefore transferred to the disabled list while also maintaining order. You can determine whether basic guarantee was provided by whether the exception thrown was a nested exception in which case it means the attempt to provide strong guarantee failed as well. It is recommended that you use the standard function [std::rethrow_if_nested](https://en.cppreference.com/w/cpp/error/rethrow_if_nested) and optionally handle the situation when the guarantee provided is basic.

#### Notes

The following properties should be taken into account:

- The state of the range pointed to by [`first`, `last`) may change according to which list [`first`, `last`) refers to (i.e. enabled or disabled).
- The range pointed to by [`first`, `last`) is placed right before `newpos` in *list iteration order*. However, the hook currently before `newpos` in *iteration order* (if any) will be linked with the spliced range instead.
- If the value of `to` specifies a different list than the one `newpos` points to then the behavior is undefined. Unless `to == transfer::both` in which case you are guaranteed a run-time assertion on debug builds only.
- If `newpos` is either `this->eend()` or `this->dend()` then the range pointed to by [`first`, `last`) will be put last in *iteration order* with state based on the list `newpos` refers to just like previously. This is always true regardless of the state of the current last hook in the chain.

### splice(list_iterator newpos, list_iterator first, list_iterator last, transfer to)

#### Description

Splices a range pointed to by [`first`, `last`) to `newpos`. If `newpos` points to an existing element then the range is placed right before that in *list iteration order*.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| newpos | list_iterator | the position before which the range pointed to by [`first`, `last`) will be spliced to. Can be the end list iterator |
| first | list_iterator | the list iterator to the first element of the range to be spliced |
| last | list_iterator | the list iterator to the end of the range to be spliced. It is not included in the range |
| to | transfer | Specifies whether `newpos` points to the enabled or the disabled list. Must not be `transfer::both` |

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)

#### Exception Guarantee

**<ins>STRONG:</ins>** Provided when either of the following properties is true:

- An attempt to remove the range failed.
- An attempt to inject the range pointed to by [`first`, `last`) to the new location failed, but reverting the operation succeeded (i.e. successfully linked back the range to its previous location).
- `newpos` refers to the enabled list (determined by `to`), [`first`, `last`) refers to the disabled one and an attempt to inject the range to the new location failed.
- both `newpos` and [`first`, `last`) refer to the respective disabled list in which case no exceptions are thrown at all.

**<ins>BASIC:</ins>** Provided when the range pointed to by [`first`, `last`) was removed successfully but failed to be injected into the new location and at the same time an attempt of reverting the operation also failed. When that happens, the range's state becomes disabled and it's therefore transferred to the disabled list while also maintaining order. You can determine whether basic guarantee was provided by whether the exception thrown was a nested exception in which case it means the attempt to provide strong guarantee failed as well. It is recommended that you use the standard function [std::rethrow_if_nested](https://en.cppreference.com/w/cpp/error/rethrow_if_nested) and optionally handle the situation when the guarantee provided is basic.

#### Notes

The following properties should be taken into account:

- The state of the range pointed to by [`first`, `last`) may change according to which list [`first`, `last`) refers to (i.e. enabled or disabled).
- The range pointed to by [`first`, `last`) is placed right before `newpos` in *list iteration order*. However, the hook currently before `newpos` in *iteration order* (if any) will be linked with the spliced range instead.
- If the value of `to` specifies a different list than the one `newpos` points to then the behavior is undefined. Unless `to == transfer::both` in which case you are guaranteed a run-time assertion on debug builds only.
- If `newpos` is either `this->eend()` or `this->dend()` then the range pointed to by [`first`, `last`) will be put last in *iteration order* with state based on the list `newpos` refers to just like previously. This is always true regardless of the state of the current last hook in the chain.

### splice(iterator newpos, hook_chain& other, list_iterator first, list_iterator last)

#### Description

Splices a range from `other` pointed to by [`first`, `last`) to `newpos`. If `newpos` points to an existing element then the range is placed right before that in *list iteration order*.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| newpos | iterator | the position before which the range pointed to by [`first`, `last`) will be spliced to. Can be the end iterator |
| other | hook_chain& other | the instance from which the range will be spliced. Can also be `*this` |
| first | list_iterator | the list iterator to the first element of the range to be spliced |
| last | list_iterator | the list iterator to the end of the range to be spliced. It is not included in the range |

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)

#### Exception Guarantee

**<ins>STRONG:</ins>** Provided when either of the following properties is true:

- An attempt to remove the range from `other` failed.
- An attempt to inject the range pointed to by [`first`, `last`) to the new location failed, but reverting the operation succeeded (i.e. successfully linked back the range to its previous location).
- `newpos` refers to the enabled list, [`first`, `last`) refers to the disabled one of other and an attempt to inject the range to the new location failed.
- both `newpos` and [`first`, `last`) refer to the respective disabled list in which case no exceptions are thrown at all.

**<ins>BASIC:</ins>** Provided when the range pointed to by [`first`, `last`) was removed successfully from `other` but failed to be injected into the new location and at the same time an attempt of reverting the operation also failed. When that happens, the range's state becomes disabled and it's therefore transferred to the disabled list while also maintaining order. You can determine whether basic guarantee was provided by whether the exception thrown was a nested exception in which case it means the attempt to provide strong guarantee failed as well. It is recommended that you use the standard function [std::rethrow_if_nested](https://en.cppreference.com/w/cpp/error/rethrow_if_nested) and optionally handle the situation when the guarantee provided is basic.

#### Notes

The following properties should be taken into account:

- The state of the range pointed to by [`first`, `last`) may change according to which list [`first`, `last`) refers to (i.e. enabled or disabled).
- The range pointed to by [`first`, `last`) is placed right before `newpos` in *list iteration order*. However, the hook currently before `newpos` in *iteration order* (if any) will be linked with the spliced range instead.

### splice(iterator newpos, hook_chain&& other, list_iterator first, list_iterator last)

#### Description

Splices a range from `other` pointed to by [`first`, `last`) to `newpos`. If `newpos` points to an existing element then the range is placed right before that in *list iteration order*.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| newpos | iterator | the position before which the range pointed to by [`first`, `last`) will be spliced to. Can be the end iterator |
| other | hook_chain&& other | the instance from which the range will be spliced. Can also be `*this` |
| first | list_iterator | the list iterator to the first element of the range to be spliced |
| last | list_iterator | the list iterator to the end of the range to be spliced. It is not included in the range |

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)

#### Exception Guarantee

**<ins>STRONG:</ins>** Provided when either of the following properties is true:

- An attempt to remove the range from `other` failed.
- An attempt to inject the range pointed to by [`first`, `last`) to the new location failed, but reverting the operation succeeded (i.e. successfully linked back the range to its previous location).
- `newpos` refers to the enabled list, [`first`, `last`) refers to the disabled one of other and an attempt to inject the range to the new location failed.
- both `newpos` and [`first`, `last`) refer to the respective disabled list in which case no exceptions are thrown at all.

**<ins>BASIC:</ins>** Provided when the range pointed to by [`first`, `last`) was removed successfully from `other` but failed to be injected into the new location and at the same time an attempt of reverting the operation also failed. When that happens, the range's state becomes disabled and it's therefore transferred to the disabled list while also maintaining order. You can determine whether basic guarantee was provided by whether the exception thrown was a nested exception in which case it means the attempt to provide strong guarantee failed as well. It is recommended that you use the standard function [std::rethrow_if_nested](https://en.cppreference.com/w/cpp/error/rethrow_if_nested) and optionally handle the situation when the guarantee provided is basic.

#### Notes

The following properties should be taken into account:

- The state of the range pointed to by [`first`, `last`) may change according to which list [`first`, `last`) refers to (i.e. enabled or disabled).
- The range pointed to by [`first`, `last`) is placed right before `newpos` in *list iteration order*. However, the hook currently before `newpos` in *iteration order* (if any) will be linked with the spliced range instead.

### splice(iterator newpos, list_iterator first, list_iterator last)

#### Description

Splices a range pointed to by [`first`, `last`) to `newpos`. If `newpos` points to an existing element then the range is placed right before that in *list iteration order*.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| newpos | iterator | the position before which the range pointed to by [`first`, `last`) will be spliced to. Can be the end iterator |
| first | list_iterator | the list iterator to the first element of the range to be spliced |
| last | list_iterator | the list iterator to the end of the range to be spliced. It is not included in the range |

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)

#### Exception Guarantee

**<ins>STRONG:</ins>** Provided when either of the following properties is true:

- An attempt to remove the range failed.
- An attempt to inject the range pointed to by [`first`, `last`) to the new location failed, but reverting the operation succeeded (i.e. successfully linked back the range to its previous location).
- `newpos` refers to the enabled list, [`first`, `last`) refers to the disabled one and an attempt to inject the range to the new location failed.
- both `newpos` and [`first`, `last`) refer to the respective disabled list in which case no exceptions are thrown at all.

**<ins>BASIC:</ins>** Provided when the range pointed to by [`first`, `last`) was removed successfully but failed to be injected into the new location and at the same time an attempt of reverting the operation also failed. When that happens, the range's state becomes disabled and it's therefore transferred to the disabled list while also maintaining order. You can determine whether basic guarantee was provided by whether the exception thrown was a nested exception in which case it means the attempt to provide strong guarantee failed as well. It is recommended that you use the standard function [std::rethrow_if_nested](https://en.cppreference.com/w/cpp/error/rethrow_if_nested) and optionally handle the situation when the guarantee provided is basic.

#### Notes

The following properties should be taken into account:

- The state of the range pointed to by [`first`, `last`) may change according to which list [`first`, `last`) refers to (i.e. enabled or disabled).
- The range pointed to by [`first`, `last`) is placed right before `newpos` in *list iteration order*. However, the hook currently before `newpos` in *iteration order* (if any) will be linked with the spliced range instead.

### splice(list_iterator newpos, hook_chain& other, iterator first, iterator last, transfer to)

#### Description

Splices the range [`first`, `last`) from `other` to the destination starting from `newpos`. The range is in *iteration order* and therefore may include both enabled and disabled hooks. The hooks that are of the same state as the hooks in the list `newpos` refers to will be put right before it while the hooks of different state will be put in a different position in the other list. The hooks that are spliced are properly linked in their new positions so that iterating over the container will give them in the same order as in [`first`, `last`) regardless of the state of the first elements in the range.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| newpos | list_iterator | the position before which the range pointed to by [`first`, `last`) will be spliced to. Can be the end list iterator |
| other | hook_chain& other | the instance from which the range will be spliced. Can also be `*this` |
| first | iterator | the iterator to the first element of the range to be spliced |
| last | iterator | the iterator to the end of the range to be spliced. It is not included in the range |
| to | transfer | Specifies whether `newpos` points to the enabled or the disabled list. Must not be `transfer::both` |

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)

#### Exception Guarantee

**<ins>STRONG:</ins>** Provided when either of the following properties is true:

- An attempt to remove the range from `other` failed.
- An attempt to inject the range pointed to by [`first`, `last`) to the new location failed, but reverting the operation succeeded (i.e. successfully linked back the range to its previous location).
- The range [`first`, `last`) has no enabled hooks included in which case no exceptions are ever thrown.

**<ins>BASIC:</ins>** Provided when the range pointed to by [`first`, `last`) was removed successfully from `other` but failed to be injected into the new location and at the same time an attempt of reverting the operation also failed. When that happens, the range's state becomes disabled and it's therefore transferred to the disabled list while also maintaining order. You can determine whether basic guarantee was provided by whether the exception thrown was a nested exception in which case it means the attempt to provide strong guarantee failed as well. It is recommended that you use the standard function [std::rethrow_if_nested](https://en.cppreference.com/w/cpp/error/rethrow_if_nested) and optionally handle the situation when the guarantee provided is basic.

#### Notes

The following properties should be taken into account:

- The state of the hooks in the range [`first`, `last`) is maintained.
- The `newpos` argument represents a destination rather than an exact position in which hooks will be placed. For example if the range [`first`, `last`) contains only disabled hooks but `newpos` refers to the enabled list then the API will search for a respective position in the disabled list. The search will start from `newpos` till a link to a hook of the other list is found. If found, the hooks in the range will be placed behind that position. Otherwise, they will be placed at the end of the disabled list. The same process will be done when there is at least one hook in the range that is of different state than the hooks in the list `newpos` refers to.
- If the value of `to` specifies a different list than the one `newpos` points to then the behavior is undefined. Unless `to == transfer::both` in which case you are guaranteed a run-time assertion on debug builds only.
- If `newpos` is either `this->eend()` or `this->dend()` then the range pointed to by [`first`, `last`) will be put last in *iteration order* with state based on the list `newpos` refers to just like previously. This is always true regardless of the state of the current last hook in the chain.

### splice(list_iterator newpos, hook_chain&& other, iterator first, iterator last, transfer to)

#### Description

Splices the range [`first`, `last`) from `other` to the destination starting from `newpos`. The range is in *iteration order* and therefore may include both enabled and disabled hooks. The hooks that are of the same state as the hooks in the list `newpos` refers to will be put right before it while the hooks of different state will be put in a different position in the other list. The hooks that are spliced are properly linked in their new positions so that iterating over the container will give them in the same order as in [`first`, `last`) regardless of the state of the first elements in the range.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| newpos | list_iterator | the position before which the range pointed to by [`first`, `last`) will be spliced to. Can be the end list iterator |
| other | hook_chain&& other | the instance from which the range will be spliced. Can also be `*this` |
| first | iterator | the iterator to the first element of the range to be spliced |
| last | iterator | the iterator to the end of the range to be spliced. It is not included in the range |
| to | transfer | Specifies whether `newpos` points to the enabled or the disabled list. Must not be `transfer::both` |

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)

#### Exception Guarantee

**<ins>STRONG:</ins>** Provided when either of the following properties is true:

- An attempt to remove the range from `other` failed.
- An attempt to inject the range pointed to by [`first`, `last`) to the new location failed, but reverting the operation succeeded (i.e. successfully linked back the range to its previous location).
- The range [`first`, `last`) has no enabled hooks included in which case no exceptions are ever thrown.

**<ins>BASIC:</ins>** Provided when the range pointed to by [`first`, `last`) was removed successfully from `other` but failed to be injected into the new location and at the same time an attempt of reverting the operation also failed. When that happens, the range's state becomes disabled and it's therefore transferred to the disabled list while also maintaining order. You can determine whether basic guarantee was provided by whether the exception thrown was a nested exception in which case it means the attempt to provide strong guarantee failed as well. It is recommended that you use the standard function [std::rethrow_if_nested](https://en.cppreference.com/w/cpp/error/rethrow_if_nested) and optionally handle the situation when the guarantee provided is basic.

#### Notes

The following properties should be taken into account:

- The state of the hooks in the range [`first`, `last`) is maintained.
- The `newpos` argument represents a destination rather than an exact position in which hooks will be placed. For example if the range [`first`, `last`) contains only disabled hooks but `newpos` refers to the enabled list then the API will search for a respective position in the disabled list. The search will start from `newpos` till a link to a hook of the other list is found. If found, the hooks in the range will be placed behind that position. Otherwise, they will be placed at the end of the disabled list. The same process will be done when there is at least one hook in the range that is of different state than the hooks in the list `newpos` refers to.
- If the value of `to` specifies a different list than the one `newpos` points to then the behavior is undefined. Unless `to == transfer::both` in which case you are guaranteed a run-time assertion on debug builds only.
- If `newpos` is either `this->eend()` or `this->dend()` then the range pointed to by [`first`, `last`) will be put last in *iteration order* with state based on the list `newpos` refers to just like previously. This is always true regardless of the state of the current last hook in the chain.

### splice(list_iterator newpos, iterator first, iterator last, transfer to)

#### Description

Splices the range [`first`, `last`) from `other` to the destination starting from `newpos`. The range is in *iteration order* and therefore may include both enabled and disabled hooks. The hooks that are of the same state as the hooks in the list `newpos` refers to will be put right before it while the hooks of different state will be put in a different position in the other list. The hooks that are spliced are properly linked in their new positions so that iterating over the container will give them in the same order as in [`first`, `last`) regardless of the state of the first elements in the range.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| newpos | list_iterator | the position before which the range pointed to by [`first`, `last`) will be spliced to. Can be the end list iterator |
| first | iterator | the iterator to the first element of the range to be spliced |
| last | iterator | the iterator to the end of the range to be spliced. It is not included in the range |
| to | transfer | Specifies whether `newpos` points to the enabled or the disabled list. Must not be `transfer::both` |

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)

#### Exception Guarantee

**<ins>STRONG:</ins>** Provided when either of the following properties is true:

- An attempt to remove the range failed.
- An attempt to inject the range pointed to by [`first`, `last`) to the new location failed, but reverting the operation succeeded (i.e. successfully linked back the range to its previous location).
- The range [`first`, `last`) has no enabled hooks included in which case no exceptions are ever thrown.

**<ins>BASIC:</ins>** Provided when the range pointed to by [`first`, `last`) was removed successfully but failed to be injected into the new location and at the same time an attempt of reverting the operation also failed. When that happens, the range's state becomes disabled and it's therefore transferred to the disabled list while also maintaining order. You can determine whether basic guarantee was provided by whether the exception thrown was a nested exception in which case it means the attempt to provide strong guarantee failed as well. It is recommended that you use the standard function [std::rethrow_if_nested](https://en.cppreference.com/w/cpp/error/rethrow_if_nested) and optionally handle the situation when the guarantee provided is basic.

#### Notes

The following properties should be taken into account:

- The state of the hooks in the range [`first`, `last`) is maintained.
- The `newpos` argument represents a destination rather than an exact position in which hooks will be placed. For example if the range [`first`, `last`) contains only disabled hooks but `newpos` refers to the enabled list then the API will search for a respective position in the disabled list. The search will start from `newpos` till a link to a hook of the other list is found. If found, the hooks in the range will be placed behind that position. Otherwise, they will be placed at the end of the disabled list. The same process will be done when there is at least one hook in the range that is of different state than the hooks in the list `newpos` refers to.
- If the value of `to` specifies a different list than the one `newpos` points to then the behavior is undefined. Unless `to == transfer::both` in which case you are guaranteed a run-time assertion on debug builds only.
- If `newpos` is either `this->eend()` or `this->dend()` then the range pointed to by [`first`, `last`) will be put last in *iteration order* with state based on the list `newpos` refers to just like previously. This is always true regardless of the state of the current last hook in the chain.

### splice(iterator newpos, hook_chain& other, iterator first, iterator last)

#### Description

Splices the range [`first`, `last`) from `other` to the destination starting from `newpos`. The range is in *iteration order* and therefore may include both enabled and disabled hooks. The hooks that are of the same state as the hooks in the list `newpos` refers to will be put right before it while the hooks of different state will be put in a different position in the other list. The hooks that are spliced are properly linked in their new positions so that iterating over the container will give them in the same order as in [`first`, `last`) regardless of the state of the first elements in the range.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| newpos | iterator | the position before which the range pointed to by [`first`, `last`) will be spliced to. Can be the end iterator |
| other | hook_chain& other | the instance from which the range will be spliced. Can also be `*this` |
| first | iterator | the iterator to the first element of the range to be spliced |
| last | iterator | the iterator to the end of the range to be spliced. It is not included in the range |

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)

#### Exception Guarantee

**<ins>STRONG:</ins>** Provided when either of the following properties is true:

- An attempt to remove the range from `other` failed.
- An attempt to inject the range pointed to by [`first`, `last`) to the new location failed, but reverting the operation succeeded (i.e. successfully linked back the range to its previous location).
- The range [`first`, `last`) has no enabled hooks included in which case no exceptions are ever thrown.

**<ins>BASIC:</ins>** Provided when the range pointed to by [`first`, `last`) was removed successfully from `other` but failed to be injected into the new location and at the same time an attempt of reverting the operation also failed. When that happens, the range's state becomes disabled and it's therefore transferred to the disabled list while also maintaining order. You can determine whether basic guarantee was provided by whether the exception thrown was a nested exception in which case it means the attempt to provide strong guarantee failed as well. It is recommended that you use the standard function [std::rethrow_if_nested](https://en.cppreference.com/w/cpp/error/rethrow_if_nested) and optionally handle the situation when the guarantee provided is basic.

#### Notes

The following properties should be taken into account:

- The state of the hooks in the range [`first`, `last`) is maintained.
- The `newpos` argument represents a destination rather than an exact position in which hooks will be placed. For example if the range [`first`, `last`) contains only disabled hooks but `newpos` refers to the enabled list then the API will search for a respective position in the disabled list. The search will start from `newpos` till a link to a hook of the other list is found. If found, the hooks in the range will be placed behind that position. Otherwise, they will be placed at the end of the disabled list. The same process will be done when there is at least one hook in the range that is of different state than the hooks in the list `newpos` refers to.

### splice(iterator newpos, hook_chain&& other, iterator first, iterator last)

#### Description

Splices the range [`first`, `last`) from `other` to the destination starting from `newpos`. The range is in *iteration order* and therefore may include both enabled and disabled hooks. The hooks that are of the same state as the hooks in the list `newpos` refers to will be put right before it while the hooks of different state will be put in a different position in the other list. The hooks that are spliced are properly linked in their new positions so that iterating over the container will give them in the same order as in [`first`, `last`) regardless of the state of the first elements in the range.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| newpos | iterator | the position before which the range pointed to by [`first`, `last`) will be spliced to. Can be the end iterator |
| other | hook_chain&& other | the instance from which the range will be spliced. Can also be `*this` |
| first | iterator | the iterator to the first element of the range to be spliced |
| last | iterator | the iterator to the end of the range to be spliced. It is not included in the range |

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)

#### Exception Guarantee

**<ins>STRONG:</ins>** Provided when either of the following properties is true:

- An attempt to remove the range from `other` failed.
- An attempt to inject the range pointed to by [`first`, `last`) to the new location failed, but reverting the operation succeeded (i.e. successfully linked back the range to its previous location).
- The range [`first`, `last`) has no enabled hooks included in which case no exceptions are ever thrown.

**<ins>BASIC:</ins>** Provided when the range pointed to by [`first`, `last`) was removed successfully from `other` but failed to be injected into the new location and at the same time an attempt of reverting the operation also failed. When that happens, the range's state becomes disabled and it's therefore transferred to the disabled list while also maintaining order. You can determine whether basic guarantee was provided by whether the exception thrown was a nested exception in which case it means the attempt to provide strong guarantee failed as well. It is recommended that you use the standard function [std::rethrow_if_nested](https://en.cppreference.com/w/cpp/error/rethrow_if_nested) and optionally handle the situation when the guarantee provided is basic.

#### Notes

The following properties should be taken into account:

- The state of the hooks in the range [`first`, `last`) is maintained.
- The `newpos` argument represents a destination rather than an exact position in which hooks will be placed. For example if the range [`first`, `last`) contains only disabled hooks but `newpos` refers to the enabled list then the API will search for a respective position in the disabled list. The search will start from `newpos` till a link to a hook of the other list is found. If found, the hooks in the range will be placed behind that position. Otherwise, they will be placed at the end of the disabled list. The same process will be done when there is at least one hook in the range that is of different state than the hooks in the list `newpos` refers to.

### splice(iterator newpos, iterator first, iterator last)

#### Description

Splices the range [`first`, `last`) from `other` to the destination starting from `newpos`. The range is in *iteration order* and therefore may include both enabled and disabled hooks. The hooks that are of the same state as the hooks in the list `newpos` refers to will be put right before it while the hooks of different state will be put in a different position in the other list. The hooks that are spliced are properly linked in their new positions so that iterating over the container will give them in the same order as in [`first`, `last`) regardless of the state of the first elements in the range.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| newpos | iterator | the position before which the range pointed to by [`first`, `last`) will be spliced to. Can be the end iterator |
| first | iterator | the iterator to the first element of the range to be spliced |
| last | iterator | the iterator to the end of the range to be spliced. It is not included in the range |

#### Exceptions

- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions)

#### Exception Guarantee

**<ins>STRONG:</ins>** Provided when either of the following properties is true:

- An attempt to remove the range failed.
- An attempt to inject the range pointed to by [`first`, `last`) to the new location failed, but reverting the operation succeeded (i.e. successfully linked back the range to its previous location).
- The range [`first`, `last`) has no enabled hooks included in which case no exceptions are ever thrown.

**<ins>BASIC:</ins>** Provided when the range pointed to by [`first`, `last`) was removed successfully but failed to be injected into the new location and at the same time an attempt of reverting the operation also failed. When that happens, the range's state becomes disabled and it's therefore transferred to the disabled list while also maintaining order. You can determine whether basic guarantee was provided by whether the exception thrown was a nested exception in which case it means the attempt to provide strong guarantee failed as well. It is recommended that you use the standard function [std::rethrow_if_nested](https://en.cppreference.com/w/cpp/error/rethrow_if_nested) and optionally handle the situation when the guarantee provided is basic.

#### Notes

The following properties should be taken into account:

- The state of the hooks in the range [`first`, `last`) is maintained.
- The `newpos` argument represents a destination rather than an exact position in which hooks will be placed. For example if the range [`first`, `last`) contains only disabled hooks but `newpos` refers to the enabled list then the API will search for a respective position in the disabled list. The search will start from `newpos` till a link to a hook of the other list is found. If found, the hooks in the range will be placed behind that position. Otherwise, they will be placed at the end of the disabled list. The same process will be done when there is at least one hook in the range that is of different state than the hooks in the list `newpos` refers to.

## Element Accessing

### operator[](size_t n)

#### Description

Returns a reference to the element at position `n` in *iteration order*. Does not throw any exception and so if `n` is out of range the behavior is undefined (however an assertion is provided on debug builds). Underlying this is effectively just `*std::next(begin(), n)`.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| n | size_t | the index of the element to access |

#### Returns

A `hook_chain::reference` to the element of the specified index.

#### Notes

Since `hook_chain::iterator` is not a [random access iterator](https://en.cppreference.com/w/cpp/iterator/random_access_iterator) but rather a [forward iterator](https://en.cppreference.com/w/cpp/iterator/forward_iterator) this operation requires iterating over each element till it reaches the `n` position. Therefore this may be considered expensive and users should prefer calling it rarely as well as keep references to the elements they care about since references are only invalidated on deletion.

### operator[](size_t n) const

#### Description

Returns a reference to the element at position `n` in *iteration order*. Does not throw any exception and so if `n` is out of range the behavior is undefined (however an assertion is provided on debug builds). Underlying this is effectively just `*std::next(begin(), n)`.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| n | size_t | the index of the element to access |

#### Returns

A `hook_chain::const_reference` to the element of the specified index.

#### Notes

Since `hook_chain::iterator` is not a [random access iterator](https://en.cppreference.com/w/cpp/iterator/random_access_iterator) but rather a [forward iterator](https://en.cppreference.com/w/cpp/iterator/forward_iterator) this operation requires iterating over each element till it reaches the `n` position. Therefore this may be considered expensive and users should prefer calling it rarely as well as keep references to the elements they care about since references are only invalidated on deletion.

### at(size_t n)

#### Description

Returns a reference to the element at position `n` in *iteration order*. If `n` is out of range it will throw [std::out_of_range](https://en.cppreference.com/w/cpp/error/out_of_range). Underlying this is effectively just `*std::next(begin(), n)`.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| n | size_t | the index of the element to access |

#### Returns

A `hook_chain::reference` to the element of the specified index.

#### Notes

Since `hook_chain::iterator` is not a [random access iterator](https://en.cppreference.com/w/cpp/iterator/random_access_iterator) but rather a [forward iterator](https://en.cppreference.com/w/cpp/iterator/forward_iterator) this operation requires iterating over each element till it reaches the `n` position. Therefore this may be considered expensive and users should prefer calling it rarely as well as keep references to the elements they care about since references are only invalidated on deletion.

### at(size_t n) const

#### Description

Returns a reference to the element at position `n` in *iteration order*. If `n` is out of range it will throw [std::out_of_range](https://en.cppreference.com/w/cpp/error/out_of_range). Underlying this is effectively just `*std::next(begin(), n)`.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| n | size_t | the index of the element to access |

#### Returns

A `hook_chain::const_reference` to the element of the specified index.

#### Notes

Since `hook_chain::iterator` is not a [random access iterator](https://en.cppreference.com/w/cpp/iterator/random_access_iterator) but rather a [forward iterator](https://en.cppreference.com/w/cpp/iterator/forward_iterator) this operation requires iterating over each element till it reaches the `n` position. Therefore this may be considered expensive and users should prefer calling it rarely as well as keep references to the elements they care about since references are only invalidated on deletion.

### front()

#### Returns

A `reference` to the first element of the container.

### front() const

#### Returns

A `const_reference` to the first element of the container.

### cfront() const

#### Returns

A `const_reference` to the first element of the container.

### back()

#### Returns

A `reference` to the last element of the container.

### back() const

#### Returns

A `const_reference` to the last element of the container.

### cback() const

#### Returns

A `const_reference` to the last element of the container.

### efront()

#### Returns

A `reference` to the first element of the enabled list.

### efront() const

#### Returns

A `const_reference` to the first element of the enabled list.

### cefront() const

#### Returns

A `const_reference` to the first element of the enabled list.

### eback()

#### Returns

A `reference` to the last element of the enabled list.

### eback() const

#### Returns

A `const_reference` to the last element of the enabled list.

### ceback() const

#### Returns

A `const_reference` to the last element of the enabled list.

### dfront()

#### Returns

A `reference` to the first element of the disabled list.

### dfront() const

#### Returns

A `const_reference` to the first element of the disabled list.

### cdfront() const

#### Returns

A `const_reference` to the first element of the disabled list.

### dback()

#### Returns

A `reference` to the last element of the disabled list.

### dback() const

#### Returns

A `const_reference` to the last element of the disabled list.

### cdback() const

#### Returns

A `const_reference` to the last element of the disabled list.

## Setters

### set_target(std::byte* target)

#### Description

Sets or initializes (if uninitialized) the hook chain using `target` as the target function.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| target | std::byte* | the target to use |

#### Exceptions

- [Trampoline Initialization Exceptions](exception_groups.md#trampoline-initialization-exceptions)
- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions) (**<ins>Only when already enabled</ins>**)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions) (**<ins>Only when already enabled</ins>**)

#### Exception Guarantee

**<ins>STRONG:</ins>** If it has enabled hooks it disables and then tries to re-enable them after the operation is finished, so the following properties are true:

- If it has enabled hooks it's only strong when the exceptions come from the disable operation.
- If not enabled the operation has strong exception guarantee when the exception belongs in the [Memory Allocation and Address Validation Exceptions](exception_groups.md#memory-allocation-and-address-validation-exceptions) group.

**<ins>BASIC:</ins>** For any other possible outcome the operation has basic exception guarantee. The cases are the following:

- If it has enabled hooks and the exception belongs in the [Memory Allocation and Address Validation Exceptions](exception_groups.md#memory-allocation-and-address-validation-exceptions) group then they will be left disabled but with the same properties as before.
- If the exception belongs to the [Trampoline Initialization Exceptions](exception_groups.md#trampoline-initialization-exceptions) group but not to the [Memory Allocation and Address Validation Exceptions](exception_groups.md#memory-allocation-and-address-validation-exceptions) then the trampoline is left uninitialized. This results in the container being left targetless. The state of all the hooks is of course disabled even for those that were enabled before and the *iteration order* is maintained.
- If the exception thrown isn't in the [Trampoline Initialization Exceptions](exception_groups.md#trampoline-initialization-exceptions) group and all hooks are left disabled when there were enabled hooks before, it means that the enable operation failed. In that case, the operation was successfully completed, with the hook redirected to a new target but the state of the hooks is left disabled nevertheless as enabling failed.

#### Notes

All enabled hooks in the container will be temporarily disabled and then re-enabled after redirection to the new target is completed.

### set_target(trg&& target)

#### Description

Sets or initializes (if uninitialized) the hook chain using `target` as the target function.

#### Parameters

| Parameter | Type | Description |
| --- | --- | --- |
| target | trg&& (forwarding reference, any) | the target to use |

#### Exceptions

- [Trampoline Initialization Exceptions](exception_groups.md#trampoline-initialization-exceptions)
- [Thread Freezer Exceptions](exception_groups.md#thread-freezer-exceptions) (**<ins>Only when already enabled</ins>**)
- [Target Injection Exceptions](exception_groups.md#target-injection-exceptions) (**<ins>Only when already enabled</ins>**)

#### Exception Guarantee

**<ins>STRONG:</ins>** If it has enabled hooks it disables and then tries to re-enable them after the operation is finished, so the following properties are true:

- If it has enabled hooks it's only strong when the exceptions come from the disable operation.
- If not enabled the operation has strong exception guarantee when the exception belongs in the [Memory Allocation and Address Validation Exceptions](exception_groups.md#memory-allocation-and-address-validation-exceptions) group.

**<ins>BASIC:</ins>** For any other possible outcome the operation has basic exception guarantee. The cases are the following:

- If it has enabled hooks and the exception belongs in the [Memory Allocation and Address Validation Exceptions](exception_groups.md#memory-allocation-and-address-validation-exceptions) group then they will be left disabled but with the same properties as before.
- If the exception belongs to the [Trampoline Initialization Exceptions](exception_groups.md#trampoline-initialization-exceptions) group but not to the [Memory Allocation and Address Validation Exceptions](exception_groups.md#memory-allocation-and-address-validation-exceptions) then the trampoline is left uninitialized. This results in the container being left targetless. The state of all the hooks is of course disabled even for those that were enabled before and the *iteration order* is maintained.
- If the exception thrown isn't in the [Trampoline Initialization Exceptions](exception_groups.md#trampoline-initialization-exceptions) group and all hooks are left disabled when there were enabled hooks before, it means that the enable operation failed. In that case, the operation was successfully completed, with the hook redirected to a new target but the state of the hooks is left disabled nevertheless as enabling failed.

#### Notes

All enabled hooks in the container will be temporarily disabled and then re-enabled after redirection to the new target is completed.

## Getters

### empty

#### Returns

`true` if the container is empty (i.e. holds no hooks at all), otherwise `false`.

### empty_enabled

#### Returns

`true` if the enabled list is empty (i.e. has no enabled hooks in the container), otherwise `false`.

### empty_disabled

#### Returns

`true` if the disabled list is empty (i.e. has no disabled hooks in the container), otherwise `false`.

### operator bool

#### Returns

`true` if the container is empty (i.e. holds no hooks at all), otherwise `false`.

### size

#### Returns

The number of hooks in the container (both enabled and disabled).

### enabled_size

#### Returns

The number of enabled hooks in the container.

### disabled_size

#### Returns

The number of disabled hooks in the container.

## Iterators

### begin()

#### Returns

An `iterator` to the beginning of the container.

### begin() const

#### Returns

A `const_iterator` to the beginning of the container.

### cbegin() const

#### Returns

A `const_iterator` to the beginning of the container.

### end()

#### Returns

An `iterator` to the end of the container.

### end() const

#### Returns

A `const_iterator` to the end of the container.

### cend() const

#### Returns

A `const_iterator` to the end of the container.

### ebegin()

#### Returns

A `list_iterator` to the beginning of the enabled list.

### ebegin() const

#### Returns

A `const_list_iterator` to the beginning of the enabled list.

### cebegin() const

#### Returns

A `const_list_iterator` to the beginning of the enabled list.

### rebegin()

#### Returns

A `reverse_list_iterator` to the reversed beginning of the enabled list.

### rebegin() const

#### Returns

A `const_reverse_list_iterator` to the reversed beginning of the enabled list.

### crebegin() const

#### Returns

A `const_reverse_list_iterator` to the reversed beginning of the enabled list.

### eend()

#### Returns

A `list_iterator` to the end of the enabled list.

### eend() const

#### Returns

A `const_list_iterator` to the end of the enabled list.

### ceend() const

#### Returns

A `const_list_iterator` to the end of the enabled list.

### reend()

#### Returns

A `reverse_list_iterator` to the reversed end of the enabled list.

### reend() const

#### Returns

A `const_reverse_list_iterator` to the reversed end of the enabled list.

### creend() const

#### Returns

A `const_reverse_list_iterator` to the reversed end of the enabled list.

### dbegin()

#### Returns

A `list_iterator` to the beginning of the disabled list.

### dbegin() const

#### Returns

A `const_list_iterator` to the beginning of the disabled list.

### cdbegin() const

#### Returns

A `const_list_iterator` to the beginning of the disabled list.

### rdbegin()

#### Returns

A `reverse_list_iterator` to the reversed beginning of the disabled list.

### rdbegin() const

#### Returns

A `const_reverse_list_iterator` to the reversed beginning of the disabled list.

### crdbegin() const

#### Returns

A `const_reverse_list_iterator` to the reversed beginning of the disabled list.

### dend()

#### Returns

A `list_iterator` to the end of the disabled list.

### dend() const

#### Returns

A `const_list_iterator` to the end of the disabled list.

### cdend() const

#### Returns

A `const_list_iterator` to the end of the disabled list.

### rdend()

#### Returns

A `reverse_list_iterator` to the reversed end of the disabled list.

### rdend() const

#### Returns

A `const_reverse_list_iterator` to the reversed end of the disabled list.

### crdend() const

#### Returns

A `const_reverse_list_iterator` to the reversed end of the disabled list.

## Comparison

Equality is determined by the following factors:

- Number of elements in the disabled list
- Number of elements in the enabled list
- The pointer to the target
- The detour and the state of each element in the container

If all of the above compare equal in *iteration order* (meaning the order of the hooks also matters) then:

- operator==: returns `true`
- operator!=: returns `false`

Otherwise, it's the other way around.

Note that the original callback is not a comparison factor.
