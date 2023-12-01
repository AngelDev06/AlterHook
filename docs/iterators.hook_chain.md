# Iterators

The custom iterator types that are used by the [hook_chain](hook_chain.md) container to iterate over all the hooks included in it (both the enabled and the disabled ones). They all satisfy the [std::forward_iterator](https://en.cppreference.com/w/cpp/iterator/forward_iterator) concept (included in c++20).

## Synopsis

<pre>
 <code>
class hook_chain::iterator
{
public:
  typedef std::forward_iterator_tag iterator_concept; // c++20 only
  typedef std::forward_iterator_tag iterator_category;
  typedef hook                      value_type;
  typedef ptrdiff_t                 difference_type;
  typedef hook*                     pointer;
  typedef hook&                     reference;

  <a href="#default-constructor">iterator</a>() noexcept;

  reference <a href="#operator">operator*</a>() const noexcept;

  pointer <a href="#operator-1">operator-></a>() const noexcept;

  iterator& <a href="#operator-2">operator++</a>() noexcept;
  iterator  <a href="#operatorint">operator++</a>(int) noexcept;

  bool <a href="#comparison">operator==</a>(const iterator& other) const noexcept;

  bool <a href="#comparison">operator!=</a>(const iterator& other) const noexcept;

  <a href="#operator-list_iterator">operator list_iterator</a>() const noexcept;

  <a href="#operator-const_list_iterator">operator const_list_iterator</a>() const noexcept;
};

class hook_chain::const_iterator
{
public:
  typedef std::forward_iterator_tag iterator_concept; // c++20 only
  typedef std::forward_iterator_tag iterator_category;
  typedef hook                      value_type;
  typedef ptrdiff_t                 difference_type;
  typedef const hook*               pointer;
  typedef const hook&               reference;

  <a href="#default-constructor">const_iterator</a>() noexcept;

  reference <a href="#operator">operator*</a>() const noexcept;

  pointer <a href="#operator-1">operator-></a>() const noexcept;

  const_iterator& <a href="#operator-2">operator++</a>() noexcept;
  const_iterator  <a href="#operatorint">operator++</a>(int) noexcept;

  bool <a href="#comparison">operator==</a>(const const_iterator& other) const noexcept;

  bool <a href="#comparison">operator!=</a>(const const_iterator& other) const noexcept;

  <a href="#operator-const_list_iterator">operator const_list_iterator</a>() const noexcept;
};
 </code>
</pre>

## Constructors

### default constructor

#### Description

Default constructs the iterator. The iterator remains uninitialized and can only be initialized by the library.

#### Notes

This is meant for temporarily constructing a variable that will hold an iterator before actually initializing it with one. Any attempt to use the default constructed iterator before setting it with a valid one returned by the library will lead to undefined behavior.

## Element Accessing

### operator*

#### Description

"dereferences" the iterator.

#### Returns

A `reference` to the element it currently points to.

#### Notes

Dereferencing the end iterator is undefined behavior.

### operator->

#### Description

Accesses a member of the hook that the iterator currently points to.

#### Returns

A `pointer` to the element it currently points to.

#### Notes

If `*this` is the end iterator then the operation is undefined behavior.

## Incrementing

### operator++()

#### Description

Increments the iterator by 1, which means it moves to the next element in the container.

#### Returns

A reference to `*this`.

#### Notes

Incrementing past the end is undefined behavior.

### operator++(int)

#### Description

Post increments the iterator by 1, meaning it will move to the next element in the container but will return an iterator that points to the current element.

#### Returns

An iterator to the current element `*this` points to (before getting incremented).

#### Notes

Post incrementing past the end is undefined behavior.

## Conversion Operators

### operator list_iterator

#### Returns

A `list_iterator` to the element that `*this` currently points to. If `*this` is the end iterator then the `list_iterator` returned is either `eend()` or `dend()` depending on the state of the last element in the container.

### operator const_list_iterator

#### Returns

A `const_list_iterator` to the element that `*this` currently points to. If `*this` is the end iterator then the `const_list_iterator` returned is either `ceend()` or `cdend()` depending on the state of the last element in the container.

## Comparison

Two iterators compare equal if and only if they point to the same element. Comparing iterators of different instances of [hook_chain](hook_chain.md) is undefined behavior.
