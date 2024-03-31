/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include <iterator>
#include <algorithm>
#include <sstream>
#include "other.h"

#if utils_msvc
  #pragma warning(push)
  #pragma warning(disable : 4018)
#endif

namespace alterhook::utils
{
  template <typename T, size_t N>
  class static_vector
  {
  public:
#ifndef NDEBUG
    class iterator;
    class const_iterator;
#else
    typedef T*       iterator;
    typedef const T* const_iterator;
#endif

    typedef T                                     value_type;
    typedef size_t                                size_type;
    typedef ptrdiff_t                             difference_type;
    typedef T*                                    pointer;
    typedef const T*                              const_pointer;
    typedef T&                                    reference;
    typedef const T&                              const_reference;
    typedef T&&                                   rvalue_reference;
    typedef std::reverse_iterator<iterator>       reverse_iterator;
    typedef std::reverse_iterator<const_iterator> const_reverse_iterator;

#if utils_cpp20
    template <typename itr, typename U = void>
    using at_least_forward_itr =
        std::enable_if_t<std::forward_iterator<itr>, U>;
#else
    template <typename itr, typename U = void>
    using at_least_forward_itr = U;
#endif

    static_vector() : count() {}

    static_vector(std::initializer_list<T> list) : count(list.size())
    {
      verify_len(list.size(), "list.size()");
      std::uninitialized_copy(list.begin(), list.end(), begin());
    }

    explicit static_vector(size_t count) : count(count)
    {
      verify_len(count, "count");
      std::uninitialized_value_construct(begin(), end());
    }

    template <typename itr, typename = at_least_forward_itr<itr>>
    static_vector(itr first, itr last) : count(std::distance(first, last))
    {
      verify_len(count, "std::distance(first, last)");
      std::uninitialized_copy(first, last, begin());
    }

    static_vector(const static_vector& other) : count(other.count)
    {
      std::uninitialized_copy(other.begin(), other.end(), begin());
    }

    static_vector(static_vector&& other) : count(other.count)
    {
      std::uninitialized_move(other.begin(), other.end(), begin());
      other.clear();
    }

    ~static_vector() { clear(); }

    iterator               begin() noexcept;
    const_iterator         begin() const noexcept;
    iterator               end() noexcept;
    const_iterator         end() const noexcept;
    reverse_iterator       rbegin() noexcept;
    const_reverse_iterator rbegin() const noexcept;
    reverse_iterator       rend() noexcept;
    const_reverse_iterator rend() const noexcept;
    const_iterator         cbegin() const noexcept;
    const_iterator         cend() const noexcept;
    const_reverse_iterator crbegin() const noexcept;
    const_reverse_iterator crend() const noexcept;

    bool empty() const noexcept { return !count; }

    operator bool() const noexcept { return !empty(); }

    size_t size() const noexcept { return count; }

    constexpr size_t max_size() { return N; }

    constexpr size_t capacity() { return max_size(); }

    pointer c_array() noexcept
    {
      return std::launder(reinterpret_cast<pointer>(data));
    }

    const_pointer c_array() const noexcept
    {
      return std::launder(reinterpret_cast<const_pointer>(data));
    }

    T& operator[](size_t pos) noexcept { return begin()[pos]; }

    const T& operator[](size_t pos) const noexcept { return begin()[pos]; }

    T& at(size_t pos)
    {
      verify_len(pos, "pos");
      return *std::launder(reinterpret_cast<pointer>(&data[pos]));
    }

    const T& at(size_t pos) const
    {
      verify_len(pos, "pos");
      return *std::launder(reinterpret_cast<const_pointer>(&data[pos]));
    }

    void clear()
    {
      std::destroy(begin(), end());
      count = 0;
    }

    template <typename... types>
    reference emplace_back(types&&... values);

    reference push_back(const_reference value);

    reference push_back(rvalue_reference value);

    template <typename... types>
    iterator emplace(iterator where, types&&... values);

    iterator insert(iterator where, const_reference val);

    iterator insert(iterator where, rvalue_reference val);

    iterator insert(iterator where, const size_t insert_count,
                    const_reference value);

    template <typename itr, typename = at_least_forward_itr<itr>>
    iterator insert(iterator where, itr first, itr last);

    iterator insert(iterator where, std::initializer_list<T> list);

    iterator
        erase(iterator where) noexcept(std::is_nothrow_move_assignable_v<T>);

    iterator erase(iterator first, iterator last);

    iterator pop_back();

    template <typename itr, typename = at_least_forward_itr<itr>>
    void assign(itr first, itr last);

    void assign(std::initializer_list<T> list);

    void assign(const size_t new_size, const_reference value);

    void resize(const size_t new_size);

    void resize(const size_t new_size, const_reference value);

    void swap(static_vector& other);

    static_vector& operator=(const static_vector& other);

    static_vector& operator=(static_vector&& other) noexcept(
        std::is_nothrow_move_assignable_v<T> &&
        std::is_nothrow_move_constructible_v<T>);

    static_vector& operator=(std::initializer_list<T> list);

  private:
    std::aligned_storage_t<sizeof(T), alignof(T)> data[N];
    size_t                                        count = 0;

    static void verify_len(size_t len, const char* str)
    {
      if (len > N)
      {
        std::stringstream stream{};
        stream << "static_vector: " << str << " > this->size() <=> " << len
               << " > " << N;
        throw(std::length_error(stream.str()));
      }
    }

#ifndef NDEBUG
    template <typename itr_t>
    static auto unwrap(const itr_t& itr)
    {
      return itr.unwrap();
    }
#else
    template <typename itr_t>
    static auto unwrap(itr_t ptr)
    {
      return ptr;
    }
#endif
  };

  template <typename first, typename... rest>
  static_vector(first, rest...)
      -> static_vector<std::common_type_t<first, rest...>, sizeof...(rest) + 1>;

#ifndef NDEBUG
  template <typename T, size_t N>
  class static_vector<T, N>::const_iterator
  {
  public:
  #if utils_cpp20
    typedef std::contiguous_iterator_tag iterator_concept;
  #endif
    typedef std::random_access_iterator_tag iterator_category;
    typedef T                               value_type;
    typedef ptrdiff_t                       difference_type;
    typedef const T*                        pointer;
    typedef const T&                        reference;

    constexpr const_iterator() noexcept = default;

    constexpr reference operator*() const noexcept { return *operator->(); }

    constexpr pointer operator->() const noexcept
    {
      utils_assert(
          ptr && pcount,
          "static_vector::iterator cannot dereference uninitialized iterator");
      utils_assert(index < *pcount, "static_vector::iterator: cannot "
                                    "dereference an out of range element");
      return ptr + index;
    }

    constexpr const_iterator& operator++() noexcept
    {
      utils_assert(
          ptr && pcount,
          "static_vector::iterator: cannot increment uninitialized iterator");
      utils_assert(
          index < *pcount,
          "static_vector::iterator: cannot increment iterator past end");
      ++index;
      return *this;
    }

    constexpr const_iterator operator++(int) noexcept
    {
      const_iterator tmp = *this;
      ++*this;
      return tmp;
    }

    constexpr const_iterator& operator--() noexcept
    {
      utils_assert(
          ptr && pcount,
          "static_vector::iterator: cannot decrement uninitialized iterator");
      utils_assert(
          index != 0,
          "static_vector::iterator: cannot decrement iterator before begin");
      --index;
      return *this;
    }

    constexpr const_iterator operator--(int) noexcept
    {
      const_iterator tmp = *this;
      --*this;
      return tmp;
    }

    constexpr const_iterator& operator+=(const ptrdiff_t offset) noexcept
    {
      verify_offset(offset);
      index += offset;
      return *this;
    }

    constexpr const_iterator& operator-=(const ptrdiff_t offset) noexcept
    {
      return *this += -offset;
    }

    constexpr ptrdiff_t operator-(const const_iterator& other) const noexcept
    {
      compat(other);
      return index - other.index;
    }

    constexpr reference operator[](const ptrdiff_t offset) const noexcept
    {
      return *(*this + offset);
    }

    constexpr bool operator==(const const_iterator& other) const noexcept
    {
      compat(other);
      return other.index == index;
    }

    constexpr bool operator<(const const_iterator& other) const noexcept
    {
      compat(other);
      return index < other.index;
    }

    constexpr const_iterator operator+(const ptrdiff_t offset) const noexcept
    {
      const_iterator tmp  = *this;
      tmp                += offset;
      return tmp;
    }

    constexpr const_iterator operator-(const ptrdiff_t offset) const noexcept
    {
      const_iterator tmp  = *this;
      tmp                -= offset;
      return tmp;
    }

    friend constexpr const_iterator operator+(const ptrdiff_t offset,
                                              const_iterator  itr) noexcept
    {
      itr += offset;
      return itr;
    }

    constexpr bool operator!=(const const_iterator& other) const noexcept
    {
      return !(*this == other);
    }

    constexpr bool operator>(const const_iterator& other) const noexcept
    {
      return other < *this;
    }

    constexpr bool operator<=(const const_iterator& other) const noexcept
    {
      return !(other < *this);
    }

    constexpr bool operator>=(const const_iterator& other) const noexcept
    {
      return !(*this < other);
    }

  private:
    const T*      ptr    = nullptr;
    size_t        index  = 0;
    const size_t* pcount = nullptr;

    template <typename U>
    friend struct std::pointer_traits;
    friend static_vector;
    friend iterator;

    constexpr explicit const_iterator(pointer ptr, size_t index,
                                      const size_t* pcount) noexcept
        : ptr(ptr), index(index), pcount(pcount)
    {
    }

    constexpr void verify_offset(const ptrdiff_t offset) const noexcept
    {
      if (offset != 0)
        utils_assert(
            ptr, "static_vector::iterator: cannot seek uninitialized iterator");

      if (offset < 0)
        utils_assert(
            index >= -offset,
            "static_vector::iterator: cannot seek iterator before begin");

      if (offset > 0)
        utils_assert(*pcount - index >= offset,
                     "static_vector::iterator: cannot seek iterator after end");
    }

    constexpr void compat(const const_iterator& itr) const noexcept
    {
      utils_assert(ptr == itr.ptr,
                   "static_vector::iterator: iterators are incompatible");
    }

    constexpr const T* unwrap() const noexcept { return ptr + index; }
  };

  template <typename T, size_t N>
  class static_vector<T, N>::iterator : public const_iterator
  {
  public:
    typedef const_iterator base;
  #if utils_cpp20
    typedef std::contiguous_iterator_tag iterator_concept;
  #endif
    typedef std::random_access_iterator_tag iterator_category;
    typedef T                               value_type;
    typedef ptrdiff_t                       difference_type;
    typedef T*                              pointer;
    typedef T&                              reference;

    constexpr iterator() noexcept = default;

    constexpr reference operator*() const noexcept
    {
      return const_cast<reference>(base::operator*());
    }

    constexpr pointer operator->() const noexcept
    {
      return const_cast<pointer>(base::operator->());
    }

    constexpr iterator& operator++() noexcept
    {
      base::operator++();
      return *this;
    }

    constexpr iterator operator++(int) noexcept
    {
      iterator tmp = *this;
      base::operator++();
      return tmp;
    }

    constexpr iterator& operator--() noexcept
    {
      base::operator--();
      return *this;
    }

    constexpr iterator operator--(int) noexcept
    {
      iterator tmp = *this;
      base::operator--();
      return tmp;
    }

    constexpr iterator& operator+=(const ptrdiff_t offset) noexcept
    {
      base::operator+=(offset);
      return *this;
    }

    constexpr iterator operator+(const ptrdiff_t offset) const noexcept
    {
      iterator tmp  = *this;
      tmp          += offset;
      return tmp;
    }

    friend constexpr iterator operator+(const ptrdiff_t offset,
                                        iterator        itr) noexcept
    {
      itr += offset;
      return itr;
    }

    constexpr iterator& operator-=(const ptrdiff_t offset) noexcept
    {
      base::operator-=(offset);
      return *this;
    }

    using base::operator-;

    constexpr iterator operator-(const ptrdiff_t offset) const noexcept
    {
      iterator tmp  = *this;
      tmp          -= offset;
      return tmp;
    }

    constexpr reference operator[](const ptrdiff_t offset) const noexcept
    {
      return const_cast<reference>(base::operator[](offset));
    }

  private:
    template <typename U>
    friend struct std::pointer_traits;
    friend static_vector;

    constexpr explicit iterator(pointer ptr, size_t index,
                                const size_t* pcount) noexcept
        : base(ptr, index, pcount)
    {
    }

    constexpr pointer unwrap() const noexcept
    {
      return const_cast<pointer>(base::unwrap());
    }
  };

  template <typename T, size_t N>
  typename static_vector<T, N>::iterator static_vector<T, N>::begin() noexcept
  {
    return iterator(std::launder(reinterpret_cast<pointer>(data)), 0, &count);
  }

  template <typename T, size_t N>
  typename static_vector<T, N>::const_iterator
      static_vector<T, N>::begin() const noexcept
  {
    return const_iterator(std::launder(reinterpret_cast<const_pointer>(data)),
                          0, &count);
  }

  template <typename T, size_t N>
  typename static_vector<T, N>::iterator static_vector<T, N>::end() noexcept
  {
    return iterator(std::launder(reinterpret_cast<pointer>(data)), count,
                    &count);
  }

  template <typename T, size_t N>
  typename static_vector<T, N>::const_iterator
      static_vector<T, N>::end() const noexcept
  {
    return const_iterator(std::launder(reinterpret_cast<const_pointer>(data)),
                          count, &count);
  }
#else
  template <typename T, size_t N>
  typename static_vector<T, N>::iterator static_vector<T, N>::begin() noexcept
  {
    return std::launder(reinterpret_cast<pointer>(data));
  }

  template <typename T, size_t N>
  typename static_vector<T, N>::const_iterator
      static_vector<T, N>::begin() const noexcept
  {
    return std::launder(reinterpret_cast<const_pointer>(data));
  }

  template <typename T, size_t N>
  typename static_vector<T, N>::iterator static_vector<T, N>::end() noexcept
  {
    return std::launder(reinterpret_cast<pointer>(data)) + count;
  }

  template <typename T, size_t N>
  typename static_vector<T, N>::const_iterator
      static_vector<T, N>::end() const noexcept
  {
    return std::launder(reinterpret_cast<const_pointer>(data)) + count;
  }
#endif

  template <typename T, size_t N>
  typename static_vector<T, N>::reverse_iterator
      static_vector<T, N>::rbegin() noexcept
  {
    return reverse_iterator(end());
  }

  template <typename T, size_t N>
  typename static_vector<T, N>::const_reverse_iterator
      static_vector<T, N>::rbegin() const noexcept
  {
    return const_reverse_iterator(end());
  }

  template <typename T, size_t N>
  typename static_vector<T, N>::reverse_iterator
      static_vector<T, N>::rend() noexcept
  {
    return reverse_iterator(begin());
  }

  template <typename T, size_t N>
  typename static_vector<T, N>::const_reverse_iterator
      static_vector<T, N>::rend() const noexcept
  {
    return const_reverse_iterator(begin());
  }

  template <typename T, size_t N>
  typename static_vector<T, N>::const_iterator
      static_vector<T, N>::cbegin() const noexcept
  {
    return begin();
  }

  template <typename T, size_t N>
  typename static_vector<T, N>::const_iterator
      static_vector<T, N>::cend() const noexcept
  {
    return end();
  }

  template <typename T, size_t N>
  typename static_vector<T, N>::const_reverse_iterator
      static_vector<T, N>::crbegin() const noexcept
  {
    return rbegin();
  }

  template <typename T, size_t N>
  typename static_vector<T, N>::const_reverse_iterator
      static_vector<T, N>::crend() const noexcept
  {
    return rend();
  }

  template <typename T, size_t N>
  typename static_vector<T, N>::reference
      static_vector<T, N>::push_back(const_reference value)
  {
    return emplace_back(value);
  }

  template <typename T, size_t N>
  typename static_vector<T, N>::reference
      static_vector<T, N>::push_back(rvalue_reference value)
  {
    return emplace_back(std::move(value));
  }

  template <typename T, size_t N>
  typename static_vector<T, N>::iterator
      static_vector<T, N>::insert(iterator where, const_reference val)
  {
    return emplace(where, val);
  }

  template <typename T, size_t N>
  typename static_vector<T, N>::iterator
      static_vector<T, N>::insert(iterator where, rvalue_reference val)
  {
    return emplace(where, std::move(val));
  }

  template <typename T, size_t N>
  typename static_vector<T, N>::iterator
      static_vector<T, N>::insert(iterator where, const size_t insert_count,
                                  const_reference value)
  {
    if (!insert_count)
      return where;
    verify_len(insert_count + count, "(insert_count + count");
    const size_t affected_elements = end() - where;
    if (insert_count > affected_elements)
    {
      std::uninitialized_move(
          where, end(),
          std::uninitialized_fill_n(unwrap(end()),
                                    insert_count - affected_elements, value));
      std::fill(where, end(), value);
    }
    else
    {
      std::uninitialized_move((end() - insert_count), end(), unwrap(end()));
      auto where_end = std::move_backward(where, (end() - insert_count), end());
      std::fill(where, where_end, value);
    }
    count += insert_count;
    return where;
  }

  template <typename T, size_t N>
  typename static_vector<T, N>::iterator
      static_vector<T, N>::insert(iterator where, std::initializer_list<T> list)
  {
    return insert(where, list.begin(), list.end());
  }

  template <typename T, size_t N>
  typename static_vector<T, N>::iterator static_vector<T, N>::erase(
      iterator where) noexcept(std::is_nothrow_move_assignable_v<T>)
  {
    std::move((where + 1), end(), where);
    std::destroy_at(unwrap(end() - 1));
    --count;
    return where;
  }

  template <typename T, size_t N>
  typename static_vector<T, N>::iterator
      static_vector<T, N>::erase(iterator first, iterator last)
  {
    if (first != last)
    {
      const auto res = std::move(last, end(), first);
      std::destroy(res, end());
      count = res - begin();
    }
    return first;
  }

  template <typename T, size_t N>
  typename static_vector<T, N>::iterator static_vector<T, N>::pop_back()
  {
    --count;
    std::destroy_at(unwrap(end()));
    return end();
  }

  template <typename T, size_t N>
  void static_vector<T, N>::assign(std::initializer_list<T> list)
  {
    assign(list.begin(), list.end());
  }

  template <typename T, size_t N>
  void static_vector<T, N>::assign(const size_t new_size, const_reference value)
  {
    if (!new_size)
    {
      clear();
      return;
    }

    verify_len(new_size, "new_size");
    if (new_size > count)
    {
      std::fill(begin(), end(), value);
      std::uninitialized_fill_n(unwrap(end()), new_size - count, value);
    }
    else
    {
      auto new_last = std::fill_n(begin(), new_size, value);
      std::destroy(new_last, end());
    }
    count = new_size;
  }

  template <typename T, size_t N>
  void static_vector<T, N>::resize(const size_t new_size)
  {
    if (new_size == count)
      return;
    if (new_size > count)
    {
      verify_len(new_size, "new_size");
      std::uninitialized_value_construct_n(unwrap(end()), new_size - count);
    }
    else
      std::destroy((begin() + new_size), end());
    count = new_size;
  }

  template <typename T, size_t N>
  void static_vector<T, N>::resize(const size_t new_size, const_reference value)
  {
    if (new_size == count)
      return;
    if (new_size > count)
    {
      verify_len(new_size, "new_size");
      std::uninitialized_fill_n(unwrap(end()), new_size - count, value);
    }
    else
      std::destroy((begin() + new_size), end());
    count = new_size;
  }

  template <typename T, size_t N>
  void static_vector<T, N>::swap(static_vector& other)
  {
    if (this == &other)
      return;
    if (other.count > count)
    {
      auto other_loc = std::swap_ranges(begin(), end(), other.begin());
      std::move(other_loc, other.end(), unwrap(end()));
      std::destroy(other_loc, other.end());
    }
    else if (other.count < count)
    {
      auto current_loc = std::swap_ranges(other.begin(), other.end(), begin());
      std::move(current_loc, end(), unwrap(other.end()));
      std::destroy(current_loc, end());
    }
    else
      std::swap_ranges(begin(), end(), other.begin());
    std::swap(count, other.count);
  }

  template <typename T, size_t N>
  static_vector<T, N>&
      static_vector<T, N>::operator=(const static_vector& other)
  {
    if (this != &other)
      assign(other.begin(), other.end());
    return *this;
  }

  template <typename T, size_t N>
  static_vector<T, N>& static_vector<T, N>::operator=(
      static_vector&& other) noexcept(std::is_nothrow_move_assignable_v<T> &&
                                      std::is_nothrow_move_constructible_v<T>)
  {
    if (this == &other)
      return *this;
    if (other.count > count)
    {
      std::move(other.begin(), (other.begin() + count), begin());
      std::uninitialized_move((other.begin() + count), other.end(),
                              unwrap(end()));
    }
    else
    {
      std::move(other.begin(), other.end(), begin());
      std::destroy((begin() + other.count), end());
    }
    count = other.count;
    other.clear();
    return *this;
  }

  template <typename T, size_t N>
  static_vector<T, N>&
      static_vector<T, N>::operator=(std::initializer_list<T> list)
  {
    assign(list.begin(), list.end());
    return *this;
  }

  template <typename T, size_t N>
  template <typename... types>
  typename static_vector<T, N>::reference
      static_vector<T, N>::emplace_back(types&&... values)
  {
    verify_len(count + 1, "(count + 1)");
    pointer res = new (unwrap(end())) T{ std::forward<types>(values)... };
    ++count;
    return *res;
  }

  template <typename T, size_t N>
  template <typename... types>
  typename static_vector<T, N>::iterator
      static_vector<T, N>::emplace(iterator where, types&&... values)
  {
    verify_len(count + 1, "(count + 1)");
    if (where != end())
    {
      new (unwrap(end())) T{ std::move(*(end() - 1)) };
      std::move_backward(where, (end() - 1), end());
      *where = T{ std::forward<types>(values)... };
    }
    else
      new (unwrap(end())) T{ std::forward<types>(values)... };
    ++count;
    return where;
  }

  template <typename T, size_t N>
  template <typename itr, typename>
  typename static_vector<T, N>::iterator
      static_vector<T, N>::insert(iterator where, itr first, itr last)
  {
    const auto len = std::distance(first, last);
    if (!len)
      return where;
    verify_len(count + len, "count + std::distance(first, last)");
    const size_t affected_elements = end() - where;
    if (len < affected_elements)
    {
      pointer new_last =
          std::uninitialized_move((end() - len), end(), unwrap(end()));
      pointer new_loc = std::move_backward(where, (end() - len), unwrap(end()));
      std::destroy(unwrap(where), new_loc);

      try
      {
        std::uninitialized_copy(std::move(first), std::move(last), where);
      }
      catch (...)
      {
        try
        {
          std::uninitialized_move(new_loc, unwrap(end()), where);
        }
        catch (...)
        {
          std::destroy(new_loc, new_last);
          count = where - begin();
          throw;
        }
        std::destroy(unwrap(end()), new_last);
        throw;
      }
    }
    else
    {
      pointer new_loc  = unwrap(where) + len;
      pointer new_last = std::uninitialized_move(where, end(), new_loc);
      std::destroy(where, end());

      try
      {
        std::uninitialized_copy(std::move(first), std::move(last),
                                unwrap(where));
      }
      catch (...)
      {
        try
        {
          std::uninitialized_move(new_loc, new_last, where);
        }
        catch (...)
        {
          std::destroy(new_loc, new_last);
          count = where - begin();
          throw;
        }
        std::destroy(new_loc, new_last);
        throw;
      }
    }
    count += len;
    return where;
  }

  template <typename T, size_t N>
  template <typename itr, typename>
  void static_vector<T, N>::assign(itr first, itr last)
  {
    const auto len = std::distance(first, last);
    if (!len)
    {
      clear();
      return;
    }

    verify_len(len, "std::distance(first, last)");
    if (len > count)
    {
      std::copy_n(first, count, begin());
      std::advance(first, count);
      std::uninitialized_copy(std::move(first), std::move(last), unwrap(end()));
    }
    else
    {
      auto new_last = std::copy(std::move(first), std::move(last), begin());
      std::destroy(new_last, end());
    }
    count = len;
  }
} // namespace alterhook::utils

#if utils_msvc
  #pragma warning(pop)
#endif
