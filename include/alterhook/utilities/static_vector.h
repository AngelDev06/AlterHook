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

#if utils_cpp20
  #define __utils_mustbefwditr std::forward_iterator
#else
  #define __utils_mustbefwditr typename
#endif

namespace utils
{
  template <typename T, size_t N>
  class static_vector;

  namespace helpers
  {
    template <typename T, size_t N>
    class static_vector_const_iterator
    {
    private:
      const T* ptr;
#ifndef NDEBUG
      size_t        index;
      const size_t* count;
#endif
#if utils_cpp20
      template <typename U>
      friend struct std::pointer_traits;
#endif
      template <typename U, size_t M>
      friend class utils::static_vector;
      template <typename U, size_t M>
      friend class static_vector_iterator;

#ifndef NDEBUG
      constexpr void verify_offset(const ptrdiff_t offset) const noexcept
      {
        if (offset != 0)
          utils_assert(
              ptr,
              "static_vector::iterator: cannot seek uninitialized iterator");

        if (offset < 0)
          utils_assert(
              index >= -offset,
              "static_vector::iterator: cannot seek iterator before begin");

        if (offset > 0)
          utils_assert(
              *count - index >= offset,
              "static_vector::iterator: cannot seek iterator after end");
      }

      constexpr void
          compat(const static_vector_const_iterator& itr) const noexcept
      {
        utils_assert(ptr == itr.ptr,
                     "static_vector::iterator: iterators are incompatible");
      }

      constexpr const T* unwrap() const noexcept { return ptr + index; }
#else
      constexpr const T* unwrap() const noexcept { return ptr; }
#endif
    public:
#if utils_cpp20
      typedef std::contiguous_iterator_tag iterator_concept;
#endif
      typedef std::random_access_iterator_tag iterator_category;
      typedef T                               value_type;
      typedef ptrdiff_t                       difference_type;
      typedef const T*                        pointer;
      typedef const T&                        reference;

#ifndef NDEBUG
      constexpr static_vector_const_iterator() noexcept
          : ptr(), index(), count()
      {
      }

      constexpr explicit static_vector_const_iterator(
          pointer ptr, const size_t* size = nullptr, size_t offset = 0) noexcept
          : ptr(ptr), index(offset), count(size)
      {
      }

      constexpr reference operator*() const noexcept { return *operator->(); }

      constexpr pointer operator->() const noexcept
      {
        utils_assert(ptr && count, "static_vector::iterator: cannot "
                                   "dereference uninitialized iterator");
        utils_assert(index < *count, "static_vector::iterator: cannot "
                                     "dereference an out of range element");
        return ptr + index;
      }

      constexpr static_vector_const_iterator& operator++() noexcept
      {
        utils_assert(
            ptr && count,
            "static_vector::iterator: cannot increment uninitialized iterator");
        utils_assert(
            index < *count,
            "static_vector::iterator: cannot increment iterator past end");
        ++index;
        return *this;
      }

      constexpr static_vector_const_iterator operator++(int) noexcept
      {
        static_vector_const_iterator tmp = *this;
        ++*this;
        return tmp;
      }

      constexpr static_vector_const_iterator& operator--() noexcept
      {
        utils_assert(
            ptr && count,
            "static_vector::iterator: cannot decrement uninitialized iterator");
        utils_assert(
            index != 0,
            "static_vector::iterator: cannot decrement iterator before begin");
        --index;
        return *this;
      }

      constexpr static_vector_const_iterator operator--(int) noexcept
      {
        static_vector_const_iterator tmp = *this;
        --*this;
        return tmp;
      }

      constexpr static_vector_const_iterator&
          operator+=(const ptrdiff_t offset) noexcept
      {
        verify_offset(offset);
        index += offset;
        return *this;
      }

      constexpr static_vector_const_iterator&
          operator-=(const ptrdiff_t offset) noexcept
      {
        return *this += -offset;
      }

      constexpr ptrdiff_t
          operator-(const static_vector_const_iterator& itr) const noexcept
      {
        compat(itr);
        return index - itr.index;
      }

      constexpr reference operator[](const ptrdiff_t offset) const noexcept
      {
        return *(*this + offset);
      }

      constexpr bool
          operator==(const static_vector_const_iterator& itr) const noexcept
      {
        compat(itr);
        return itr.index == index;
      }
  #if utils_cpp20
      constexpr auto
          operator<=>(const static_vector_const_iterator& itr) const noexcept
      {
        compat(itr);
        return itr.index <=> index;
      }
  #else
      constexpr bool
          operator<(const static_vector_const_iterator& itr) const noexcept
      {
        compat(itr);
        return index < itr.index;
      }
  #endif
#else
      constexpr static_vector_const_iterator() noexcept : ptr() {}

      constexpr explicit static_vector_const_iterator(
          pointer ptr, size_t offset = 0) noexcept
          : ptr(ptr + offset)
      {
      }

      constexpr reference operator*() const noexcept { return *ptr; }

      constexpr pointer operator->() const noexcept { return ptr; }

      constexpr static_vector_const_iterator& operator++() noexcept
      {
        ++ptr;
        return *this;
      }

      constexpr static_vector_const_iterator operator++(int) noexcept
      {
        static_vector_const_iterator tmp = *this;
        ++ptr;
        return tmp;
      }

      constexpr static_vector_const_iterator& operator--() noexcept
      {
        --ptr;
        return *this;
      }

      constexpr static_vector_const_iterator operator--(int) noexcept
      {
        static_vector_const_iterator tmp = *this;
        --ptr;
        return tmp;
      }

      constexpr static_vector_const_iterator&
          operator+=(ptrdiff_t offset) noexcept
      {
        ptr += offset;
        return *this;
      }

      constexpr static_vector_const_iterator&
          operator-=(ptrdiff_t offset) noexcept
      {
        ptr -= offset;
        return *this;
      }

      constexpr ptrdiff_t
          operator-(const static_vector_const_iterator& itr) const noexcept
      {
        return ptr - itr.ptr;
      }

      constexpr reference operator[](const ptrdiff_t offset) const noexcept
      {
        return ptr[offset];
      }

      constexpr bool
          operator==(const static_vector_const_iterator& itr) const noexcept
      {
        return ptr == itr.ptr;
      }
  #if utils_cpp20
      constexpr auto
          operator<=>(const static_vector_const_iterator& itr) const noexcept
      {
        return ptr <=> itr.ptr;
      }
  #else
      constexpr bool
          operator<(const static_vector_const_iterator& itr) const noexcept
      {
        return ptr < itr.ptr;
      }
  #endif
#endif
      constexpr static_vector_const_iterator
          operator+(const ptrdiff_t offset) const noexcept
      {
        static_vector_const_iterator tmp  = *this;
        tmp                              += offset;
        return tmp;
      }

      constexpr static_vector_const_iterator
          operator-(const ptrdiff_t offset) const noexcept
      {
        static_vector_const_iterator tmp  = *this;
        tmp                              -= offset;
        return tmp;
      }

      friend constexpr static_vector_const_iterator
          operator+(const ptrdiff_t              offset,
                    static_vector_const_iterator itr) noexcept
      {
        itr += offset;
        return itr;
      }

#if !utils_cpp20
      constexpr bool
          operator!=(const static_vector_const_iterator& itr) const noexcept
      {
        return !(*this == itr);
      }

      constexpr bool
          operator>(const static_vector_const_iterator& itr) const noexcept
      {
        return itr < *this;
      }

      constexpr bool
          operator<=(const static_vector_const_iterator& itr) const noexcept
      {
        return !(itr < *this);
      }

      constexpr bool
          operator>=(const static_vector_const_iterator& itr) const noexcept
      {
        return !(*this < itr);
      }
#endif
    };

    template <typename T, size_t N>
    class static_vector_iterator : public static_vector_const_iterator<T, N>
    {
    public:
      typedef static_vector_const_iterator<T, N> base;
#if utils_cpp20
      typedef std::contiguous_iterator_tag iterator_concept;
#endif
      typedef std::random_access_iterator_tag iterator_category;
      typedef T                               value_type;
      typedef ptrdiff_t                       difference_type;
      typedef T*                              pointer;
      typedef T&                              reference;

      constexpr static_vector_iterator() noexcept {}

      constexpr explicit static_vector_iterator(pointer       ptr,
                                                const size_t* size = nullptr,
                                                size_t offset      = 0) noexcept
          : base(ptr, size, offset)
      {
      }

      constexpr reference operator*() const noexcept
      {
        return const_cast<reference>(base::operator*());
      }

      constexpr pointer operator->() const noexcept
      {
        return const_cast<pointer>(base::operator->());
      }

      constexpr static_vector_iterator& operator++() noexcept
      {
        base::operator++();
        return *this;
      }

      constexpr static_vector_iterator operator++(int) noexcept
      {
        static_vector_iterator tmp = *this;
        base::operator++();
        return tmp;
      }

      constexpr static_vector_iterator& operator--() noexcept
      {
        base::operator--();
        return *this;
      }

      constexpr static_vector_iterator operator--(int) noexcept
      {
        static_vector_iterator tmp = *this;
        base::operator--();
        return tmp;
      }

      constexpr static_vector_iterator&
          operator+=(const ptrdiff_t offset) noexcept
      {
        base::operator+=(offset);
        return *this;
      }

      constexpr static_vector_iterator
          operator+(const ptrdiff_t offset) const noexcept
      {
        static_vector_iterator tmp  = *this;
        tmp                        += offset;
        return tmp;
      }

      friend constexpr static_vector_iterator
          operator+(const ptrdiff_t offset, static_vector_iterator itr) noexcept
      {
        itr += offset;
        return itr;
      }

      constexpr static_vector_iterator&
          operator-=(const ptrdiff_t offset) noexcept
      {
        base::operator-=(offset);
        return *this;
      }

      using base::operator-;

      constexpr static_vector_iterator
          operator-(const ptrdiff_t offset) const noexcept
      {
        static_vector_iterator tmp  = *this;
        tmp                        -= offset;
        return tmp;
      }

      constexpr reference operator[](const ptrdiff_t offset) const noexcept
      {
        return const_cast<reference>(base::operator[](offset));
      }

    private:
#if utils_cpp20
      template <typename U>
      friend struct std::pointer_traits;
#endif
      template <typename U, size_t M>
      friend class utils::static_vector;

      constexpr pointer unwrap() const noexcept
      {
        return const_cast<pointer>(base::unwrap());
      }
    };
  } // namespace helpers

  template <typename T, size_t N>
  class static_vector
  {
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

  public:
    typedef T                                           value_type;
    typedef size_t                                      size_type;
    typedef ptrdiff_t                                   difference_type;
    typedef T*                                          pointer;
    typedef const T*                                    const_pointer;
    typedef T&                                          reference;
    typedef const T&                                    const_reference;
    typedef T&&                                         rvalue_reference;
    typedef helpers::static_vector_iterator<T, N>       iterator;
    typedef helpers::static_vector_const_iterator<T, N> const_iterator;
    typedef std::reverse_iterator<iterator>             reverse_iterator;
    typedef std::reverse_iterator<const_iterator>       const_reverse_iterator;

    // none of the bellow is marked as constexpr simply because c++ malds when
    // reinterpret_cast is being used at compile time. use an actual vector if
    // you want compile time behaviour, this is meant for runtime performance
    static_vector() : count() {}

    static_vector(std::initializer_list<T> list) : count(list.size())
    {
      verify_len(list.size(), "list.size()");
      std::uninitialized_copy(list.begin(), list.end(), begin().unwrap());
    }

    explicit static_vector(size_t count) : count(count)
    {
      verify_len(count, "count");
      std::uninitialized_value_construct(begin().unwrap(), end().unwrap());
    }

    template <__utils_mustbefwditr itr>
    static_vector(itr first, itr last) : count(std::distance(first, last))
    {
      verify_len(count, "std::distance(first, last)");
      std::uninitialized_copy(first, last, begin().unwrap());
    }

    static_vector(const static_vector& other) : count(other.count)
    {
      std::uninitialized_copy(other.begin().unwrap(), other.end().unwrap(),
                              begin().unwrap());
    }

    static_vector(static_vector&& other) : count(other.count)
    {
      std::uninitialized_move(other.begin().unwrap(), other.end().unwrap(),
                              begin().unwrap());
      other.clear();
    }

    ~static_vector() { clear(); }

    iterator begin() noexcept
    {
      return iterator(std::launder(reinterpret_cast<pointer>(data)), &count, 0);
    }

    const_iterator begin() const noexcept
    {
      return const_iterator(std::launder(reinterpret_cast<const_pointer>(data)),
                            &count, 0);
    }

    iterator end() noexcept
    {
      return iterator(std::launder(reinterpret_cast<pointer>(data)), &count,
                      count);
    }

    const_iterator end() const noexcept
    {
      return const_iterator(std::launder(reinterpret_cast<const_pointer>(data)),
                            &count, count);
    }

    reverse_iterator rbegin() noexcept { return reverse_iterator(end()); }

    const_reverse_iterator rbegin() const noexcept
    {
      return const_reverse_iterator(end());
    }

    reverse_iterator rend() noexcept { return reverse_iterator(begin()); }

    const_reverse_iterator rend() const noexcept
    {
      return const_reverse_iterator(begin());
    }

    const_iterator cbegin() const noexcept { return begin(); }

    const_iterator cend() const noexcept { return end(); }

    const_reverse_iterator crbegin() const noexcept { return rbegin(); }

    const_reverse_iterator crend() const noexcept { return rend(); }

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

    T& operator[](size_t pos) noexcept
    {
      return *std::launder(reinterpret_cast<pointer>(&data[pos]));
    }

    const T& operator[](size_t pos) const noexcept
    {
      return *std::launder(reinterpret_cast<const_pointer>(&data[pos]));
    }

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
      std::destroy(begin().unwrap(), end().unwrap());
      count = 0;
    }

    template <typename... types>
    reference emplace_back(types&&... values)
    {
      verify_len(count + 1, "(count + 1)");
      pointer res = new (end().unwrap()) T{ std::forward<types>(values)... };
      ++count;
      return *res;
    }

    reference push_back(const_reference value) { return emplace_back(value); }

    reference push_back(rvalue_reference value)
    {
      return emplace_back(std::move(value));
    }

    template <typename... types>
    iterator emplace(iterator where, types&&... values)
    {
      verify_len(count + 1, "(count + 1)");
      if (where != end())
      {
        new (end().unwrap()) T{ std::move(*(end() - 1)) };
        std::move_backward(where.unwrap(), (end() - 1).unwrap(),
                           end().unwrap());
        *where = T{ std::forward<types>(values)... };
      }
      else
        new (end().unwrap()) T{ std::forward<types>(values)... };
      ++count;
      return where;
    }

    iterator insert(iterator where, const_reference val)
    {
      return emplace(where, val);
    }

    iterator insert(iterator where, rvalue_reference val)
    {
      return emplace(where, std::move(val));
    }

    iterator insert(iterator where, const size_t insert_count,
                    const_reference value)
    {
      if (insert_count)
      {
        verify_len(insert_count + count, "(insert_count + count");
        const size_t affected_elements = end() - where;
        if (insert_count > affected_elements)
        {
          std::uninitialized_move(
              where.unwrap(), end().unwrap(),
              std::uninitialized_fill_n(
                  end().unwrap(), insert_count - affected_elements, value));
          std::fill(where.unwrap(), end().unwrap(), value);
        }
        else
        {
          std::uninitialized_move((end() - insert_count).unwrap(),
                                  end().unwrap(), end().unwrap());
          std::move_backward(where.unwrap(), (end() - insert_count).unwrap(),
                             end().unwrap());
          std::fill(where.unwrap(), (where + insert_count).unwrap(), value);
        }
        count += insert_count;
      }
      return where;
    }

    template <__utils_mustbefwditr itr>
    iterator insert(iterator where, itr first, itr last)
    {
      const auto len = std::distance(first, last);
      if (len)
      {
        verify_len(count + len, "count + std::distance(first, last)");
        const size_t affected_elements = end() - where;
        if (len < affected_elements)
        {
          pointer new_last = std::uninitialized_move(
              (end() - len).unwrap(), end().unwrap(), end().unwrap());
          std::move_backward(where.unwrap(), (end() - len).unwrap(),
                             end().unwrap());
          std::destroy(where.unwrap(), where.unwrap() + len);

          try
          {
            std::uninitialized_copy(std::move(first), std::move(last),
                                    where.unwrap());
          }
          catch (...)
          {
            try
            {
              std::uninitialized_move(where.unwrap() + len,
                                      where.unwrap() + 2 * len, where.unwrap());
            }
            catch (...)
            {
              std::destroy(where.unwrap() + len, new_last);
              count = where - begin();
              throw;
            }
            std::move(where.unwrap() + 2 * len, new_last, where.unwrap() + len);
            std::destroy(end().unwrap(), new_last);
            throw;
          }
        }
        else
        {
          pointer new_loc = where.unwrap() + len;
          pointer new_last =
              std::uninitialized_move(where.unwrap(), end().unwrap(), new_loc);
          std::destroy(where.unwrap(), end().unwrap());

          try
          {
            std::uninitialized_copy(std::move(first), std::move(last),
                                    where.unwrap());
          }
          catch (...)
          {
            try
            {
              std::uninitialized_move(new_loc, new_last, where.unwrap());
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
      }
      return where;
    }

    iterator insert(iterator where, std::initializer_list<T> list)
    {
      return insert(where, list.begin(), list.end());
    }

    iterator
        erase(iterator where) noexcept(std::is_nothrow_move_assignable_v<T>)
    {
      std::move((where + 1).unwrap(), end().unwrap(), where.unwrap());
      std::destroy_at((end() - 1).unwrap());
      --count;
      return where;
    }

    iterator erase(iterator first, iterator last)
    {
      if (first != last)
      {
        const pointer res =
            std::move(last.unwrap(), end().unwrap(), first.unwrap());
        std::destroy(res, end().unwrap());
        count = res - begin().unwrap();
      }
      return first;
    }

    iterator pop_back()
    {
      --count;
      std::destroy_at(end().unwrap());
      return end();
    }

    template <__utils_mustbefwditr itr>
    void assign(itr first, itr last)
    {
      const auto len = std::distance(first, last);
      if (len)
      {
        verify_len(len, "std::distance(first, last)");
        if (len > count)
        {
          std::copy_n(first, count, begin().unwrap());
          std::advance(first, count);
          std::uninitialized_copy(std::move(first), std::move(last),
                                  end().unwrap());
        }
        else
        {
          pointer new_last =
              std::copy(std::move(first), std::move(last), begin().unwrap());
          std::destroy(new_last, end().unwrap());
        }
        count = len;
      }
      else
        clear();
    }

    void assign(std::initializer_list<T> list)
    {
      assign(list.begin(), list.end());
    }

    void assign(const size_t new_size, const_reference value)
    {
      if (new_size)
      {
        verify_len(new_size, "new_size");
        if (new_size > count)
        {
          std::fill(begin().unwrap(), end().unwrap(), value);
          std::uninitialized_fill_n(end().unwrap(), new_size - count, value);
        }
        else
        {
          pointer new_last = std::fill_n(begin().unwrap(), new_size);
          std::destroy(new_last, end().unwrap());
        }
        count = new_size;
      }
      else
        clear();
    }

    void resize(const size_t new_size)
    {
      if (new_size != count)
      {
        if (new_size > count)
        {
          verify_len(new_size, "new_size");
          std::uninitialized_value_construct_n(end().unwrap(),
                                               new_size - count);
        }
        else
          std::destroy((begin() + new_size).unwrap(), end().unwrap());
        count = new_size;
      }
    }

    void resize(const size_t new_size, const_reference value)
    {
      if (new_size != count)
      {
        if (new_size > count)
        {
          verify_len(new_size, "new_size");
          std::uninitialized_fill_n(end().unwrap(), new_size - count, value);
        }
        else
          std::destroy((begin() + new_size).unwrap(), end().unwrap());
        count = new_size;
      }
    }

    void swap(static_vector& other)
    {
      if (this != &other)
      {
        if (other.count > count)
        {
          std::swap_ranges(begin().unwrap(), end().unwrap(),
                           other.begin().unwrap());
          std::move((other.begin() + count).unwrap(), other.end().unwrap(),
                    end().unwrap());
          std::destroy((other.begin() + count).unwrap(), other.end().unwrap());
        }
        else if (other.count < count)
        {
          std::swap_ranges(other.begin().unwrap(), other.end().unwrap(),
                           begin().unwrap());
          std::move((begin() + other.count).unwrap(), end().unwrap(),
                    other.end().unwrap());
          std::destroy((begin() + other.count).unwrap(), end().unwrap());
        }
        else
          std::swap_ranges(begin().unwrap(), end().unwrap(),
                           other.begin().unwrap());
        std::swap(count, other.count);
      }
    }

    static_vector& operator=(const static_vector& other)
    {
      if (this != &other)
        assign(other.begin().unwrap(), other.end().unwrap());
      return *this;
    }

    static_vector& operator=(static_vector&& other) noexcept(
        std::is_nothrow_move_assignable_v<T>&&
            std::is_nothrow_move_constructible_v<T>)
    {
      if (this != &other)
      {
        if (other.count > count)
        {
          std::move(other.begin().unwrap(), (other.begin() + count).unwrap(),
                    begin().unwrap());
          std::uninitialized_move((other.begin() + count).unwrap(),
                                  other.end().unwrap(), end().unwrap());
        }
        else
        {
          std::move(other.begin().unwrap(), other.end().unwrap(),
                    begin().unwrap());
          std::destroy((begin() + other.count).unwrap(), end().unwrap());
        }
        count = other.count;
        other.clear();
      }
      return *this;
    }

    static_vector& operator=(std::initializer_list<T> list)
    {
      assign(list.begin(), list.end());
      return *this;
    }
  };

  namespace helpers
  {
    template <bool are_same, typename... types>
    struct enforce_same
    {
      static_assert(are_same, "static_vector: deduction guide requires all "
                              "types during initialization to be the same");
    };

    template <typename first, typename... rest>
    struct enforce_same<true, first, rest...>
    {
      typedef remove_cvref_t<first> type;
    };

    template <typename first, typename... rest>
    using enforce_same_t = typename enforce_same<
        (std::is_same_v<remove_cvref_t<first>, remove_cvref_t<rest>> && ...),
        first, rest...>::type;
  } // namespace helpers

  template <typename first, typename... rest>
  static_vector(first, rest...)
      -> static_vector<helpers::enforce_same_t<first, rest...>,
                       sizeof...(rest) + 1>;
} // namespace utils

namespace std
{
#if utils_cpp20
  template <typename T, size_t size>
  struct pointer_traits<utils::helpers::static_vector_const_iterator<T, size>>
  {
    typedef utils::helpers::static_vector_const_iterator<T, size> pointer;
    typedef const T                                               element_type;
    typedef ptrdiff_t difference_type;

    static constexpr element_type* to_address(const pointer itr) noexcept
    {
      return itr.unwrap();
    }
  };

  template <typename T, size_t size>
  struct pointer_traits<utils::helpers::static_vector_iterator<T, size>>
  {
    typedef utils::helpers::static_vector_iterator<T, size> pointer;
    typedef T                                               element_type;
    typedef ptrdiff_t                                       difference_type;

    static constexpr element_type* to_address(const pointer itr) noexcept
    {
      return itr.unwrap();
    }
  };
#endif
} // namespace std

#if utils_msvc
  #pragma warning(pop)
#endif
