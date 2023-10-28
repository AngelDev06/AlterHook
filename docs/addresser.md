# Addresser
A class that provides a few static methods that are used for getting the raw address of a method, whether the method is virtual or not.

## Synopsis
```cpp
namespace alterhook
{
  class addresser
  {
  public:
    template <typename T>
    static bool <pre><a href="#is_virtual">is_virtual</a></pre>(T memfuncptr);

    template <typename T>
    static uintptr_t address_of(T memfuncptr);

    template <typename T>
    static uintptr_t address_of_virtual(T memfuncptr);

    template <typename T>
    static uintptr_t address_of_regular(T memfuncptr);
  };
}
```

## Static Methods
### is_virtual