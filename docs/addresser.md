# Addresser
A class that provides a few static methods that are used for getting the raw address of a method, whether the method is virtual or not.

## Synopsis
<pre>
 <code>
namespace alterhook
{
  template &lt;typename T&gt;
  struct <a href="#instanceptrof">instanceptrof</a>;

  class addresser
  {
  public:
    template &lt;typename T&gt;
    static bool <a href="#is_virtual">is_virtual</a>(T memfuncptr);

    template &lt;typename T&gt;
    static uintptr_t <a href="#address_of">address_of</a>(T memfuncptr);

    template &lt;typename T&gt;
    static uintptr_t <a href="#address_of_virtual">address_of_virtual</a>(T memfuncptr);

    template &lt;typename T&gt;
    static uintptr_t address_of_regular(T memfuncptr);
  };
}
 </code>
</pre>

## Static Methods
### is_virtual
#### Description
A method that returns whether the given member function pointer points to a virtual method.
#### Parameters
| Parameter | Type | Description |
| --- | --- | --- |
| memfuncptr | T (any) | The member function pointer to use |
#### Returns
A boolean that's true when the member function pointer passed points to a virtual method, otherwise false
#### Notes
This is implemented for every compiler and platform except for windows clang. The reason being that clang on windows generates a large vcall thunk on debug builds that it's hard to tell whether it is actually a vcall thunk. Any help implementing it is appreciated!
### address_of
#### Description
A method that returns the raw address of a member function pointer. It works for both virtual methods and non-virtual ones as it uses `is_virtual` to tell how to deal with the argument passed.
#### Parameters
| Parameter | Type | Description |
| --- | --- | --- |
| memfuncptr | T (any) | The member function pointer to use |
#### Returns
The raw address of the member function pointer passed represented as `uintptr_t` (aka an unsigned integral type large enough to hold a pointer).
#### Notes
Since `is_virtual` is not implemented for windows clang this method will also not work in that case.
### address_of_virtual
#### Description
A method that returns the raw address of a virtual member function pointer. It only works for virtual ones unlike `address_of` so don't use it with anything else.
#### Parameters
| Parameter | Type | Description |
| --- | --- | --- |
| memfuncptr | T (any) | The member function pointer to use |
#### Returns
The raw address of the virtual member function pointer passed represented as `uintptr_t` (aka an unsigned integral type large enough to hold a pointer).
### address_of_regular
#### Description
A method that returns the raw address of a regular member function pointer. It only works for regular ones unlike `address_of` so don't use it with anything else.
#### Parameters
| Parameter | Type | Description |
| --- | --- | --- |
| memfuncptr | T (any) | The member function pointer to use |
#### Returns
The raw address of the regular member function pointer passed represented as `uintptr_t` (aka an unsigned integral type large enough to hold a pointer).
## Non-member Classes/Structs
### instanceptrof
#### Description
A struct that can be partially specialized to let the user provide the instance that `address_of_virtual` will use in order to avoid any unintended behavior. The reason this struct exists is because in order for `address_of_virtual` to lookup the vtable it has to heap allocate some memory and place a move constructed "fake" instance. And by that it manages to get back a valid vpointer to make use of.
#### Examples
```cpp
template <>
struct instanceptrof<float>
{
  float* operator()() { return new float{}; }
};
```
## Credits
Big thanks to [alk](https://github.com/altalk23) for providing an [implementation](https://gist.github.com/altalk23/29b97969e9f0624f783b673f6c1cd279) from which I was inspired.