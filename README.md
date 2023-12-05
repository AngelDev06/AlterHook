# AlterHook

A dynamic inline hooking library that is written entirely in C++ and focuses on ease of use API, cross-platform support, customization as well as edge case handling to ensure that it can work as expected no matter the target.

It has the following properties:

- supported compilers: [msvc, clang, gcc]
- supported platforms: [Windows, Linux, Android]
- supported architectures: [x86 (both 32 and 64 bit), armv7]
- minimum c++ standard: c++17
- c++ exceptions and RTTI are required

## Contents

- [Compilation](#compilation)
  - [With CMake](#with-cmake)
  - [With Visual Studio](#with-visual-studio)
- [API Showcase](#api-showcase)
  - [Trampoline](#trampoline)
  - [Hook](#hook)
  - [Hook Chain](#hook-chain)
  - [Hook Map](#hook-map)
  - [Modifier](#modifier)

## Compilation

### With CMake

Clone the repository:

```bash
git clone https://github.com/AngelDev06/AlterHook
```

In the repository run:

```bash
cmake --list-presets
```

This will list all of the cmake configure presets provided by the library. You can then choose one via the `--preset` argument like:

```bash
cmake --preset clang-x64-debug-dll
```

Which in this case will configure the project to be built as a Windows dll using the `clang-cl` compiler with the architecture being x64.

> Note that on windows you may also have to run [vcvarsall.bat](https://learn.microsoft.com/en-us/cpp/build/building-on-the-command-line?view=msvc-170#vcvarsall-syntax) before running any cmake commands (refer to the documentation for that). Also note that if you are trying to cross-compile for android with the presets provided you should have set the `NDK_ROOT` environment variable to the full path to your [ndk installation](https://developer.android.com/ndk/downloads).

Now you have the project configured but not built.
To build it run:

```bash
cmake --build out/build/<preset name>
```

### With Visual Studio

Clone the repository:

```bash
git clone --recursive https://github.com/AngelDev06/AlterHook
```

Open Visual Studio and create a new empty solution. You can use any built-in template for that, including the Android ones when targeting Android.
In the solution explorer, right-click on your solution, then **add > existing project** and find the `.vcxproj` file in the `vs/` directory you are interested in.
After adding it, you can create a simple test project and add the library as a reference with **references > add reference** which will link your project and the library together.
Also if you are building a dll you may need to go to **properties > Advanced** of your project and turn on **Copy Project References to OutDir** to automatically copy the dll to your output directory.

## API Showcase

This is meant for showcasing the API with examples going from lower lever to higher level features.
For a complete reference take a look at `docs/`.

### Trampoline

The lowest level data structure the library offers. Its purpose is to hold an executable buffer of the first few relocated instructions so that when needed to call the original, it will first execute those instructions before eventually jumping back to the target to continue executing the rest of the function. This is needed because the first few bytes of the target function will be replaced with a jump instruction to the detour so calling it directly would result in an unintended infinite loop.

Relocating instructions from one location to another is not as easy as it sounds since the behavior of some instructions depends on their location. Therefore this class is prepared to handle some very edge cases, namely:

- relative calls/jumps
- eip/rip/pc relative instructions
- arm to thumb and vice versa switches
- IT blocks
- middle jumps
- early exits
- calls to `__x86.get_pc_thunk.bx` or similar ones for Linux x86 builds

Example:

```cpp
#include <alterhook/trampoline.h>
#include <android/log.h>
#define LOG(...)                                                               \
  ((void)__android_log_print(ANDROID_LOG_INFO, "sandboxapp", __VA_ARGS__))

extern "C"
{
  void print_hex(size_t arg) { LOG("hex value: 0x%X", arg); }

  __attribute__((naked)) void target1()
  {
    asm("push { lr };"
        "ldrb r0, MYDATA;"
        "add r0, pc;"
        "bl print_hex;"
        "pop { pc };"
        "MYDATA:"
        ".byte 15;");
  }

  __attribute__((naked)) void target2()
  {
    asm("ittt AL;"
        "moval r0, #5;"
        "addal r0, pc;"
        "lsral r0, #8;"
        "push { lr };"
        "bl print_hex;"
        "pop { pc };");
  }
}

int main()
{
  alterhook::trampoline tramp{ target1 };
  std::string str = tramp.str();

  // they should have the same output
  target1();
  tramp.invoke<void()>();

  // this should print the disassembled content of the trampoline
  LOG(str.c_str());

  tramp.init(target2);
  str = tramp.str();

  target2();
  tramp.invoke<void()>();

  LOG(str.c_str());
}
```

### Hook

A very simple and straightforward implementation of an inline hook. Handy for most use cases. Its purpose as the name suggests is to enable detouring on a target function, effectively allowing your function to be called instead of the target one. You can optionally provide a reference to a function variable to store a callback to the original function so that you can call it at any time. Additionally, since this is C++ it has the following properties:

- Can hook virtual and regular methods
- Can accept a reference to an instance of `std::function` to store the callback.
- Can accept non-capturing lambdas as detours
- Automatically disables the hook when it goes out of scope
- No manual conversions are needed, any reinterpret casts required are handled by the library.
- Compile time checks are performed to ensure that the target, detour and original callback types are compatible (i.e. they have compatible calling conventions/arguments and same return types)
- If an error occurs an exception will be thrown which you can catch via a simple try-catch block.

Apart from that it has a relatively easy-to-use API.
You can create a hook and enable it by calling the hook's constructor like this:

```cpp
alterhook::hook hook{ &originalcls::func, &detourcls::func, original };
```

If you don't wish to enable it immediately you can pass `false` to the default parameter at the end to prevent it from doing so.
You can always enable it later via a call to:

```cpp
hook.enable();
```

Or disable it with:

```cpp
hook.disable();
```

As mentioned earlier, the hook class also accepts lambdas as detours and instances of `std::function` to store the original callback.
So the following should compile fine:

```cpp
static std::function<void(originalcls*)> original{};
alterhook::hook hook{ &originalcls::func2,
                      [](originalcls* self)
                      {
                        std::cout << "hooked!\n";
                        original(self);
                      },
                      original };
```

"But wait, when I try to compile this using the MSVC compiler on Windows x86 it errors at compile time with"
![Screenshot 2023-10-25 153827](https://github.com/AngelDev06/AlterHook/assets/134562527/f4c5ab76-82a2-4e10-a6cb-46edf5f94337)

The reason for this is that the library makes use of a feature only captureless lambdas have which is to be able to `static_cast` them to a raw function pointer.
This is useful because the library can now make use of the raw function pointer as the detour and place a jump instruction that leads to that. However, on Windows x86 things get interesting when calling conventions are involved. You can check out [this article](https://devblogs.microsoft.com/oldnewthing/20150220-00/?p=44623) which explains in detail what goes on with lambdas and calling conventions but to make it short, the calling convention depends on the type of the raw function pointer you cast it to. So if the function pointer has `__vectorcall` set as the calling convention, the compiler will return a version of the lambda that uses the said calling convention. Therefore considering that by default the library casts it to a function pointer of unspecified calling convention, the compiler will use the default one which is `__cdecl`. As the error message says it is incompatible with the calling convention of the target, which since it's a method is set to `__thiscall` by default.

To fix this, you can tag the lambda with the calling convention you want to use by using some utility tags provided by the library as a return type. For example:

```cpp
static std::function<void(originalcls*)> original{};
alterhook::hook hook{ &originalcls::func2,
                      [](originalcls* self) -> alterhook::utils::fastcall<void>
                      {
                        std::cout << "hooked!\n";
                        original(self);
                        return {};
                      },
                      original };
```

A few things to mind here:

- The calling convention used in this example is `__fastcall` because MSVC doesn't allow casting a lambda to a function pointer of `__thiscall`. If you are using clang instead you can just use `alterhook::utils::thiscall<void>` as you would normally. It doesn't make much difference in this case since the calling conventions are fully compatible with functions that take one argument.
- The tag tells the library to cast it to a function pointer of the calling convention specified, so in this case, it will cast it to `__fastcall`.
- Since the return type is no longer just `void`, you now have to manually put a return statement. Otherwise, the compiler will complain.

"Am I done here?"

No, because the original callback is also of calling convention `__cdecl` by default so you will now get this error message:
![Screenshot 2023-10-25 160433](https://github.com/AngelDev06/AlterHook/assets/134562527/cad6b6fd-1c80-4b41-ad2b-158ee2d61aad)

To fix that one simply specify `__fastcall` as the calling convention to the original callback like:

```cpp
static std::function<void __fastcall (originalcls*)> original{};
```

And now everything should compile and run successfully!

Beware though that calling convention utilities and assertions are only provided for Windows x86 (other platforms don't need them), so you may want to wrap stuff in macros if you want to write portable code.

### Hook Chain

A powerful API meant for storing a chain of detours and original callbacks to the same target.

Most people are familiar with the multihook approach which basically means hooking on top of an already activated hook. While this method may be functional, it can be very error-prone. What if the first hook gets disabled? That will also disable the rest of the hooks as the target's first bytes will have been replaced by the backup it made previously. What if you disable the second hook when the first one is already disabled? It will re-enable the first one! This is because the second hook will have made a backup of the jump instruction that leads to the first hook which it will copy back to the target when it gets disabled.

The hook chain class is designed to put an end to this. **<ins>Any hook added to the chain can be disabled or enabled from any position without affecting the rest of the hooks.</ins>** Apart from that it also allows reordering the container as needed. That means changing the order of enabled or disabled hooks and swapping them as well as transferring them from one chain to another. erasing or appending a hook at any position will also not affect the rest of the chain.

To construct an instance of the `alterhook::hook_chain` class you have two styles to choose from:

- Passing all arguments (target, detours and callbacks) as is

```cpp
alterhook::hook_chain chain1{ &originalcls::func, 
                              &detourcls::func, original,
                              &detourcls::func2, original2,
                              &detourcls::func3, original3 };
```

- Or grouping the detours and callbacks in tuple-like objects

```cpp
alterhook::hook_chain chain2{
    &originalcls::func2, 
    std::forward_as_tuple(&detourcls::func4, original4),
    std::forward_as_tuple(&detourcls::func5, original5),
    std::forward_as_tuple(&detourcls::func6, original6)
};
// or
alterhook::hook_chain chain2{
    &originalcls::func2, 
    std::make_pair(&detourcls::func4, std::ref(original4)),
    std::make_pair(&detourcls::func5, std::ref(original5)),
    std::make_pair(&detourcls::func6, std::ref(original6))
};
```

After construction, the hooks will be immediately enabled and linked. A few things to note, however:

- The hooks are passed to the chain in the construction order. That means that the last pair passed will be the last hook in the chain (which you can access via `chain.back()`)
- The hooks' detours are invoked in reverse order. This means that the last hook in the chain will have its detour invoked first and the first hook's detour will be invoked last.
- Unlike in the `alterhook::hook` class, here specifying the original callback is NOT optional. Not providing a callback will result in a compilation error. If your detour does not use the callback to call the original, it can result in detours not being called. So it's important to **<ins>always call the original.</ins>**
- The container stores reference to the callbacks to set them to point to the next detour or the target function when a reordering occurs.
- When a hook gets disabled or enabled it will not affect the order. So when the hook gets re-enabled or re-disabled it will go back to its previous position.
- Hooking operations use locks (like the rest of the library), but the container itself **<ins>isn't thread-safe.</ins>** Therefore you should not attempt to do write operations to the container concurrently from different threads.
- Under the hood, the container maintains two **<ins>linked lists</ins>**, one for the enabled hooks and one for the disabled. So keep that in mind when using the provided `operator[]` overload. It will have to iterate the container in order to find the element needed, as fast random access is not supported.
- By default when using range-based loops, it will iterate over both the enabled and the disabled hooks in the range from begin to end. You can choose to use special iterators to only iterate over the enabled or the disabled ones like `chain.ebegin()` which gets the begin iterator of the enabled list. The special list iterators are bidirectional, unlike the default iterator which is only forward.

A few useful operations you can do with the container are:

- inserting

```cpp
// will add a hook right before the second enabled hook
chain.insert(
      std::next(chain.ebegin()),
      [](originalcls* self)
      {
        std::cout << "lambda\n";
        original(self);
      },
      original);

// will add multiple hooks on the back (defaults to enabled)
chain.append(&detourcls::func2, original2, &detourcls::func3, original3);

// will add a hook to the front (defaults to enabled)
chain.push_front(&detourcls::func4, original4);
```

- erasing

```cpp
// will erase the second hook (enabled or disabled)
chain.erase(std::next(chain.begin()));

// will erase only the enabled hooks starting from the third one till the last
chain.erase(std::next(chain.ebegin(), 2), chain.eend());

// will erase the following range (both enabled and disabled
chain.erase(std::next(chain.begin()), chain.end());

// will erase the last element
chain.pop_back();
```

- enabling/disabling hooks

```cpp
// enables all hooks
chain.enable_all();

// disables second hook
chain[1].disable();
```

- splicing/swapping

```cpp
typedef typename alterhook::hook_chain::transfer transfer;

// transfer all of the enabled hooks but the last one at the end of the disabled list (also disables them because of it)
chain.splice(chain.dend(), chain.ebegin(), std::prev(chain.eend()),
             transfer::disabled);

// puts the first disabled hook before the first enabled one (also enables it because of it)
chain.splice(chain.ebegin(), chain.dbegin(), transfer::enabled);

// transfers all hooks from a different `hook_chain` to the beggining of the current chain 
// (it maintains the status of the hooks, as the hooks that are enabled go to the enabled chain and the others in the disabled chain respectively)
chain.splice(chain.ebegin(), chain2, 
             std::next(chain2.begin()), 
             chain2.end(), transfer::enabled);

// swaps the hooks of `chain` with the hooks of `chain2`
// however it doesn't swap the targets!
chain.swap(chain2);

// swaps the first element of `chain` with the last enabled element of `chain2`
// it also makes sure to swap status if needed, i.e. when swapping an enabled hook with a disabled one it makes sure to disable the enabled one and enable the other one
chain.swap(chain.begin(), chain2, std::prev(chain2.eend()));
```

- iterating

```cpp
// iterate over the entire chain (both enabled and disabled hooks)
for (auto& hook : chain)
  std::cout << hook.get_detour() << '\n';

// iterate over all the enabled hooks
for (auto itr = chain.ebegin(); itr != chain.eend(); ++itr)
  std::cout << itr->get_detour() << '\n';

// iterate over all the disabled hooks
for (auto itr = chain.dbegin(); itr != chain.dend(); ++itr)
  std::cout << itr->get_detour() << '\n';
```

And more!

### Hook Map

A hash map and hook chain adapter that allows for average constant time lookup of a hook using a custom key. It accepts almost the same template parameters `std::unordered_map` and other similar hash map implementations accept but with a few differences:

- It doesn't have mapped type parameter, since it will by design use a reference to a hook entry as a mapped type.
- It has a hash_map parameter which allows you to customize the hash map to adapt. It will by default use `std::unordered_map` but it can also use `std::unordered_multimap` and the `boost.Unordered` containers. It was tested with:
  - `std::unordered_map`
  - `std::unordered_multimap`
  - `boost::unordered_map`
  - `boost::unordered_multimap`
  - `boost::unordered_flat_map`
  - `boost::unordered_node_map`
  - `boost::concurrent_flat_map`
- It has a boolean flag as a last template parameter that tells whether to activate thread-safe mode (yes this is the only container that can be used concurrently) which is by default set to true when using a concurrent map (like `boost::concurrent_flat_map`) or false otherwise.

There are a few aliases that might be useful:

- `alterhook::hook_map_using` takes the key and container to adapt
- `alterhook::concurrent_hook_map` takes the key and turns on thread-safe mode
- `alterhook::concurrent_hook_map_using` takes the key, container to adapt and turns on thread-safe mode

What's cool about this container is that its API depends on the hash map it adapts.

For example, when adapting `boost::concurrent_flat_map` it will not allow the use of `operator[]` to lookup elements but it will instead use the [visitation-based API](https://www.boost.org/doc/libs/1_83_0/libs/unordered/doc/html/unordered.html#concurrent_visitation_based_api) provided by the hash map. Or when using `boost::unordered_flat_map` it will not have the bucket API implemented as it's an open-addressing container.

Since it's an adapter and not a real container, it uses custom iterators that when dereferenced return `std::pair<const key&, typename alterhook::hook_chain::hook&>` so you can freely do `auto [k, v] = *itr;` without minding copies.

This class inherits the constructors of both the hash map and the hook chain so you can construct it like this:

```cpp
alterhook::hook_map<std::string> map{
    &originalcls::func, 
    std::forward_as_tuple("entry1", &detourcls::func, original),
    std::forward_as_tuple("entry2", &detourcls::func2, original2)
};
```

Which is like the hook_chain constructor but it expects keys to be passed along each entry as well either in triplets like in the example or 'as is'. Or you can construct it like

```cpp
alterhook::hook_map<std::string> map{ 10 };
```

Which constructs the container with n buckets.

Showcase:

```cpp
alterhook::concurrent_hook_map<std::string> map{
    &originalcls::func, 
    std::forward_as_tuple("entry1", &detourcls::func, original1),
    std::forward_as_tuple("entry2", &detourcls::func2, original2)
};

// inserts two hooks with specified keys to the disabled list
map.insert(alterhook::hook_chain::transfer::disabled,
           std::forward_as_tuple("entry3", &detourcls::func3, original3),
           std::forward_as_tuple("entry4", &detourcls::func4, original4));

// swap entry3 with entry1
map.swap("entry3", "entry1");

// visit all entries and print their info.
// note that looping over the container with a range-based for loop is NOT possible 
// as on thread-safe mode iterators are removed
map.visit_all(
     [](const auto& item)
     {
       std::cout << item.first << ": " << item.second.get_target() << ", "
                 << item.second.get_detour() << ", "
                 << item.second.is_enabled() << '\n';
     });
```

### Modifier

A very sugary and user-friendly way of hooking multiple class methods via defining your own class. It is achieved via using a macro and listing the function names you want to "modify" with your own.

The macro signature is the following:

```cpp
#define modifier(modifier_name, modifier_target, ...)
```

- The first argument represents the name of your class or modifier that you are using to detour the other class methods.
- The second argument is the target class to use that has those methods defined.
- Lastly, the last argument is `__VA_ARGS__` which means it can accept any number of arguments at the end. Those arguments can be:
  - The name of the target method
  - Both the name and the type of the target method grouped into a 'pair' like `(foo, void())`

This macro generates a few classes and wrappers to achieve the following:

- [x] Detour private or protected methods from the target class
- [x] Allow your implementation to use members of the target class as it publicly inherits from it
- [x] Provides an overload with an identical signature for each of the target methods that lets you call the original.
- [x] Lets you disambiguate target overloads by explicitly specifying the function type in the macro list.
- [x] Inherits 4 static methods that allow you to enable/disable activate/deactivate the modifier
- [x] Does a lot of compile time checks to ensure safety. These are:
  - Checking if `sizeof(original) == sizeof(derived)` to make sure that the modifier class hasn't added any members (which is not supported)
  - Checking if the methods specified in the `modifier` macro are actually defined in the modifier class.
  - Checking if the return types of the specified methods match the original ones
  - Checking if the calling conventions of the specified methods are compatible with the original ones (windows x86 only)
  - Checking if the arguments of the specified methods are compatible with the original ones

The good thing about the compile time checks is that they are bound with the modifier class. For example, when you accidentally use an incorrect return type you get back:

![Screenshot 2023-10-28 215001](https://github.com/AngelDev06/AlterHook/assets/134562527/dc1b8212-d4f3-4e39-942a-8f2a18c8ee4f)

Which tells you exactly which method causes the problem, what the problem is and in which line the modifier is defined!

Likewise, if you forgot to define foo, you would get:

![Screenshot 2023-10-28 215349](https://github.com/AngelDev06/AlterHook/assets/134562527/347aab2a-716e-4bf9-bc26-2c8b86b7290e)

The 4 static methods inherited are:

- `activate_modifier` (which inserts all hooks to the global table and enables them)
- `deactivate_modifier` (which erases all hooks from the global table and disables them)
- `enable_modifier` (which enables all hooks if they are already in the global table, otherwise calls `activate_modifier`)
- `disable_modifier` (which disables all hooks if they are already in the global table, and does nothing otherwise)

In general, when you have already activated the modifier you should be using `enable_modifier` and `disable_modifier` to enable/disable all the hooks that are part of it. Using `activate_modifier` and `deactivate_modifier` instead would have the hooks added and erased from the global table apart from just enabling/disabling them. Which means more heap allocations!

Ok but how does one call the original from the modifier class? Another thing that's inherited is a typedef named `original` which you can use to call the original methods. The original methods have identical signatures to your detours and are generated by the macro to properly call back the target function. For example, say you want to hook a function named `foo` and call it from your detour. You can do it like so:

```cpp
void foo()
{
  // do your stuff
  ...
  // call the original
  original::foo();
}
```

As mentioned earlier you can also access private/protected methods from the target class as well as disambiguate overloads. That however doesn't change the fact that all of your detours should be public, as the library does nothing to access any of your private methods. Disambiguation works by explicitly providing the function type of your target function like `(foo, void())` as a parameter to the modifier. So the following should compile:

```cpp
class target
{
 void private_method() {}
public:
  void foo() {}
  void foo(int x) {}
};

class modifier(mymodifier, target, (foo, void(int)), private_method)
{
public:
  // note `private_method` is public here
  void private_method() { original::private_method(); }
  void foo(int x) { original::foo(x); }
};
```

A usage example would be:

```cpp
#include <alterhook/modifier.h>
#include <iostream>

struct target
{
  int x, y, z;

  void multiply_by(int count)
  {
    x *= count; y *= count; z *= count;
    std::cout << "target::multiply_by\n";
  }

  // overloaded method
  void multiply_by(float count)
  {
    x *= count; y *= count; z *= count;
    std::cout << "target::multiply_by\n";
  }

  void power_all() { private_power_all(); }
private:
  // private method
  void private_power_all()
  {
    x *= x; y *= y; z *= z;
    std::cout << "target::private_power_all\n";
  }
};

class modifier(mymodifier, target, (multiply_by, void(int)),
               (multiply_by, void(float)), private_power_all)
{
public:
  void multiply_by(int count)
  {
    std::cout << "mymodifier::multiply_by\n";
    original::multiply_by(count * 2);
  }

  void multiply_by(float count)
  {
    std::cout << "mymodifier::multiply_by\n";
    original::multiply_by(count * 2);
  }

  void private_power_all()
  {
    std::cout << "mymodifier::private_power_all\n";
    original::private_power_all();
  }
};

int main()
{
  // activates the modifier
  mymodifier::activate_modifier();
  // from here all targeted methods will have been hooked
  ...
  // erase all hooks from the global table and exit
  mymodifier::deactivate_modifier();
}
```

Now what if you want to enable/disable individual hooks or just get info about them?
The hooks are all stored in the global table which can be accessed via `hook_manager::get()`. You can use it to insert/erase/enable/disable individual entries and access the underlying instance of `concurrent_hook_map` for a specific target. Once you have accessed the concurrent hook map you can use the [visitation-based API](https://www.boost.org/doc/libs/1_83_0/libs/unordered/doc/html/unordered.html#concurrent_visitation_based_api) to access a specific hook using the needed key and a callback. For example:

```cpp
// note: the type returned from `operator[]` is an instance of std::unique_ptr
// with a custom deleter which wraps `managed_concurrent_hook_map`.
// `managed_concurrent_hook_map` is also a wrapper over
// `concurrent_hook_map<std::string>` and you can therefore use all of its
// methods but can't copy or move it around
typedef typename alterhook::managed_concurrent_hook_map::reference reference;
auto map = alterhook::hook_manager::get()[&target::foo];
map->visit("mymodifier::foo",
           [](reference pair)
           {
             std::cout << "key: " << pair.first
                       << " detour: " << pair.second.get_detour() << '\n';
           });
```

As you can tell the key that `visit` accepts is the full name of the method, like `<class name>::<method name>`. You can use all sorts of methods inherited from `concurrent_hook_map<std::string>` but you should note however that each instance of `managed_concurrent_hook_map` refers to a single target. So you should not expect `mymodifier::func` for example to be on the same instance. Also, you might be wondering, why does `operator[]` return an instance of `std::unique_ptr`? The answer is safety. The library tries to clean up any instances of `managed_concurrent_hook_map` that are left with no hooks to save space. But what if those instances are currently in use by some thread? That would be catastrophic. So instead `std::unique_ptr` is used to keep it alive for as long as it's used by using a ref count. Once it goes out of scope the ref count is decremented and the custom deleter provided will be responsible for doing any cleanup IF needed.

## Credits

All credits go to the [capstone](https://github.com/capstone-engine/capstone) disassembly framework for making my idea possible.
