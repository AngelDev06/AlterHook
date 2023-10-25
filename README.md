# AlterHook
A dynamic inline hooking library written entirely in c++ which focuses on an ease of use api, cross platform support, customization as well as edge case handling to ensure that it can work as expected no matter the target.

It has the following properties:
- supported compilers: [msvc, clang, gcc]
- supported platforms: [windows, linux, android]
- supported architectures: [x86 (both 32 and 64 bit), armv7]
- minimum c++ standard: c++17
- c++ exceptions and rtti are required

## Contents
- [Compilation](#compilation)
	- [With CMake](#with-cmake)
	- [With Visual Studio](#with-visual-studio)
- [API Showcase](#api-showcase)
	- [Trampoline](#trampoline)
    - [Hook](#hook)
    - [Hook Chain](#hook-chain)
    - [Hook Map](#hook-map)

## Compilation
### With CMake
Clone the repository:
```
git clone https://github.com/AngelDev06/AlterHook
```
In the repository run:
```
cmake --list-presets
```
This will list all of the cmake configure presets provided by the library. You can then choose one via the `--preset` argument like:
```
cmake --preset clang-x64-debug-dll
```
Which in this case will configure the project to be build as a windows dll using the `clang-cl` compiler with architecture being x64.

> Note that on windows you may also have to run [vcvarsall.bat](https://learn.microsoft.com/en-us/cpp/build/building-on-the-command-line?view=msvc-170#vcvarsall-syntax) before running any cmake commands (refer to the documentation for that).

Now you have the project configured but not build.
To build it run:
```
cmake --build out/build/<preset name>
```
### With Visual Studio
Clone the repository:
```
git clone --recursive https://github.com/AngelDev06/AlterHook
```
Open Visual Studio and create a new empty solution. You can use any builtin template for that, including the android ones when targeting android.
In the solution explorer, right click on your solution, then **add > existing project** and find the `.vcxproj` file you are interested in.
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
- arm to thumb and vise versa switches
- IT blocks
- middle jumps
- early exits
- calls to `__x86.get_pc_thunk.bx` or similar ones for linux x86 builds

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
  alterhook::trampoline tramp{ reinterpret_cast<std::byte*>(target1) };
  std::string str = tramp.str();

  // they should have the same output
  target1();
  tramp.invoke<void()>();

  // this should print the disassembled content of the trampoline
  LOG(str.c_str());

  tramp.init(reinterpret_cast<std::byte*>(target2));
  str = tramp.str();

  target2();
  tramp.invoke<void()>();

  LOG(str.c_str());
}
```
### Hook
A very simple and straight forward implementation of an inline hook. Handy for most use cases. Its purpose as the name suggests is enable detouring on a target function, effectively allowing your function to be called instead of the target one. You can optionally provide a reference to a function variable to store a callback to the original function so that you can call it any time.
Additionally since this is c++ it has the following properties:
- Can hook virtual and regular methods
- Can accept a reference to an instance of `std::function` to store the callback.
- Can accept non-capturing lambdas as detours
- Automatically disables the hook when it goes out of scope
- No manual conversions are needed, any reinterpret casts required are handled by the library.
- Compile time checks are performed to ensure that the target, detour and the original callback types are compatible (i.e. they have compatible calling conventions/arguments and same return types)
- If an error occurs an exception will be thrown which you can catch via a simple try catch block.

Apart from that it has a relatively easy to use API.
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
As mentioned earlier, hook class also accepts lambdas as detours and instances of `std::function` to store the original callback.
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
"But wait, when I try to compile this using the MSVC compiler on windows x86 it errors at compile time with"
![Screenshot 2023-10-25 153827](https://github.com/AngelDev06/AlterHook/assets/134562527/f4c5ab76-82a2-4e10-a6cb-46edf5f94337)

The reason for this is that the library makes use of a feature only captureless lambdas have which is to be able to `static_cast` them to a raw function pointer.
This is useful because the library can now make use of the raw function pointer as the detour and place a jump instruction that leads to that. However on windows x86 things get interesting when calling conventions are involved. You can checkout [this article](https://devblogs.microsoft.com/oldnewthing/20150220-00/?p=44623) which explains in detail what goes on with lambdas and calling conventions but to make it short, the calling convention depends on the type of the raw function pointer you cast it to. So if the function pointer has `__vectorcall` set as the calling convention, the compiler will return a version of the lambda that uses the said calling convention. Therefore considering that by default the library casts it to a function pointer of unspecified calling convention, the compiler will use the default one which is `__cdecl`. And as the error message says it is incompatible with the calling convention of the target, which since it's a method it is set to `__thiscall` by default.

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
- The calling convention used in this example is `__fastcall` because MSVC doesn't allow casting a lambda to a function pointer of `__thiscall`. If you are using clang instead you can just use `alterhook::utils::thiscall<void>` as you would normally. It doesn't make much difference in this case since the calling conventions are fully compatible on functions that take one argument.
- The tag tells the library to cast it to a function pointer of the calling convention specified, so in this case it will cast it to `__fastcall`.
- Since the return type is no longer just `void`, you now have to manually put a return statement. Otherwise the compiler will complain.

"Am I done here?"

No, because the original callback is also of calling convention `__cdecl` by default so you will now get this error message:
![Screenshot 2023-10-25 160433](https://github.com/AngelDev06/AlterHook/assets/134562527/cad6b6fd-1c80-4b41-ad2b-158ee2d61aad)

To fix that one simply specify `__fastcall` as the calling convention to the original callback like:
```cpp
static std::function<void __fastcall (originalcls*)> original{};
```
And now everything should compile and run successfully!

Beware though that calling convention utilities and assertions are only provided for windows x86 (other platforms don't need them), so you may want to wrap stuff in macros if you want to write portable code.

### Hook Chain
A powerful api meant for storing a chain of detours and original callbacks to the same target. 

Most people are familiar with the multihook approach which basically means hooking on top of an already activated hook. While this method may be functional, it can be very error prone. What if the first hook gets disabled? That will also disable the rest of the hooks as the target's first bytes will have been replaced by the backup it made previously. What if you disable the second hook when the first one is already disabled? It will re-enable the first one! This is because the second hook will have made a backup of the jump instruction that leads to the first hook which it will copy back to the target when it gets disabled.

The hook chain class is designed to put an end to this. **<ins>Any hook added in the chain can be disabled or enabled from any position without affecting the rest of the hooks.</ins>** Apart from that it also allows reordering the container as needed. That means changing the order of enabled or disabled hooks and swapping them as well as transferring them from one chain to another. erasing or appending a hook at any position will also not affect the rest of the chain.

To construct an instance of the `alterhook::hook_chain` class you have two styles to choose:
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

After construction the hooks will be immediately enabled and linked. A few things to note however:
- The hooks are passed to the chain in the construction order. That means that the last pair passed will be the last hook in the chain (which you can access via `chain.back()`)
- The hooks' detours are invoked in reverse order. Which means that the last hook in the chain will have its detour invoked first and the first hook's detour will be invoked last.
- Unlike in the `alterhook::hook` class, here specifying the original callback is NOT optional. Not providing a callback will result in a compilation error. If your detour does not use the callback to call the original, it can result in detours not being called. So it's important to **<ins>always call the original.</ins>**
- The container stores references to the callbacks to set them to point to the next detour or the target function when a reordering occurs.
- When a hook gets disabled or enabled it will not affect order. So when the hook gets re-enabled or re-disabled it will go back to its previous position.
- Hooking operations use locks (like the rest of the library), but the container itself **<ins>isn't thread-safe.</ins>** Therefore you should not attempt to do write operations to the container concurrently from different threads.
- Under the hood the container maintains two **<ins>linked lists</ins>**, one for the enabled hooks and one for the disabled. So keep that in mind when using the provided `operator[]` overload. It will have to iterate the container in order to find the element needed, as fast random access is not supported.
- By default when using range-based loops, it will iterate over both the enabled and the disabled hooks in the range from begin to end. You can choose to use special iterators to only iterate over the enabled or the disabled ones like `chain.ebegin()` which gets the begin iterator of the enabled list. The special list iterators are bidirectional unlike the default iterator which is only forward.

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
// transfer all of the enabled hooks but the last one at the end of the disabled list (also disables them because of it)
chain.splice(chain.dend(), chain.ebegin(), std::prev(chain.eend()),
             alterhook::hook_chain::transfer::disabled);

// puts the first disabled hook before the first enabled one (also enables it because of it)
chain.splice(chain.ebegin(), chain.dbegin());

// transfers all hooks from a different `hook_chain` to the beggining of the current chain 
// (it maintains the status of the hooks, as the hooks that are enabled go to the enabled chain and the others in the disabled chain respectively)
chain.splice(chain.ebegin(), chain2, 
             std::next(chain2.begin()), 
             chain2.end());

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
  std::cout << hook.get_detour() << '\n';

// iterate over all the disabled hooks
for (auto itr = chain.dbegin(); itr != chain.dend(); ++itr)
  std::cout << hook.get_detour() << '\n';
```
And more!

### Hook Map
A hash map and hook chain adapter that allows for average constant time lookup of a hook using a custom key. It accepts almost the same template parameters `std::unordered_map` and other similar hash map implementations accept but with a few differences:
- It doesn't have mapped type parameter, since it will by design use a reference to a hook entry as a mapped type.
- It has a hash_map parameter which allows you to customize the hash map to adapt. It will by default use `std::unordered_map` but it can also use `std::unordered_multimap` and the boost.Unordered containers. It was tested with:
    - `std::unordered_map`
    - `std::unordered_multimap`
    - `boost::unordered_map`
    - `boost::unordered_multimap`
    - `boost::unordered_flat_map`
    - `boost::unordered_node_map`
    - `boost::concurrent_flat_map`
- It has a boolean flag as a last template parameter that tells whether to activate thread-safe mode (yes this is the only container that can be used concurrently) which is by default set to true when using a concurrent map (like `boost::concurrent_flat_map`) or false otherwise.

There are a few aliases the might be useful:
- `alterhook::hook_map_using` takes key and container to adapt
- `alterhook::concurrent_hook_map` takes key and turns on thread-safe mode
- `alterhook::concurrent_hook_map_using` takes key, container to adapt and turns on thread-safe mode

What's cool about this container is that its api depends on the hash map it adapts.
For example when adapting `boost::concurrent_flat_map` it will not allow the use of `operator[]` to lookup elements but it will instead use the [visitation based api](https://www.boost.org/doc/libs/1_83_0/libs/unordered/doc/html/unordered.html#concurrent_visitation_based_api) provided by the hash map. Or when using `boost::unordered_flat_map` it will not have the bucket api implemented as it's an open-addressing container.

Since it's an adapter and not a real container, it uses custom iterators that when dereferenced return `std::pair<const key&, typename alterhook::hook_chain::hook&>` so you can freely do `auto [k, v] = *itr;` without minding copies.

This class inherits the constructors of both the hash map and the hook chain so you can construct it like:
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