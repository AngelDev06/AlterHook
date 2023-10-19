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
- Compile time checks are performed to ensure that the detour and the original callback types are compatible (i.e. they have compatible calling conventions/arguments and same return types)
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