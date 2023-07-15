/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#include <pch.h>
#include "macros.h"
#include "addresser.h"

// Addresser inspiration from: https://gist.github.com/altalk23/29b97969e9f0624f783b673f6c1cd279
namespace alterhook
{
	#define __alterhook_noseperator()
	#define __alterhook_comma_seperator() ,

	#define __alterhook_for_hex_digit0(FN, PREFIX, SEPERATOR) \
		FN(PREFIX##0)SEPERATOR() \
		FN(PREFIX##1)SEPERATOR() \
		FN(PREFIX##2)SEPERATOR() \
		FN(PREFIX##3)SEPERATOR() \
		FN(PREFIX##4)SEPERATOR() \
		FN(PREFIX##5)SEPERATOR() \
		FN(PREFIX##6)SEPERATOR() \
		FN(PREFIX##7)SEPERATOR() \
		FN(PREFIX##8)SEPERATOR() \
		FN(PREFIX##9)SEPERATOR() \
		FN(PREFIX##A)SEPERATOR() \
		FN(PREFIX##B)SEPERATOR() \
		FN(PREFIX##C)SEPERATOR() \
		FN(PREFIX##D)SEPERATOR() \
		FN(PREFIX##E)SEPERATOR() \
		FN(PREFIX##F)

	#define __alterhook_for_hex_digit(FN, SEPERATOR) \
		__alterhook_for_hex_digit0(FN, 0x0, SEPERATOR)SEPERATOR() \
		__alterhook_for_hex_digit0(FN, 0x1, SEPERATOR)SEPERATOR() \
		__alterhook_for_hex_digit0(FN, 0x2, SEPERATOR)SEPERATOR() \
		__alterhook_for_hex_digit0(FN, 0x3, SEPERATOR)SEPERATOR() \
		__alterhook_for_hex_digit0(FN, 0x4, SEPERATOR)SEPERATOR() \
		__alterhook_for_hex_digit0(FN, 0x5, SEPERATOR)SEPERATOR() \
		__alterhook_for_hex_digit0(FN, 0x6, SEPERATOR)SEPERATOR() \
		__alterhook_for_hex_digit0(FN, 0x7, SEPERATOR)SEPERATOR() \
		__alterhook_for_hex_digit0(FN, 0x8, SEPERATOR)SEPERATOR() \
		__alterhook_for_hex_digit0(FN, 0x9, SEPERATOR)SEPERATOR() \
		__alterhook_for_hex_digit0(FN, 0xA, SEPERATOR)SEPERATOR() \
		__alterhook_for_hex_digit0(FN, 0xB, SEPERATOR)SEPERATOR() \
		__alterhook_for_hex_digit0(FN, 0xC, SEPERATOR)SEPERATOR() \
		__alterhook_for_hex_digit0(FN, 0xD, SEPERATOR)SEPERATOR() \
		__alterhook_for_hex_digit0(FN, 0xE, SEPERATOR)SEPERATOR() \
		__alterhook_for_hex_digit0(FN, 0xF, SEPERATOR)

	#define __alterhook_vtable_element(hex) reinterpret_cast<intptr_t>(&index_func<hex * sizeof(intptr_t)>)
	#define __alterhook_instance_vpointer(hex) reinterpret_cast<intptr_t>(&custom_vtable)
	#define __alterhook_virtual_function_def(hex) virtual void vfunction##hex() {}
	#define __alterhook_function_array_element(hex) &virtual_function_array::vfunction##hex

	#define __alterhook_custom_vtable_set() { __alterhook_for_hex_digit(__alterhook_vtable_element, __alterhook_comma_seperator) }
	#define __alterhook_vpointer_array_set() { __alterhook_for_hex_digit(__alterhook_instance_vpointer, __alterhook_comma_seperator) }
	#define __alterhook_generate_virtual_functions() __alterhook_for_hex_digit(__alterhook_virtual_function_def, __alterhook_noseperator)
	#define __alterhook_virtual_function_array_set() { __alterhook_for_hex_digit(__alterhook_function_array_element, __alterhook_comma_seperator) }

	template <ptrdiff_t index>
	static ptrdiff_t index_func()
	{
		return index;
	}

	constexpr size_t table_size = 0x100;
	typedef intptr_t table_t[table_size];
	static table_t custom_vtable = __alterhook_custom_vtable_set();
	static table_t vpointer_array = __alterhook_vpointer_array_set();

	class virtual_function_array
	{
	private:
		__alterhook_generate_virtual_functions()
	public:
		typedef void (virtual_function_array::* vmethod_t)();
		typedef vmethod_t vtable_t[table_size];

		static vtable_t array;
	};

	virtual_function_array::vtable_t virtual_function_array::array = __alterhook_virtual_function_array_set();

	addresser::multiple_inheritance* addresser::instance() noexcept
	{
		return reinterpret_cast<addresser::multiple_inheritance*>(&vpointer_array);
	}

	#if !defined(NDEBUG) && utils_msvc
	// TO FIX
	//uintptr_t addresser::follow_msvc_debug_jmp(uintptr_t address) noexcept
	//{
		//if (asm_instruction(*reinterpret_cast<BYTE*>(address)) == asm_instruction::JMP)
			//address += sizeof(JMP) + *reinterpret_cast<intptr_t*>(address + 1);
		//return address;
	//}
	#endif

	uintptr_t addresser::follow_thunk_function(uintptr_t address) noexcept
	{
		// TO FIX
		#if utils_windows
		//if (*reinterpret_cast<BYTE*>(address) == 0xFF && *reinterpret_cast<BYTE*>(address + 1) == 0x25)
		//{
			//address = *reinterpret_cast<intptr_t*>(address + 2);
			//address = *reinterpret_cast<intptr_t*>(address);
		//}
		#endif
		return address;
	}

	bool addresser::is_virtual_impl(void* address) noexcept
	{
		auto memfunc = *reinterpret_cast<virtual_function_array::vmethod_t*>(address);
		for (auto element : virtual_function_array::array)
		{
			if (element == memfunc)
				return true;
		}
		return false;
	}

	#if utils_windows
	/* TO FIX
	bool addresser::is_virtual_msvc_impl(void* address) noexcept
	{
		asm_register thisregister = asm_register::UNKNOWN;
		uintptr_t instruction_pointer = reinterpret_cast<uintptr_t>(address);
		do
		{
			HDE hs;
			disassemble(reinterpret_cast<void*>(instruction_pointer), &hs);
			if (
				hs.flags & F_ERROR ||
				hs.flags & F_PREFIX_ANY ||
				hs.flags & F_SIB ||
				hs.opcode2 != 0
				)
				return false;

			switch (asm_instruction(hs.opcode))
			{
			case asm_instruction::MOV:
				if (thisregister != asm_register::UNKNOWN)
					return false;
				// check if it loads from ecx (where the this pointer is stored)
				if (asm_register(hs.modrm_rm) != asm_register::ECX)
					return false;
				thisregister = asm_register(hs.modrm_reg);
				break;
			case asm_instruction::JMP_ABS:
				// check if it uses the register specified in mov (if it doesn't then it's not a thunk)
				if (hs.modrm_reg != 4 || asm_register(hs.modrm_rm) != thisregister || hs.modrm_mod == 3)
					return false;
				return true;
			case asm_instruction::JMP_SHORT:
				instruction_pointer += sizeof(JMP_SHORT) + static_cast<INT8>(hs.imm.imm8);
				continue;
			case asm_instruction::JMP:
				instruction_pointer += sizeof(JMP) + static_cast<int>(hs.imm.imm32);
				continue;
			default:
				return false;
			}
			instruction_pointer += hs.len;
		} while (true);
	}
	*/
	#endif
}
