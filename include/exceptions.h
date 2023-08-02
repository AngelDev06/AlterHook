/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#if utils_clang
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdefaulted-function-deleted"
#endif

namespace alterhook::exceptions
{
	// specifies the status the hook engine had 
	// before raising an exception
	enum class hook_status
	{
		anlysing, //< when the original function is being analyzed
		activating, //< when the hook is being activated
		deactivating //< when the hook is being deactivated
	};

	utils_generate_exception_no_base_args(
		hook_exception, std::exception,
		(
			(hook_status, status),
			(const std::byte*, target),
			(const std::byte*, detour)
		)
	)

	utils_generate_exception_no_base_args(
		trampoline_exception, std::exception,
		(
			(const std::byte*, target)
		),
		virtual std::string str() const;
	)

	utils_generate_exception_no_base_args(
		disassembler_exception, std::exception,
		(
			(const std::byte*, target)
		),
	private:
		int m_flag = 0;
	public:
		disassembler_exception(const std::byte* target, int flag) 
			: std::exception(), m_flag(flag), m_target(target) {}
		const char* get_error_string() const noexcept;
		const char* what() const noexcept override { return "An exception occurred with the disassembler"; }
	)

	#if utils_windows
		#define __alterhook_add_buffer \
			private: \
				mutable char buffer[94];
	#else
		#define __alterhook_add_buffer
	#endif

	utils_generate_exception_no_base_args(
		os_exception, std::exception,
		(
			(uint64_t, error_code)
		),
		const char* get_error_string() const noexcept;
		virtual std::string error_function() const = 0;
		__alterhook_add_buffer
	)

	utils_generate_empty_exception(misc_exception, std::exception, virtual std::string str() const = 0;)

	inline namespace trampoline
	{
		#if utils_arm
			#define __alterhook_add_uih_constr \
				unsupported_instruction_handling(const std::byte instr[], bool thumb, const std::byte* target) \
					: trampoline_exception(target), m_thumb(thumb) { memcpy(m_instr, instr, 24); }
			#define __alterhook_add_uih_field const bool m_thumb = false;
		#else
			#define __alterhook_add_uih_constr \
				unsupported_instruction_handling(const std::byte instr[], const std::byte* target) \
					: trampoline_exception(target) { memcpy(m_instr, instr, 24); }
			#define __alterhook_add_uih_field
		#endif

		utils_generate_exception_no_fields(
			unsupported_instruction_handling, trampoline_exception,
			(
				(const std::byte*, target)
			),
			std::string str() const override;
			const char* what() const noexcept override { return "Cannot handle a given instruction in the target function"; }
			__alterhook_add_uih_constr
		private:
			__alterhook_add_uih_field
			std::byte m_instr[24]{};
		)

		#if utils_arm
		utils_generate_exception(
			it_block_exception, trampoline_exception,
			(
				(uintptr_t, it_address),
				(size_t, remaining_instructions)
			),
			(
				(const std::byte*, target)
			),
			std::string str() const override;
			std::string it_str() const;
			size_t instruction_count() const;
			it_block_exception(const std::byte it_block[], uintptr_t address, size_t size, size_t remaining, const std::byte* target)
				: trampoline_exception(target), m_size(size), m_it_address(address), m_remaining_instructions(remaining)
			{ 
				memcpy(m_buffer, it_block, size); 
			}
		private:
			size_t m_size = 0;
			std::byte m_buffer[32]{};
		)

		inline namespace it_block
		{
			utils_generate_exception_no_fields(
				invalid_it_block, it_block_exception,
				(
					(const std::byte*, it_block),
					(uintptr_t, address),
					(size_t, size),
					(size_t, remaining),
					(const std::byte*, target)
				),
				const char* what() const noexcept override { return "An invalid IT block was spotted"; }
			)

			utils_generate_exception_no_fields(
				incomplete_it_block, it_block_exception,
				(
					(const std::byte*, it_block),
					(uintptr_t, address),
					(size_t, size),
					(size_t, remaining),
					(const std::byte*, target)
				),
				const char* what() const noexcept override { return "A part of an IT block was cut off when completing the trampoline function"; }
			)
		}

		utils_generate_exception_no_fields(
			unused_register_not_found, trampoline_exception,
			(
				(const std::byte*, target)
			),
			const char* what() const noexcept override { return "Couldn't find a register suitable for handling PC relative instructions"; }
		)

		utils_generate_exception_no_fields(
			pc_relative_handling_fail, trampoline_exception,
			(
				(const std::byte*, target)
			),
			std::string str() const override;
			const char* what() const noexcept override { return "A PC relative instruction cannot be modified to work"; }
			const std::byte* get_instruction_address() const { return m_instruction_address; }
			pc_relative_handling_fail(const std::byte instr[], const std::byte* target)
				: trampoline_exception(target), m_instruction_address(instr) { memcpy(m_buffer, instr, 24); }
		private:
			const std::byte* m_instruction_address;
			std::byte m_buffer[24]{};
		)
		#endif

		utils_generate_exception_no_fields(
			instructions_in_branch_handling_fail, trampoline_exception,
			(
				(const std::byte*, target)
			),
			const char* what() const noexcept override { return "An instruction in the middle of a branch cannot be altered without breaking the branch"; }
		)

		utils_generate_exception(
			trampoline_max_size_exceeded, trampoline_exception,
			(
				(size_t, size),
				(size_t, max_size)
			),
			(
				(const std::byte*, target)
			),
			std::string str() const override;
			const char* what() const noexcept override { return "Exceeded the trampoline's available size"; }
		)

		utils_generate_exception(
			insufficient_function_size, trampoline_exception,
			(
				(size_t, size),
				(size_t, needed_size)
			),
			(
				(const std::byte*, target)
			),
			std::string str() const override;
			const char* what() const noexcept override { return "The original function isn't long enough to hook"; }
		)
	}

	inline namespace disassembler
	{
		utils_generate_exception_no_fields(
			disassembler_init_fail, disassembler_exception,
			(
				(const std::byte*, target),
				(int, flag)
			),
			const char* what() const noexcept override { return "Disassembler failed to be initialized"; }
		)

		utils_generate_exception_no_fields(
			disassembler_iter_init_fail, disassembler_exception,
			(
				(const std::byte*, target),
				(int, flag)
			),
			const char* what() const noexcept override { return "Disassembler iterator failed to be initialized"; }
		)

		utils_generate_exception_no_fields(
			disassembler_disasm_fail, disassembler_exception,
			(
				(const std::byte*, target),
				(int, flag)
			),
			const char* what() const noexcept override { return "Disassembler failed when trying to disassemble an instruction"; }
		)
	}

	inline namespace os
	{
		#if utils_windows
		utils_generate_exception(
			virtual_alloc_exception, os_exception,
			(
				(const void*, target_address),
				(size_t, size),
				(uint64_t, allocation_type),
				(uint64_t, protection)
			),
			(
				(uint64_t, flag)
			),
			const char* what() const noexcept override { return "An exception occurred when trying to allocate a memory block"; }
			std::string error_function() const override;
		)
		#else
		utils_generate_exception(
			mmap_exception, os_exception,
			(
				(const void*, target_address),
				(size_t, size),
				(int, protection),
				(int, flags),
				(int, fd),
				(uint64_t, offset)
			),
			(
				(uint64_t, flag)
			),
			const char* what() const noexcept override { return "An exception occurred when trying to allocate a memory block"; }
			std::string error_function() const override;
		)
		utils_generate_exception(
			sigaction_exception, os_exception,
			(
				(int, signal),
				(const void*, action),
				(const void*, old_action)
			),
			(
				(uint64_t, flag)
			),
			const char* what() const noexcept override { return "An exception occurred when trying to setup the signal handler"; }
			std::string error_function() const override;
		)

		utils_generate_exception(
			mprotect_exception, os_exception,
			(
				(const void*, address),
				(size_t, length),
				(int, protection)
			),
			(
				(uint64_t, flag)
			),
			const char* what() const noexcept override { return "An exception occured when changing the protection of a memory page"; }
			std::string error_function() const override;
		)
		#endif
	}

	inline namespace misc
	{
		#if !utils_windows
		utils_generate_exception_no_base_args(
			thread_process_fail, misc_exception,
			(
				(const void*, trampoline_address),
				(const void*, target_address),
				(size_t, position)
			),
			const char* what() const noexcept override { return "A thread failed to be processed in order for hooks to work"; }
			std::string str() const override;
		)
		#endif

		utils_generate_exception_no_base_args(
			invalid_address, misc_exception,
			(
				(std::byte*, address)
			),
			const char* what() const noexcept override { return "A non executable address was passed"; }
			std::string str() const override;
		)
	}
}

#if utils_clang
#pragma clang diagnostic pop
#endif
