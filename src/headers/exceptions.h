/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once

namespace alterhook::exceptions
{
	// specifies the status the hook engine had 
	// before raising an exception
	enum class hook_status
	{
		anlysing, //< when the original function is being analysed
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
		disassembler_exception, std::exception,
		(
			(const std::byte*, target)
		),
	private:
		uint64_t m_flag = 0;
	public:
		disassembler_exception(const std::byte* target, uint64_t flag) 
			: std::exception(), m_target(target), m_flag(flag) {}
		const char* get_error_string() const noexcept;
		const char* what() const noexcept override { return "An exception occured with the disassembler"; }
	)

	utils_generate_exception_no_base_args(
		os_exception, std::exception,
		(
			(uint64_t, error_code)
		),
		const char* get_error_string() const noexcept;
		virtual std::string error_function() const = 0;
	)

	inline namespace disassembler
	{
		utils_generate_exception_no_fields(
			disassembler_init_fail, disassembler_exception,
			(
				(const std::byte*, target),
				(uint64_t, flag)
			),
			const char* what() const noexcept override { return "Dissasembler failed to be initialized"; }
		)

		utils_generate_exception_no_fields(
			disassembler_iter_init_fail, disassembler_exception,
			(
				(const std::byte*, target),
				(uint64_t, flag)
			),
			const char* what() const noexcept override { return "Dissasembler iterator failed to be initialized"; }
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
		#endif
	}
}
