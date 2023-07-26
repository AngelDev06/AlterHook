/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once

namespace alterhook
{
	namespace helpers
	{
		class ALTERHOOK_HIDDEN disassembler_iterator
		{
		private:
			csh handle = 0;
			const std::byte* code = nullptr;
			uint64_t address = 0;
			size_t size = 0;
			cs_insn* instr = nullptr;
			bool status = false;
		public:
			disassembler_iterator() {}
			disassembler_iterator(
				csh handle,
				const std::byte* orig_code,
				size_t code_size
			) : handle(handle), code(orig_code), size(code_size), address(reinterpret_cast<uintptr_t>(orig_code))
			{
				if (!size)
					return;
				// since this is a C api we have to manually check if everything went ok
				// and throw an exception if not
				if (!(instr = cs_malloc(handle)))
					throw(exceptions::disassembler_iter_init_fail(code, cs_errno(handle)));
				status = cs_disasm_iter(handle, reinterpret_cast<const uint8_t**>(&code), &size, &address, instr);
				if (cs_err error = cs_errno(handle))
					throw(exceptions::disassembler_disasm_fail(code, error));
			}
			~disassembler_iterator() noexcept
			{
				if (instr)
					cs_free(instr, 1);
			}

			const cs_insn& operator*() const noexcept
			{
				utils_assert(instr, "Attempt to dereference an uninitialized instruction");
				return *instr;
			}
			const cs_insn* operator->() const noexcept
			{
				utils_assert(instr, "Attempt to dereference an uninitialized instruction");
				return instr;
			}
			disassembler_iterator& operator++()
			{
				status = cs_disasm_iter(handle, reinterpret_cast<const uint8_t**>(&code), &size, &address, instr);
				if (cs_err error = cs_errno(handle))
					throw(exceptions::disassembler_disasm_fail(code, error));
				return *this;
			}
			bool operator==(const disassembler_iterator& other) const noexcept 
			{
				// iteration should end when either current size or status is
				// equal to the size & status respectively of the end iterator
				// this isn't meant to be compared with anything other than
				// the end iterator
				return other.size == size || other.status == status;
			}
			bool operator!=(const disassembler_iterator& other) const noexcept
			{
				return !(other == *this);
			}
		};
	}

	class ALTERHOOK_HIDDEN disassembler
	{
	private:
		const std::byte* address;
		#if utils_arm
		bool thumb;
		#endif
		csh handle = CS_ERR_OK;
		size_t disasm_size = 0;
	public:
		typedef helpers::disassembler_iterator iterator;

		#if utils_x86 || utils_x64
		disassembler(const std::byte* start_address)
		{
			#if utils_x64
				#define __alterhook_disasm_mode CS_MODE_64
			#else
				#define __alterhook_disasm_mode CS_MODE_32
			#endif
			if (cs_err error = cs_open(CS_ARCH_X86, __alterhook_disasm_mode, &handle))
				throw(exceptions::disassembler_init_fail(start_address, error));
			if (cs_err error = cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON))
				throw(exceptions::disassembler_init_fail(start_address, error));
		}
		#elif utils_arm
		disassembler(const std::byte* start_address, bool thumb, bool detail = true)
			: address(start_address), thumb(thumb)
		{
			if (cs_err error = cs_open(CS_ARCH_ARM, thumb ? CS_MODE_THUMB : CS_MODE_ARM, &handle))
				throw(exceptions::disassembler_init_fail(start_address, error));
			if (!detail)
				return;
			if (cs_err error = cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON))
				throw(exceptions::disassembler_init_fail(start_address, error));
		}
		#endif
		// not checking for errors on close to keep this noexcept
		~disassembler() noexcept { cs_close(&handle); }
		disassembler& disasm(size_t size) noexcept
		{
			disasm_size = size;
			return *this;
		}
		#if utils_arm
		// changes from ARM to THUMB & vice versa
		void switch_instruction_set()
		{
			thumb = !thumb;
			cs_option(handle, CS_OPT_MODE, thumb ? CS_MODE_THUMB : CS_MODE_ARM);
		}
		#endif
		void set_reg_accesses(const cs_insn& instr) const
		{
			instr.detail->regs_read_count = 0;
			instr.detail->regs_write_count = 0;
			cs_regs_access(
				handle, &instr, instr.detail->regs_read, &instr.detail->regs_read_count,
				instr.detail->regs_write, &instr.detail->regs_write_count
			);
		}
		bool modifies_reg(const cs_insn& instr, uint32_t reg) const { return cs_reg_write(handle, &instr, reg); }
		bool reads_reg(const cs_insn& instr, uint32_t reg) const { return cs_reg_read(handle, &instr, reg); }
		bool has_group(const cs_insn& instr, uint32_t group) const { return memchr(instr.detail->groups, group, instr.detail->groups_count); }

		iterator begin() const noexcept { return iterator(handle, address, disasm_size); }
		iterator end() const noexcept { return iterator(); }
		const void* get_address() const noexcept { return address; }
		csh get_handle() const noexcept { return handle; }
		#if utils_arm
		bool is_thumb() const noexcept { return thumb; }
		#endif
	};
}
