/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once

namespace alterhook
{
	namespace helpers
	{
		class disassembler_iterator
		{
		private:
			csh handle = 0;
			const std::byte* code = nullptr;
			uint64_t position = 0;
			size_t size = 0;
			cs_insn* instr = nullptr;
			bool status = false;
		public:
			disassembler_iterator() {}
			disassembler_iterator(
				csh handle,
				const std::byte* code,
				size_t size,
				uint64_t position = 0
			) : handle(handle), code(code), position(position), size(size)
			{
				if (!size)
					return;
				// since this is a C api we have to manually check if everything went ok
				// and throw an exception if not
				if (!(instr = cs_malloc(handle)))
					throw(exceptions::disassembler_iter_init_fail(code, cs_errno(handle)));
				status = cs_disasm_iter(handle, reinterpret_cast<const uint8_t**>(&code), &size, &position, instr);
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
				status = cs_disasm_iter(handle, reinterpret_cast<const uint8_t**>(&code), &size, &position, instr);
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

	class disassembler
	{
	private:
		const std::byte* address;
		bool thumb;
		csh handle = CS_ERR_OK;
		size_t disasm_size = 0;
	public:
		typedef helpers::disassembler_iterator iterator;

		disassembler(const std::byte* start_address, bool thumb)
			: address(start_address), thumb(thumb)
		{
			if (cs_err error = cs_open(CS_ARCH_ARM, thumb ? CS_MODE_THUMB : CS_MODE_ARM, &handle))
				throw(exceptions::disassembler_init_fail(start_address, error));
			if (cs_err error = cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON))
				throw(exceptions::disassembler_init_fail(start_address, error));
		}
		// not checking for errors on close to keep this noexcept
		~disassembler() noexcept { cs_close(&handle); }
		disassembler& disasm(size_t size) noexcept
		{
			disasm_size = size;
			return *this;
		}
		// changes from ARM to THUMB & vice versa
		void switch_instruction_set()
		{
			thumb = !thumb;
			cs_option(handle, CS_OPT_MODE, thumb ? CS_MODE_THUMB : CS_MODE_ARM);
		}

		iterator begin() const noexcept { return iterator(handle, address, disasm_size); }
		iterator end() const noexcept { return iterator(); }
		const void* get_address() const noexcept { return address; }
		bool is_thumb() const noexcept { return thumb; }
	};
}
