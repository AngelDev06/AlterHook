/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#include <pch.h>
#include "arm_instructions.h"
#include "exceptions.h"
#include "linux_thread_handler.h"
namespace fs = std::filesystem;

#ifdef __GNUC__
	#define __alterhook_flush_cache(address, size) \
		__builtin___clear_cache(reinterpret_cast<char*>(address), reinterpret_cast<char*>(address) + size)
#else
	#define __alterhook_flush_cache(address, size) cacheflush(reinterpret_cast<uintptr_t>(address), size, 0)
#endif

namespace alterhook
{
	extern const long memory_block_size;

	static ALTERHOOK_HIDDEN cs_insn* disasm_one(csh& handle, const std::byte target[], uint64_t address = 0)
	{
		cs_insn* instr = nullptr;
		size_t size = 24;
		auto buffer = reinterpret_cast<const uint8_t*>(target);
		if (
			(handle = cs_open(CS_ARCH_ARM, CS_MODE_THUMB, &handle)) ||
			!(instr = cs_malloc(handle)) ||
			!cs_disasm_iter(handle, &buffer, &size, &address, instr)
		)
		{
			cs_free(instr, 1);
			cs_close(&handle);
			return nullptr;
		}
		return instr;
	}
	static ALTERHOOK_HIDDEN void cleanup(cs_insn* instr, csh handle)
	{
		cs_free(instr, 1);
		cs_close(&handle);
	}

	namespace exceptions
	{
		std::string it_block_exception::str() const
		{
			std::stringstream stream;
			csh handle = 0;
			cs_insn* instructions = nullptr;
			size_t count = 0;
			
			if (cs_open(CS_ARCH_ARM, CS_MODE_THUMB, &handle))
				return {};
			count = cs_disasm(handle, reinterpret_cast<const uint8_t*>(m_buffer), m_size, m_it_address, 0, &instructions);
			if (cs_errno(handle) || !count)
				return {};

			try
			{
				stream << "TARGET: 0x" << std::hex << std::setfill('0') << std::setw(8)
					<< reinterpret_cast<uintptr_t>(get_target()) << "\nIT INSTRUCTIONS COUNT: "
					<< std::dec << instruction_count() << "\nIT REMAINING INSTRUCTIONS COUNT: "
					<< m_remaining_instructions << "\nIT BLOCK:";
				for (size_t i = 0; i != count; ++i)
					stream << "\n\t0x" << std::hex << std::setfill('0') << std::setw(8) << instructions[i].address
						<< ": " << instructions[i].mnemonic << '\t' << instructions[i].op_str;
			}
			catch (...)
			{
				cs_free(instructions, count);
				cs_close(&handle);
				throw;
			}
			cs_free(instructions, count);
			cs_close(&handle);
			return stream.str();
		}

		std::string it_block_exception::it_str() const
		{
			std::stringstream stream;
			csh handle = 0;

			if (cs_insn* instr = disasm_one(handle, m_buffer, m_it_address))
			{
				try
				{
					stream << "0x" << std::hex << std::setfill('0') << std::setw(8)
						<< instr->address << ": " << instr->mnemonic << '\t' << instr->op_str;
				}
				catch (...)
				{
					cleanup(instr, handle);
					throw;
				}
				cleanup(instr, handle);
			}
			return stream.str();
		}

		size_t it_block_exception::instruction_count() const
		{
			return reinterpret_cast<const THUMB_IT*>(m_buffer)->instruction_count();
		}

		std::string pc_relative_handling_fail::str() const
		{
			std::stringstream stream;
			csh handle = 0;

			if (cs_insn* instr = disasm_one(handle, m_buffer, reinterpret_cast<uintptr_t>(m_instruction_address)))
			{
				try
				{
					stream << "TARGET: 0x" << std::hex << std::setfill('0') << std::setw(8) << 
						reinterpret_cast<uintptr_t>(get_target()) << '\n';
					stream << "0x" << std::hex << std::setfill('0') << std::setw(8)
						<< instr->address << ": " << instr->mnemonic << '\t' << instr->op_str;
				}
				catch (...)
				{
					cleanup(instr, handle);
					throw;
				}
				cleanup(instr, handle);
			}
			return stream.str();
		}

		const char* os_exception::get_error_string() const noexcept { return strerror(m_error_code); }

		std::string mmap_exception::error_function() const
		{
			std::stringstream stream;
			stream << "mmap(0x" << std::hex << std::setfill('0') << std::setw(8)
				<< reinterpret_cast<uintptr_t>(m_target_address) << ", " << std::dec << m_size
				<< ", " << m_protection << ", " << m_flags << ", " << m_fd << ", " << m_offset << ')';
			return stream.str();
		}

		std::string sigaction_exception::error_function() const
		{
			std::stringstream stream;
			stream << "sigaction(" << m_signal << ", 0x" << std::hex << std::setfill('0')
				<< std::setw(8) << reinterpret_cast<uintptr_t>(m_action) << ", 0x"
				<< std::setfill('0') << std::setw(8) << reinterpret_cast<uintptr_t>(m_old_action)
				<< ')';
			return stream.str();
		}

		std::string thread_process_fail::str() const
		{
			std::stringstream stream;
			stream << "trampoline address: 0x" << std::hex << std::setfill('0') << std::setw(8)
				<< reinterpret_cast<uintptr_t>(m_trampoline_address) << "\ntarget address: 0x"
				<< std::setfill('0') << std::setw(8) << reinterpret_cast<uintptr_t>(m_target_address)
				<< "\nposition: " << std::dec << m_position;
			return stream.str();
		}

		std::string mprotect_exception::error_function() const
		{
			std::stringstream stream;
			stream << "mprotect(" << std::hex << std::setfill('0') << std::setw(8) << reinterpret_cast<uintptr_t>(m_address)
				<< ", " << std::dec << m_length << ", " << m_protection << ')';
			return stream.str();
		}
	}

	void process_frozen_threads(const trampoline& tramp, bool enable_hook, unsigned long& pc);

	size_t thread_freezer::ref_count = 0;
	std::mutex thread_freezer::ref_count_lock{};
	std::atomic_size_t thread_freezer::processed_threads_count{};
	std::shared_mutex thread_freezer::freezer_lock{};
	bool thread_freezer::should_suspend = false;
	struct sigaction thread_freezer::old_action {};
	std::pair<const trampoline*, bool> thread_freezer::args{};
	std::pair<std::atomic_bool, std::tuple<std::byte*, std::byte*, size_t>> thread_freezer::result{};

	void thread_freezer::scan_threads()
	{
		// we don't want to scan threads while another thread is freezing them (or the other way around)
		// but we can have multiple threads scanning the thread list in parallel without issues
		// so this is the perfect use case for a shared lock
		std::shared_lock lock{ freezer_lock };
		pid_t current_tid = gettid();

		for (const fs::directory_entry& entry : fs::directory_iterator("/proc/self/task"))
		{
			pid_t tid = std::stoi(entry.path().stem().string());
			if (tid == current_tid)
				continue;

			std::ifstream status{ entry.path() / "stat" };
			if (!status.is_open())
				continue;
			char state{};
			status.ignore(std::numeric_limits<std::streamsize>::max(), ')');
			status >> state;

			if (state == 'R')
			{
				if (tids.empty())
					tids.reserve(10);
				tids.push_back(tid);
			}
		}
	}

	void thread_freezer::wait_until_threads_are_processed()
	{
		while (processed_threads_count.load(std::memory_order_acquire) < tids.size())
			std::this_thread::yield();
	}

	bool thread_freezer::suspend(pid_t tid) noexcept
	{
		should_suspend = true;
		return !tgkill(getpid(), tid, SIGURG);
	}

	void thread_freezer::resume(pid_t tid) noexcept
	{
		should_suspend = false;
		tgkill(getpid(), tid, SIGURG);
	}

	void thread_freezer::set_signal_handler()
	{
		struct sigaction act {};
		act.sa_sigaction = thread_control_handler;
		act.sa_flags = SA_RESTART | SA_SIGINFO | SA_ONSTACK;
		sigemptyset(&act.sa_mask);
		// we cannot proceed if signal handler isn't set so this
		// is exception worthy
		if (sigaction(SIGURG, &act, &old_action))
			throw(exceptions::sigaction_exception(errno, SIGURG, &act, &old_action));
	}

	void thread_freezer::unset_signal_handler() noexcept { sigaction(SIGURG, &old_action, nullptr); }

	void thread_freezer::thread_control_handler(int sig, siginfo_t* siginfo, void* sigcontext)
	{
		if (should_suspend)
		{
			if (args.first)
				process_frozen_threads(
					*args.first, args.second,
					static_cast<ucontext_t*>(sigcontext)->uc_mcontext.arm_pc
				);
			processed_threads_count.fetch_add(1, std::memory_order_acq_rel);
			pause();
		}
		else
			processed_threads_count.fetch_add(1, std::memory_order_acq_rel);
	}

	void thread_freezer::init(const trampoline& tramp, bool enable_hook)
	{
		// read only operation, it can work in parallel
		scan_threads();
		{
			std::scoped_lock lock{ ref_count_lock };
			if (!ref_count)
				set_signal_handler();
			++ref_count;
		}
		std::unique_lock lock{ freezer_lock };
		args = { &tramp, enable_hook };
		// iterating with indexes on purpose since we are modifying the list at the same time
		// also note that erase in this case is noexcept
		for (size_t i = 0; i != tids.size(); ++i)
		{
			if (!suspend(tids[i]))
				tids.erase(tids.begin() + i);
		}

		wait_until_threads_are_processed();

		// to be able to freely throw exceptions we first need to resume & unset handler if needed
		if (result.first.load(std::memory_order_relaxed))
		{
			for (pid_t tid : tids)
				resume(tid);
			std::scoped_lock lock { ref_count_lock };
			--ref_count;
			if (!ref_count)
				unset_signal_handler();

			result.first.store(false, std::memory_order_relaxed);
			auto [tramp_addr, target_addr, pos] = result.second;
			throw(exceptions::thread_process_fail(tramp_addr, target_addr, pos));
		}
	}

	void thread_freezer::init(std::nullptr_t)
	{
		scan_threads();
		{
			std::scoped_lock lock{ ref_count_lock };
			if (!ref_count)
				set_signal_handler();
			++ref_count;
		}
		std::unique_lock lock{ freezer_lock };
		args = { nullptr, 0 };

		for (size_t i = 0; i != tids.size(); ++i)
		{
			if (!suspend(tids[i]))
				tids.erase(tids.begin() + i);
		}

		wait_until_threads_are_processed();
	}

	thread_freezer::~thread_freezer() noexcept
	{
		{
			std::unique_lock lock{ freezer_lock };
			for (pid_t tid : tids)
				resume(tid);
		}
		{
			std::scoped_lock lock{ ref_count_lock };
			--ref_count;
			if (!ref_count)
				unset_signal_handler();
		}
	}

	std::pair<bool, int> ALTERHOOK_HIDDEN get_prot(const std::byte* address)
	{
		std::ifstream maps{ "/proc/self/maps" };
		utils_assert(maps.is_open(), "get_prot: couldn't open `/proc/self/maps`");

		do
		{
			uintptr_t begin_address = 0;
			uintptr_t end_address = 0;

			maps >> std::hex >> begin_address;
			maps.seekg(1, std::ios_base::cur);
			maps >> end_address;

			if (reinterpret_cast<uintptr_t>(address) >= begin_address && reinterpret_cast<uintptr_t>(address) < end_address)
			{
				char perms[5]{};
				int result = PROT_NONE;
				maps >> perms;

				if (perms[0] == 'r')
					result |= PROT_READ;
				if (perms[1] == 'w')
					result |= PROT_WRITE;
				if (perms[2] == 'x')
					result |= PROT_EXEC;
				return { true, result };
			}

			maps.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
		} while (maps.good());

		return { false, PROT_NONE };
	}

	bool is_executable_address(const void* address)
	{
		auto [status, value] = get_prot(static_cast<const std::byte*>(address));
		if (status && (value & PROT_EXEC))
			return true;
		return false;
	}

	void ALTERHOOK_HIDDEN inject_to_target(std::byte* target, const std::byte* backup_or_detour, bool patch_above, bool enable, int old_protect)
	{
		utils_assert(target, "inject_to_target: no target address specified");
		utils_assert(backup_or_detour, "inject_to_target: no backup or detour specified");
		const bool uses_thumb = reinterpret_cast<uintptr_t>(target) & 1;
		reinterpret_cast<uintptr_t&>(target) &= ~1;
		const std::array patch_info = { 
			std::pair(target, reinterpret_cast<uintptr_t>(target) % 4 ? sizeof(FULL_JMP_ABS) + 2 : sizeof(FULL_JMP_ABS)),
			std::pair(target - sizeof(uint32_t), sizeof(FULL_JMP_ABS))
		};
		auto [address, size] = patch_info[patch_above];
		std::byte* const prot_addr = reinterpret_cast<std::byte*>(utils_align(reinterpret_cast<uintptr_t>(address), memory_block_size));
		const size_t prot_len = utils_align((address - prot_addr) + size + (memory_block_size - 1), memory_block_size);
		constexpr int protection = PROT_READ | PROT_WRITE | PROT_EXEC;

		if (mprotect(prot_addr, prot_len, protection) == -1)
			throw(exceptions::mprotect_exception(errno, prot_addr, prot_len, protection));
		if (enable)
		{
			std::byte buffer[sizeof(FULL_JMP_ABS) + 2]{};
			if (uses_thumb)
			{
				if (patch_above)
				{
					THUMB2_JMP_ABS tjmp{};
					tjmp.set_offset(address - reinterpret_cast<std::byte*>(utils_align(reinterpret_cast<uintptr_t>(target) + 4, 4)));
					new (buffer) auto(backup_or_detour);
					new (&buffer[sizeof(backup_or_detour)]) auto(tjmp);
				}
				else
				{
					if (reinterpret_cast<uintptr_t>(target) % 4)
					{
						THUMB2_JMP_ABS tjmp{};
						tjmp.set_offset(2);
						new (buffer) auto(tjmp);
						new (&buffer[sizeof(tjmp) + 2]) auto(backup_or_detour);
					}
					else
						new (buffer) THUMB2_FULL_JMP_ABS(reinterpret_cast<uintptr_t>(backup_or_detour));
				}
			}
			else
			{
				if (patch_above)
				{
					JMP_ABS jmp{};
					jmp.set_offset(address - (target + 8));
					new (buffer) auto(backup_or_detour);
					new (&buffer[sizeof(backup_or_detour)]) auto(jmp);
				}
				else
					new (buffer) FULL_JMP_ABS(reinterpret_cast<uintptr_t>(backup_or_detour));
			}
			memcpy(address, buffer, size);
		}
		else
			memcpy(address, backup_or_detour, size);

		mprotect(prot_addr, prot_len, old_protect);
		__alterhook_flush_cache(address, size);
	}

	void ALTERHOOK_HIDDEN patch_jmp(std::byte* target, const std::byte* detour, bool patch_above, int old_protect)
	{
		utils_assert(target, "patch_jmp: no target address specified");
		utils_assert(detour, "patch_jmp: no detour specified");
		reinterpret_cast<uintptr_t&>(target) &= ~1;
		std::byte* address = patch_above ? target - sizeof(uint32_t) :
			reinterpret_cast<uintptr_t>(target) % 4 ? target + sizeof(JMP_ABS) + 2 : target + sizeof(JMP_ABS);
		std::byte* const prot_addr = reinterpret_cast<std::byte*>(utils_align(reinterpret_cast<uintptr_t>(address), memory_block_size));
		const size_t prot_len = utils_align((address - prot_addr) + sizeof(uint32_t) + (memory_block_size - 1), memory_block_size);
		constexpr int protection = PROT_READ | PROT_WRITE | PROT_EXEC;

		if (mprotect(prot_addr, prot_len, protection) == -1)
			throw(exceptions::mprotect_exception(errno, prot_addr, prot_len, protection));	
		*reinterpret_cast<uint32_t*>(address) = reinterpret_cast<uintptr_t>(detour);
		mprotect(prot_addr, prot_len, protection);
		__alterhook_flush_cache(address, sizeof(uint32_t));
	}
}
