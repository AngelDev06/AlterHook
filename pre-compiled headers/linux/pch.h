/* Part of the AlterHook Project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include <capstone/capstone.h>
#include <string.h>
#include <array>
#include <vector>
#include <unordered_map>
#include <list>
#include <unistd.h>
#include <mutex>
#include <shared_mutex>
#include <atomic>
#include <sys/mman.h>
#ifndef __GNUC__
#include <sys/cachectl.h>
#endif
#include <signal.h>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <fstream>
#include <limits>
#include <thread>
#include <bitset>
#include <variant>
#include <optional>
#include "macros.h"
#include "utilities/utils.h"
