// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "vrf/log.h"
#include <iostream>

namespace vrf
{

using enum LogLevel;

std::shared_ptr<Logger> NewDefaultLogger()
{
    std::array<log_handler_t, log_level_count> log_handlers{};
    log_handlers[static_cast<std::size_t>(TRACE)] = [](std::string msg) { std::cerr << "[trace] " << msg << '\n'; };
    log_handlers[static_cast<std::size_t>(DEBUG)] = [](std::string msg) { std::cerr << "[debug] " << msg << '\n'; };
    log_handlers[static_cast<std::size_t>(INFO)] = [](std::string msg) { std::cerr << "[info] " << msg << '\n'; };
    log_handlers[static_cast<std::size_t>(WARN)] = [](std::string msg) { std::cerr << "[warning] " << msg << '\n'; };
    log_handlers[static_cast<std::size_t>(ERR)] = [](std::string msg) { std::cerr << "[error] " << msg << '\n'; };

    std::array<flush_handler_t, log_level_count> flush_handlers{};
    flush_handlers[static_cast<std::size_t>(TRACE)] = []() { std::cerr << std::flush; };
    flush_handlers[static_cast<std::size_t>(DEBUG)] = []() { std::cerr << std::flush; };
    flush_handlers[static_cast<std::size_t>(INFO)] = []() { std::cerr << std::flush; };
    flush_handlers[static_cast<std::size_t>(WARN)] = []() { std::cerr << std::flush; };
    flush_handlers[static_cast<std::size_t>(ERR)] = []() { std::cerr << std::flush; };

    // No special close actions needed for stdout/stderr.
    std::array<close_handler_t, log_level_count> close_handlers{};

    return Logger::Create(std::move(log_handlers), std::move(flush_handlers), std::move(close_handlers));
}

} // namespace vrf
