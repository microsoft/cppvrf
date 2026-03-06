// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "vrf/log.h"

#include <cstddef>
#include <shared_mutex>
#include <string>

namespace vrf
{

std::shared_ptr<Logger> GetOrSetLogger(std::shared_ptr<Logger> new_logger)
{
    static std::shared_mutex mtx;
    static std::shared_ptr<Logger> logger = NewDefaultLogger();
    if (nullptr != new_logger)
    {
        std::unique_lock lock{mtx};
        logger = std::move(new_logger);
        return logger;
    }
    std::shared_lock lock{mtx};
    return logger;
}

void Logger::log(LogLevel level, const std::string &msg) const
{
    const std::size_t level_index = static_cast<std::size_t>(level);
    const std::size_t min_level_index = static_cast<std::size_t>(log_level_);
    if (level_index >= log_level_count || level_index < min_level_index)
    {
        // Invalid log level; ignore.
        return;
    }

    std::scoped_lock lock{mtx_};
    if (log_handlers_[level_index])
    {
        log_handlers_[level_index](msg);
    }
}

void Logger::flush_internal() const
{
    for (std::size_t i = 0; i < log_level_count; i++)
    {
        if (flush_handlers_[i])
        {
            flush_handlers_[i]();
        }
    }
}

void Logger::close_internal()
{
    flush_internal();
    for (std::size_t i = 0; i < log_level_count; i++)
    {
        if (close_handlers_[i])
        {
            close_handlers_[i]();
        }
    }

    // Set all handlers to null after closing.
    log_handlers_.fill(nullptr);
    flush_handlers_.fill(nullptr);
    close_handlers_.fill(nullptr);
}

} // namespace vrf
