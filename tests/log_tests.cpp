// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "vrf/log.h"
#include <gtest/gtest.h>

namespace vrf::tests
{

namespace
{

std::vector<std::string> captured_logs{};

// Create a logger that appends to captured_logs vector.
std::shared_ptr<Logger> make_test_logger()
{
    return Logger::Create(
        []() {
            std::array<log_handler_t, log_level_count> log_handlers{};
            log_handlers[static_cast<std::size_t>(LogLevel::INFO)] = [](std::string msg) {
                captured_logs.push_back("[info] " + msg);
            };
            log_handlers[static_cast<std::size_t>(LogLevel::WARN)] = [](std::string msg) {
                captured_logs.push_back("[warning] " + msg);
            };
            log_handlers[static_cast<std::size_t>(LogLevel::ERR)] = [](std::string msg) {
                captured_logs.push_back("[error] " + msg);
            };
            return log_handlers;
        }(),
        []() {
            std::array<flush_handler_t, log_level_count> flush_handlers{};
            flush_handlers[static_cast<std::size_t>(LogLevel::TRACE)] = []() {};
            flush_handlers[static_cast<std::size_t>(LogLevel::DEBUG)] = []() {};
            flush_handlers[static_cast<std::size_t>(LogLevel::INFO)] = []() {};
            flush_handlers[static_cast<std::size_t>(LogLevel::WARN)] = []() {};
            flush_handlers[static_cast<std::size_t>(LogLevel::ERR)] = []() {};
            return flush_handlers;
        }(),
        []() {
            std::array<close_handler_t, log_level_count> close_handlers{};
            close_handlers[static_cast<std::size_t>(LogLevel::TRACE)] = []() { captured_logs.clear(); };
            close_handlers[static_cast<std::size_t>(LogLevel::DEBUG)] = []() { captured_logs.clear(); };
            close_handlers[static_cast<std::size_t>(LogLevel::INFO)] = []() { captured_logs.clear(); };
            close_handlers[static_cast<std::size_t>(LogLevel::WARN)] = []() { captured_logs.clear(); };
            close_handlers[static_cast<std::size_t>(LogLevel::ERR)] = []() { captured_logs.clear(); };
            return close_handlers;
        }());
}

} // namespace

TEST(LogTests, BasicLogging)
{
    // Set the test logger.
    GetOrSetLogger(make_test_logger());

    // Clear any previous logs.
    captured_logs.clear();

    // Log messages at different levels.
    GetLogger()->info("This is an info message.");
    GetLogger()->warn("This is a warning message.");
    GetLogger()->error("This is an error message.");
    GetLogger()->debug("This debug message is not captured.");

    // Verify that the captured logs match expected output.
    ASSERT_EQ(captured_logs.size(), 3);
    EXPECT_EQ(captured_logs[0], "[info] This is an info message.");
    EXPECT_EQ(captured_logs[1], "[warning] This is a warning message.");
    EXPECT_EQ(captured_logs[2], "[error] This is an error message.");

    // Clean up by closing the logger.
    GetLogger()->close();
}

TEST(LogTests, FlushAndClose)
{
    // Set the test logger.
    GetOrSetLogger(make_test_logger());

    // Clear any previous logs.
    captured_logs.clear();

    // Log a message.
    GetLogger()->info("Logging before flush.");

    // Flush the logger (no-op in this test logger).
    GetLogger()->flush();

    // Verify that the log was captured.
    ASSERT_EQ(captured_logs.size(), 1);
    EXPECT_EQ(captured_logs[0], "[info] Logging before flush.");

    // Close the logger, which should clear captured logs.
    GetLogger()->close();

    // Verify that captured logs are cleared after close.
    EXPECT_TRUE(captured_logs.empty());
}

TEST(LogTests, LogLevel)
{
    // Set the test logger.
    GetOrSetLogger(make_test_logger());

    // Clear any previous logs.
    captured_logs.clear();

    GetLogger()->set_level(LogLevel::WARN);

    // Log messages at different levels.
    GetLogger()->info("Info message won't be captured.");
    ASSERT_EQ(captured_logs.size(), 0);

    GetLogger()->warn("Warning message will be captured.");
    GetLogger()->error("Error message will be captured.");
    ASSERT_EQ(captured_logs.size(), 2);

    // Clean up by closing the logger.
    GetLogger()->close();
}

} // namespace vrf::tests
