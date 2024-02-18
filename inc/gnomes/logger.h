/*
 * Copyright (C) 2666680 Ontario Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 */
#ifndef GNOMES_LOGGER_H
#define GNOMES_LOGGER_H

#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

// #include <utils/types.h>

#ifdef __cplusplus
#include <iostream>

extern "C" {
#endif

//! Code to help our logging system work better.
#define LOG(loglevel, ...)                          \
    {                                               \
    if (LOGGER != NULL &&                           \
        LOGGER->log_print != NULL)                  \
        LOGGER->log_print(loglevel, __VA_ARGS__);   \
    }

#ifdef __cplusplus
//! Code to help our logging system work better for C++.
#define CPP_LOG(loglevel)                           \
    if (LOGGER != NULL &&                           \
        LOGGER->get_ostream != NULL &&              \
        LOGGER->max >= loglevel)                    \
        LOGGER->get_ostream(loglevel)

//! Helper functions for logging for C++.
#define GNOMES_ERROR CPP_LOG(LogError)
#define GNOMES_WARN CPP_LOG(LogWarning)
#define GNOMES_NOTICE CPP_LOG(LogNotice)
#define GNOMES_INFO CPP_LOG(LogInfo)
#define GNOMES_DEBUG CPP_LOG(LogDebug)
#endif

#define STACKTRACE() \
    {                                               \
    if (LOGGER != NULL &&                           \
        LOGGER->stacktrace != NULL)                 \
        LOGGER->stacktrace();                       \
    }

#define HEXDUMP(loglevel, obj)                                  \
    {                                                           \
    if (LOGGER != NULL &&                                       \
        LOGGER->hex_dump != NULL)                               \
        LOGGER->hex_dump(loglevel, (void*) &obj, sizeof(obj));  \
    }

#define HEXDUMP2(loglevel, obj, size)                           \
    {                                                           \
    if (LOGGER != NULL &&                                       \
        LOGGER->hex_dump != NULL)                               \
        LOGGER->hex_dump(loglevel, (void*) obj, size);          \
    }

//! Helper functions for logging.
#define gnomes_fatal(...) {LOG(LogFatal, __VA_ARGS__); exit(1);}
#define gnomes_error(...) LOG(LogError, __VA_ARGS__)
#define gnomes_warn(...) LOG(LogWarning, __VA_ARGS__)
#define gnomes_notice(...) LOG(LogNotice, __VA_ARGS__)
#define gnomes_info(...) LOG(LogInfo, __VA_ARGS__)
#define gnomes_debug(...) LOG(LogDebug, __VA_ARGS__)

//! Helper functions for hex dumps.
#define gnomes_fatal_hexdump(obj) {HEXDUMP(LogFatal, obj); exit(1);}
#define gnomes_error_hexdump(obj) HEXDUMP(LogError, obj)
#define gnomes_warn_hexdump(obj) HEXDUMP(LogWarning, obj)
#define gnomes_notice_hexdump(obj) HEXDUMP(LogNotice, obj)
#define gnomes_info_hexdump(obj) HEXDUMP(LogInfo, obj)
#define gnomes_debug_hexdump(obj) HEXDUMP(LogDebug, obj)

#define gnomes_fatal_hexdump2(obj, n) {HEXDUMP2(LogFatal, obj, n); exit(1);}
#define gnomes_error_hexdump2(obj, n) HEXDUMP2(LogError, obj, n)
#define gnomes_warn_hexdump2(obj, n) HEXDUMP2(LogWarning, obj, n)
#define gnomes_notice_hexdump2(obj, n) HEXDUMP2(LogNotice, obj, n)
#define gnomes_info_hexdump2(obj, n) HEXDUMP2(LogInfo, obj, n)
#define gnomes_debug_hexdump2(obj, n) HEXDUMP2(LogDebug, obj, n)

//! Log levels.
enum LogLevel {
   LogFatal = 0,
   LogError = 1,
   LogWarning = 2,
   LogNotice = 3,
   LogInfo = 4,
   LogDebug = 5
};

/*! \brief Logger API.
 *
 * This is the logging API used in ArcHPC.
 */
struct LoggerAPI {
    enum LogLevel max;                                 //!< Maximum logging level.
    void *init_data;                                   //!< Due to logging logic, we need to also
                                                       //   have a dynamic component inside the
                                                       //   logger.
    uint8_t (*init)(void*);                            //!< Initialization for the logger.
    void (*log_print)(
        enum LogLevel level,
        const char *message,
        ...
    );                                                 //!< Logs a normal printed message to API.
    void (*hex_dump)(
        enum LogLevel level,
        const void *,
        const int
    );                                                 //!< Dumps the hex of a particular binary address.
    void (*stacktrace)(void);                          //!< Dumps the stack trace using the API.
#ifdef __cplusplus
    std::ostream &(*get_ostream)(enum LogLevel level); // C++ Version of log_print.
#endif
};

//! Printing only logger API for only printing.
extern struct LoggerAPI print_only_logger_api;

//! The currently allocated logger.
extern struct LoggerAPI *LOGGER;

#ifdef __cplusplus
};
#endif

#endif
