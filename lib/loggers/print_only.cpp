/*
 * Copyright (C) 2666680 Ontario Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 */
#include <gnomes/logger.h>

#include <utils/colors.h>

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <execinfo.h>
#include <cxxabi.h>

#include <iostream>

//! Log prefix for message.
static const char *log_name[] = {
    [LogFatal] = "fatal",
    [LogError] = "error",
    [LogWarning] = "warning",
    [LogNotice] = "notice",
    [LogInfo] = "info",
    [LogDebug] = "debug"
};

//! Logging color for message.
static const char *log_color[] = {
    [LogFatal] = RED_COLOR,
    [LogError] = RED_COLOR,
    [LogWarning] = YELLOW_COLOR,
    [LogNotice] = BLUE_COLOR,
    [LogInfo] = WHITE_COLOR,
    [LogDebug] = GREEN_COLOR
};

static void log_print(
    enum LogLevel level,
    const char *message,
    ...
)
{
    const char *prefix = log_name[level];
    const char *color = log_color[level];

    if (print_only_logger_api.max >= level) {
        char max_buffer[1024] = {};
        va_list ap;
        va_start(ap, message);
        vsnprintf(max_buffer, 1024, message, ap);
        printf("%s%s:%s %s\n", color, prefix, RESET_COLOR, max_buffer);
        va_end(ap);
    }
}

static std::ostream &get_ostream(enum LogLevel level)
{
    const char *prefix = log_name[level];
    const char *color = log_color[level];

    return std::cout << color << prefix << ":" << RESET_COLOR << " ";
}

//! NOTE: Function shamelessly stolen from:
//        https://panthema.net/2008/0901-stacktrace-demangled/
/** Print a demangled stack backtrace of the caller function to FILE* out. */
static void stacktrace(void)
{
    uint64_t max_frames = 63;
    FILE *out = stdout;
    fprintf(out, "stack trace:\n");

    // storage array for stack trace address data
    void* addrlist[max_frames+1];

    // retrieve current stack addresses
    int addrlen = backtrace(addrlist, sizeof(addrlist) / sizeof(void*));

    if (addrlen == 0) {
        fprintf(out, "  <empty, possibly corrupt>\n");
        return;
    }

    // resolve addresses into strings containing "filename(function+address)",
    // this array must be free()-ed
    char** symbollist = backtrace_symbols(addrlist, addrlen);

    // allocate string which will be filled with the demangled function name
    size_t funcnamesize = 256;
    char* funcname = (char*)malloc(funcnamesize);

    // iterate over the returned symbol lines. skip the first, it is the
    // address of this function.
    for (int i = 1; i < addrlen; i++)
    {
	char *begin_name = 0, *begin_offset = 0, *end_offset = 0;

	// find parentheses and +address offset surrounding the mangled name:
	// ./module(function+0x15c) [0x8048a6d]
	for (char *p = symbollist[i]; *p; ++p)
	{
	    if (*p == '(')
		begin_name = p;
	    else if (*p == '+')
		begin_offset = p;
	    else if (*p == ')' && begin_offset) {
		end_offset = p;
		break;
	    }
	}

	if (begin_name && begin_offset && end_offset
	    && begin_name < begin_offset)
	{
	    *begin_name++ = '\0';
	    *begin_offset++ = '\0';
	    *end_offset = '\0';

	    // mangled name is now in [begin_name, begin_offset) and caller
	    // offset in [begin_offset, end_offset). now apply
	    // __cxa_demangle():

	    int status;
	    char* ret = abi::__cxa_demangle(begin_name,
					    funcname, &funcnamesize, &status);
	    if (status == 0) {
		funcname = ret; // use possibly realloc()-ed string
		fprintf(out, "  %s : %s+%s\n",
			symbollist[i], funcname, begin_offset);
	    }
	    else {
		// demangling failed. Output function name as a C function with
		// no arguments.
		fprintf(out, "  %s : %s()+%s\n",
			symbollist[i], begin_name, begin_offset);
	    }
	}
	else
	{
	    // couldn't parse the line? print the whole line.
	    fprintf(out, "  %s\n", symbollist[i]);
	}
    }

    free(funcname);
    free(symbollist);
}

// NOTE: Shamelessly stolen from: https://stackoverflow.com/questions/7775991/how-to-get-hexdump-of-a-structure-data
void hexDump (
    enum LogLevel level,
    const void * addr,
    const int len
) {
    // Silently ignore silly per-line values.
    const char *desc = log_name[level];
    const char *color = log_color[level];
    const int perLine = 16;

    if (print_only_logger_api.max < level)
        return;

    int i;
    unsigned char buff[perLine+1];
    const unsigned char * pc = (const unsigned char *)addr;

    // Output description if given.

    if (desc != nullptr) printf ("%s%s hexdump:%s\n", color, desc, RESET_COLOR);

    // Length checks.

    if (len == 0 || addr == nullptr) {
        printf("  ZERO LENGTH\n");
        return;
    }
    if (len < 0) {
        printf("  NEGATIVE LENGTH: %d\n", len);
        return;
    }

    // Process every byte in the data.

    for (i = 0; i < len; i++) {
        // Multiple of perLine means new or first line (with line offset).

        if ((i % perLine) == 0) {
            // Only print previous-line ASCII buffer for lines beyond first.

            if (i != 0) printf ("  %s\n", buff);

            // Output the offset of current line.

            printf ("  %04x ", i);
        }

        // Now the hex code for the specific character.

        printf (" %02x", pc[i]);

        // And buffer a printable ASCII character for later.

        if ((pc[i] < 0x20) || (pc[i] > 0x7e)) // isprint() may be better.
            buff[i % perLine] = '.';
        else
            buff[i % perLine] = pc[i];
        buff[(i % perLine) + 1] = '\0';
    }

    // Pad out last line if not exactly perLine characters.

    while ((i % perLine) != 0) {
        printf ("   ");
        i++;
    }

    // And print the final ASCII buffer.

    printf ("  %s\n", buff);
}

struct LoggerAPI print_only_logger_api = {
.max = LogFatal,
.init_data = NULL,
.init = NULL,
.log_print = log_print,
.hex_dump = hexDump,
.stacktrace = stacktrace,
.get_ostream = get_ostream
};
