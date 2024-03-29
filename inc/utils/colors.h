/*
 * Copyright (C) 2666680 Ontario Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 */
#ifndef UTILS_COLORS_H
#define UTILS_COLORS_H

#ifdef __cplusplus
extern "C" {
#endif

//! Prefix for colors.
#define COLOR_PREFIX "\033["

//! Prefix for bold.
#define BOLD COLOR_PREFIX "1m"

//! Red color.
#define RED_COLOR BOLD COLOR_PREFIX "31m"

//! Green color.
#define GREEN_COLOR BOLD COLOR_PREFIX "32m"

//! Yellow color.
#define YELLOW_COLOR BOLD COLOR_PREFIX "33m"

//! Blue color.
#define BLUE_COLOR BOLD COLOR_PREFIX "34m"

//! Magenta color.
#define MAGENTA_COLOR BOLD COLOR_PREFIX "35m"

//! Cyan color.
#define CYAN_COLOR BOLD COLOR_PREFIX "36m"

//! White color.
#define WHITE_COLOR BOLD COLOR_PREFIX "37m"

//! Reset color.
#define RESET_COLOR COLOR_PREFIX "0m"

#ifdef __cplusplus
};
#endif

#endif
