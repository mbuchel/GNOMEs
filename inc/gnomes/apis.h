/*
 * Copyright (C) 2666680 Ontario Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 */
#ifndef GNOMES_APIS_H
#define GNOMES_APIS_H

#include <gnomes/editor.h>
#include <gnomes/logger.h>
#include <gnomes/schemas.h>

#ifdef __cplusplus
extern "C" {
#endif

/*! These are the different type of logger APIs which we support.
 */
enum SupportedLoggers {
    PrintOnly = 0,                //!< Printing logger only.
    TotalLoggers = 1              //!< Number of supported loggers in the code.
};

//! Logger APIs
extern struct LoggerAPI *LOGGER_APIS[TotalLoggers];

/*! These are the different types of APIs.
 */
enum SupportedGnomes {
    ElfInjector = 0,             //!< Changes the function called with the injected function.
    ElfRenamer = 1,              //!< Renames the functions inside the binary with different function names.
    ElfPatcher = 2,              //!< Automated patching of functions with machine language.
    TotalGnomes = 3              //!< Total number of possible GNOMEs used.
};

//! GNOME editing APIs.
extern const struct GnomeEditorAPI *GNOMES[TotalGnomes];

/*! Different type of schemas we support.
 */
enum SupportedSchemas {
    JSONSchema = 0,              //!< JSON Schema information.
    TotalSchemas = 1             //!< Total number of schema validators we support.
};

//! Schema APIs.
extern struct GnomeSchemaAPI *SCHEMA_APIS[TotalSchemas];

#ifdef __cplusplus
};
#endif

#endif
