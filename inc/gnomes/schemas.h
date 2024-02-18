/*
 * Copyright (C) 2666680 Ontario Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 */
#ifndef GNOMES_SCHEMAS_H
#define GNOMES_SCHEMAS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*! \brief API for initializing a schema.
 *
 * API to help perform schema validation.
 */
struct GnomeSchemaAPI {
    uint8_t inited;                                         //!< If we are initialized or not.
    uint8_t (*init)(void);                                  //!< Initialized the schema information.
    uint8_t (*valid)(
        const char*, const char*, void*
    );                                                      //!< Checks if the schema is valid.
};

/*! \brief JSON Schema API.
 *
 * This is the schema API for JSON validation.
 */
extern struct GnomeSchemaAPI json_schema_api;

#ifdef __cplusplus
};
#endif

#endif
