/*
 * Copyright (C) 2666680 Ontario Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 */
#include <gnomes/apis.h>

// Logger the code is currently using.
struct LoggerAPI *LOGGER = NULL;

struct LoggerAPI *LOGGER_APIS[TotalLoggers] = {
    &print_only_logger_api
};

const struct GnomeEditorAPI *GNOMES[TotalGnomes] = {
    &gnome_elf_injector_api,
    &gnome_elf_renamer_api,
    &gnome_elf_patcher_api
};

struct GnomeSchemaAPI *SCHEMA_APIS[TotalSchemas] = {
    &json_schema_api
};
