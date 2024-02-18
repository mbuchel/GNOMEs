/*
 * Copyright (C) 2666680 Ontario Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 */
#include <configs/elf/renamer.h>
#include <elf/renamer.h>
#include <gnomes/apis.h>
#include <gnomes/logger.h>
#include <gnomes/schemas.h>

#include <rapidjson/document.h>

#include <sstream>

#define schema (SCHEMA_APIS[JSONSchema])

static std::string schema_type = "elf_schemas";

struct elf_renamer_config* get_elf_renamer_config(void *json_ptr)
{
    struct elf_renamer_config *ret = nullptr;
    rapidjson::Value *node = (rapidjson::Value*) json_ptr;

    if (!schema->valid(schema_type.c_str(), "elf_renamer_config_schema", node))
        goto exit_get_elf_renamer_config;

    ret = new struct elf_renamer_config();

    if (ret == nullptr)
        goto failed_get_elf_renamer_config;

    ret->num_symbols = node->Size();
    ret->symbols = new struct elf_renamer_symbol[ret->num_symbols]();

    if (ret->symbols == nullptr)
        goto failed_get_elf_renamer_config;

    for (uint64_t i = 0; i < ret->num_symbols; ++i) {
        std::string old_symbol = (*node)[i]["old_symbol"].GetString();
        std::string new_symbol = (*node)[i]["new_symbol"].GetString();
        rapidjson::Value list;

        ret->symbols[i].old_symbol = new char[old_symbol.length() + 1]();
        ret->symbols[i].new_symbol = new char[new_symbol.length() + 1]();

        if (ret->symbols[i].old_symbol == nullptr ||
            ret->symbols[i].new_symbol == nullptr)
            goto failed_get_elf_renamer_config;

        strcpy(
            ret->symbols[i].old_symbol,
            old_symbol.c_str()
        );
        strcpy(
            ret->symbols[i].new_symbol,
            new_symbol.c_str()
        );

        gnomes_debug(
            "Replacing symbol %s with %s",
            ret->symbols[i].old_symbol, ret->symbols[i].new_symbol
        );
    }

    goto exit_get_elf_renamer_config;

failed_get_elf_renamer_config:
    gnomes_error("Failed with creating the ELF renamer config.");
    free_elf_renamer_config(ret);
    ret = nullptr;

exit_get_elf_renamer_config:
    return ret;
}

struct elf_renamer_config* parse_elf_renamer_config(const char *json_str)
{
    struct elf_renamer_config *ret = nullptr;
    rapidjson::Document doc;
    rapidjson::ParseResult ok = doc.Parse(json_str);
    rapidjson::Value node;

    if (!ok) {
        GNOMES_ERROR << "Error parsing: \"" << json_str << "\":\n" << ok.Code() << "\n";
        goto exit_parse_elf_renamer_config;
    }

    if (!doc.IsArray()) {
        GNOMES_ERROR << "Failed to read json as an array.\n";
        goto exit_parse_elf_renamer_config;
    }

    node = doc.GetArray();
    ret = get_elf_renamer_config(&node);

exit_parse_elf_renamer_config:
    return ret;
}

void free_elf_renamer_config(struct elf_renamer_config *config)
{
    if (config == nullptr) return;

    for (uint64_t i = 0; i < config->num_symbols && config->symbols != nullptr; ++i) {
        struct elf_renamer_symbol *symbol = &(config->symbols[i]);

        if (symbol->old_symbol) delete symbol->old_symbol;
        if (symbol->new_symbol) delete symbol->new_symbol;
    }

    if (config->symbols) delete config->symbols;
    delete config;
}
