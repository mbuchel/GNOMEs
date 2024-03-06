/*
 * Copyright (C) 2666680 Ontario Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 */
#include <configs/elf/function-adder.h>
#include <elf/function-adder.h>
#include <gnomes/apis.h>
#include <gnomes/logger.h>
#include <gnomes/schemas.h>

#include <rapidjson/document.h>

#include <sstream>

#define schema (SCHEMA_APIS[JSONSchema])

static std::string schema_type = "elf_schemas";

struct elf_function_adder_config* get_elf_function_adder_config(void *json_ptr)
{
    struct elf_function_adder_config *ret = nullptr;
    rapidjson::Value *node = (rapidjson::Value*) json_ptr;

    if (!schema->valid(schema_type.c_str(), "elf_function_adder_config_schema", node))
        goto exit_get_elf_function_adder_config;

    ret = new struct elf_function_adder_config();

    if (ret == nullptr)
        goto failed_get_elf_function_adder_config;

    ret->num_symbols = node->Size();
    ret->symbols = new struct elf_function_adder_symbol[ret->num_symbols]();

    if (ret->symbols == nullptr)
        goto failed_get_elf_function_adder_config;

    for (uint64_t i = 0; i < ret->num_symbols; ++i) {
        std::string sym_section = (*node)[i]["sym_section"].GetString();
        std::string section = (*node)[i]["section"].GetString();
        std::string symbol = (*node)[i]["symbol"].GetString();
        std::string offset = (*node)[i]["offset"].GetString();
        std::stringstream ss;

        ss << std::hex << offset;
        ss >> ret->symbols[i].offset;

        ret->symbols[i].str_section = nullptr;
        ret->symbols[i].section = new char[section.length() + 1]();
        ret->symbols[i].sym_section = new char[sym_section.length() + 1]();
        ret->symbols[i].symbol = new char[symbol.length() + 1]();

        if (ret->symbols[i].symbol == nullptr ||
            ret->symbols[i].section == nullptr ||
            ret->symbols[i].sym_section == nullptr)
            goto failed_get_elf_function_adder_config;

        if ((*node)[i].HasMember("str_section")) {
            std::string str_section = (*node)[i]["str_section"].GetString();
            ret->symbols[i].str_section = new char[section.length() + 1]();
            if (ret->symbols[i].str_section == nullptr)
                goto failed_get_elf_function_adder_config;
            strcpy(
                ret->symbols[i].str_section,
                str_section.c_str()
            );
        }

        strcpy(
            ret->symbols[i].symbol,
            symbol.c_str()
        );
        strcpy(
            ret->symbols[i].section,
            section.c_str()
        );
        strcpy(
            ret->symbols[i].sym_section,
            sym_section.c_str()
        );
    }

    goto exit_get_elf_function_adder_config;

failed_get_elf_function_adder_config:
    gnomes_error("Failed with creating the ELF function_adder config.");
    free_elf_function_adder_config(ret);
    ret = nullptr;

exit_get_elf_function_adder_config:
    return ret;
}

struct elf_function_adder_config* parse_elf_function_adder_config(const char *json_str)
{
    struct elf_function_adder_config *ret = nullptr;
    rapidjson::Document doc;
    rapidjson::ParseResult ok = doc.Parse(json_str);
    rapidjson::Value node;

    if (!ok) {
        GNOMES_ERROR << "Error parsing: \"" << json_str << "\":\n" << ok.Code() << "\n";
        goto exit_parse_elf_function_adder_config;
    }

    if (!doc.IsArray()) {
        GNOMES_ERROR << "Failed to read json as an array.\n";
        goto exit_parse_elf_function_adder_config;
    }

    node = doc.GetArray();
    ret = get_elf_function_adder_config(&node);

exit_parse_elf_function_adder_config:
    return ret;
}

void free_elf_function_adder_config(struct elf_function_adder_config *config)
{
    if (config == nullptr) return;

    for (uint64_t i = 0; i < config->num_symbols && config->symbols != nullptr; ++i) {
        struct elf_function_adder_symbol *symbol = &(config->symbols[i]);

        if (symbol->section) delete [] symbol->section;
        if (symbol->sym_section) delete [] symbol->sym_section;
        if (symbol->symbol) delete [] symbol->symbol;
    }

    if (config->symbols) delete [] config->symbols;
    delete config;
}
