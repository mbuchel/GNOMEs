/*
 * Copyright (C) 2666680 Ontario Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 */
#include <configs/elf/injector.h>
#include <elf/injector.h>
#include <gnomes/apis.h>
#include <gnomes/logger.h>
#include <gnomes/schemas.h>

#include <rapidjson/document.h>

#include <sstream>

#define schema (SCHEMA_APIS[JSONSchema])

static std::string schema_type = "elf_schemas";

struct elf_injector_config* get_elf_injector_config(void *json_ptr)
{
    struct elf_injector_config *ret = nullptr;
    rapidjson::Value *node = (rapidjson::Value*) json_ptr;

    if (!schema->valid(schema_type.c_str(), "elf_injector_config_schema", node))
        goto exit_get_elf_injector_config;

    ret = new struct elf_injector_config();

    if (ret == nullptr)
        goto failed_get_elf_injector_config;

    ret->num_symbols = node->Size();
    ret->symbols = new struct elf_injector_symbol[ret->num_symbols]();

    if (ret->symbols == nullptr)
        goto failed_get_elf_injector_config;

    for (uint64_t i = 0; i < ret->num_symbols; ++i) {
        std::string old_symbol = (*node)[i]["old_symbol"].GetString();
        std::string new_symbol = (*node)[i]["new_symbol"].GetString();
        rapidjson::Value list;

        ret->symbols[i].old_symbol = new char[old_symbol.length() + 1]();
        ret->symbols[i].new_symbol = new char[new_symbol.length() + 1]();
        ret->symbols[i].relocation_type = (*node)[i]["relocation"].GetInt();

        if (ret->symbols[i].old_symbol == nullptr ||
            ret->symbols[i].new_symbol == nullptr)
            goto failed_get_elf_injector_config;

        strcpy(
            ret->symbols[i].old_symbol,
            old_symbol.c_str()
        );
        strcpy(
            ret->symbols[i].new_symbol,
            new_symbol.c_str()
        );

        if ((*node)[i].HasMember("whitelist")) {
            ret->symbols[i].inverse = 1;
            list = (*node)[i]["whitelist"].GetArray();
        } else if ((*node)[i].HasMember("blacklist")) {
            ret->symbols[i].inverse = 0;
            list = (*node)[i]["blacklist"].GetArray();
        } else {
            gnomes_warn("Improperly formatted JSON, missing a whitelist or a blacklist flag.");
            ret->symbols[i].num_blacklisted = 0;
            continue;
        }

        ret->symbols[i].num_blacklisted = list.Size();
        if (!ret->symbols[i].num_blacklisted) continue;

        gnomes_debug(
            "Got %d %s locations:",
            ret->symbols[i].num_blacklisted,
            ret->symbols[i].inverse ? "whitelisted" : "blacklisted"
        );

        ret->symbols[i].blacklist =
            new struct elf_injector_blacklisted_symbol[ret->symbols[i].num_blacklisted]();
        if (ret->symbols[i].blacklist == nullptr)
            goto failed_get_elf_injector_config;

        for (uint64_t j = 0; j < ret->symbols[i].num_blacklisted; ++j) {
            std::string symbol = list[j]["symbol"].GetString();
            std::string offset = list[j]["offset"].GetString();
            std::stringstream ss;

            ss << std::hex << offset;
            ss >> ret->symbols[i].blacklist[j].offset;

            ret->symbols[i].blacklist[j].symbol = new char[symbol.length() + 1]();

            if (ret->symbols[i].blacklist[j].symbol == nullptr)
                goto failed_get_elf_injector_config;

            strcpy(
                ret->symbols[i].blacklist[j].symbol,
                symbol.c_str()
            );

            gnomes_debug(
                "\tGot a %s symbol at %s:0x%.8X",
                ret->symbols[i].inverse ? "whitelisted" : "blacklisted",
                ret->symbols[i].blacklist[j].symbol,
                ret->symbols[i].blacklist[j].offset
            );
        }
    }

    goto exit_get_elf_injector_config;

failed_get_elf_injector_config:
    gnomes_error("Failed with creating the ELF injector config.");
    free_elf_injector_config(ret);
    ret = nullptr;

exit_get_elf_injector_config:
    return ret;
}

struct elf_injector_config* parse_elf_injector_config(const char *json_str)
{
    struct elf_injector_config *ret = nullptr;
    rapidjson::Document doc;
    rapidjson::ParseResult ok = doc.Parse(json_str);
    rapidjson::Value node;

    if (!ok) {
        GNOMES_ERROR << "Error parsing: \"" << json_str << "\":\n" << ok.Code() << "\n";
        goto exit_parse_elf_injector_config;
    }

    if (!doc.IsArray()) {
        GNOMES_ERROR << "Failed to read json as an array.\n";
        goto exit_parse_elf_injector_config;
    }

    node = doc.GetArray();
    ret = get_elf_injector_config(&node);

exit_parse_elf_injector_config:
    return ret;
}

void free_elf_injector_config(struct elf_injector_config *config)
{
    if (config == nullptr) return;

    for (uint64_t i = 0; i < config->num_symbols && config->symbols != nullptr; ++i) {
        struct elf_injector_symbol *symbol = &(config->symbols[i]);

        if (symbol->old_symbol) delete symbol->old_symbol;
        if (symbol->new_symbol) delete symbol->new_symbol;

        if (symbol->blacklist == nullptr) continue;

        for (uint64_t j = 0; j < symbol->num_blacklisted; ++j) {
            delete symbol->blacklist[j].symbol;
        }
        delete symbol->blacklist;
    }

    if (config->symbols) delete config->symbols;
    delete config;
}
