/*
 * Copyright (C) 2666680 Ontario Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 */
#include <configs/elf/patcher.h>
#include <elf/patcher.h>
#include <gnomes/apis.h>
#include <gnomes/logger.h>
#include <gnomes/schemas.h>

#include <rapidjson/document.h>

#include <sstream>

#define schema (SCHEMA_APIS[JSONSchema])

static std::string schema_type = "elf_schemas";

struct elf_patcher_config* get_elf_patcher_config(void *json_ptr)
{
    struct elf_patcher_config *ret = nullptr;
    rapidjson::Value *node = (rapidjson::Value*) json_ptr;

    if (!schema->valid(schema_type.c_str(), "elf_patcher_config_schema", node))
        goto exit_get_elf_patcher_config;

    ret = new struct elf_patcher_config();

    if (ret == nullptr)
        goto failed_get_elf_patcher_config;

    ret->num_patches = node->Size();
    ret->patches = new struct elf_patch[ret->num_patches]();

    if (ret->patches == nullptr)
        goto failed_get_elf_patcher_config;

    for (uint64_t i = 0; i < ret->num_patches; ++i) {
        std::string patch_type = (*node)[i]["patch_type"].GetString();
        std::string symbol = (*node)[i]["symbol"].GetString();
        std::string offset = (*node)[i]["offset"].GetString();
        std::stringstream ss;

        rapidjson::Value list;

        uint64_t list_length = 0;

        ss << std::hex << offset;
        ss >> ret->patches[i].offset;

        ret->patches[i].symbol = new char[symbol.length() + 1]();

        if (ret->patches[i].symbol == nullptr)
            goto failed_get_elf_patcher_config;

        strcpy(
            ret->patches[i].symbol,
            symbol.c_str()
        );

        if (patch_type == "inplace") {
            ret->patches[i].patch_type = InplacePatch;
        } else if (patch_type == "additive") {
            ret->patches[i].patch_type = AdditivePatch;
        } else if (patch_type == "destructive") {
            ret->patches[i].patch_type = DestructivePatch;
        } else {
            ret->patches[i].patch_type = NullPatch;
            continue;
        }

        if ((*node)[i].HasMember("assembly")) {
            ret->patches[i].patch_data_type = AssemblyPatch;
            list = (*node)[i]["assembly"].GetArray();
        } else if ((*node)[i].HasMember("binary")) {
            ret->patches[i].patch_data_type = BinaryPatch;
            list = (*node)[i]["binary"].GetArray();
        } else {
            gnomes_warn("Improperly formatted JSON, missing an assembly or binary flag.");
            ret->patches[i].patch_type = NullPatch;
            continue;
        }

        list_length = list.Size();
        switch (ret->patches[i].patch_data_type) {
        case AssemblyPatch: {
            struct elf_assembly_patch *assembly =
                &(ret->patches[i].p.assembly);

            assembly->num_instrs = list_length;
            assembly->instructions = new char*[list_length]();

            if (assembly->instructions == nullptr)
                goto failed_get_elf_patcher_config;

            for (uint64_t j = 0; j < list_length; ++j) {
                std::string assembly_instruction = list[j].GetString();

                assembly->instructions[j] =
                    new char[assembly_instruction.length() + 1]();

                if (assembly->instructions[j] == nullptr)
                    goto failed_get_elf_patcher_config;

                strcpy(
                    assembly->instructions[j],
                    assembly_instruction.c_str()
                );
            }
            break;
        }
        case BinaryPatch: {
            struct elf_binary_patch *binary =
                &(ret->patches[i].p.binary);

            binary->size = list_length;
            binary->data = new uint8_t[list_length]();

            if (binary->data == nullptr)
                goto failed_get_elf_patcher_config;

            for (uint64_t j = 0; j < list_length; ++j) {
                std::string d = list[j].GetString();
                std::stringstream ss;

                uint64_t offset = 0;

                ss << std::hex << d;
                ss >> offset;

                if (offset > 0xFF) {
                    gnomes_error("Incorrect binary patch data at: %d", j);
                    goto failed_get_elf_patcher_config;
                }

                binary->data[j] = uint8_t(offset);
            }

            if (!((*node)[i].HasMember("binary_relocs"))) break;

            list = (*node)[i]["binary_relocs"].GetArray();
            list_length = list.Size();

            binary->reloc_size = list_length;
            if (!binary->reloc_size) break;

            binary->reloc_data = new struct elf_binary_reloc[binary->reloc_size]();
            if (binary->reloc_data == nullptr) goto failed_get_elf_patcher_config;

            for (uint64_t j = 0; j < list_length; ++j) {
                std::string d = list[j]["offset"].GetString();
                std::string symbol = list[j]["symbol"].GetString();
                std::stringstream ss;

                ss << std::hex << d;
                ss >> binary->reloc_data[j].offset;

                binary->reloc_data[j].symbol = new char[symbol.length() + 1]();
                if (binary->reloc_data[j].symbol == nullptr)
                    goto failed_get_elf_patcher_config;

                strcpy(
                    binary->reloc_data[j].symbol,
                    symbol.c_str()
                );
            }

            break;
        }
        default:
            gnomes_warn("Invalid patch type, ignoring patch.");
            ret->patches[i].patch_type = NullPatch;
            break;
        }
    }

    goto exit_get_elf_patcher_config;

failed_get_elf_patcher_config:
    gnomes_error("Failed with creating the ELF patcher config.");
    free_elf_patcher_config(ret);
    ret = nullptr;

exit_get_elf_patcher_config:
    return ret;
}

struct elf_patcher_config* parse_elf_patcher_config(const char *json_str)
{
    struct elf_patcher_config *ret = nullptr;
    rapidjson::Document doc;
    rapidjson::ParseResult ok = doc.Parse(json_str);
    rapidjson::Value node;

    if (!ok) {
        GNOMES_ERROR << "Error parsing: \"" << json_str << "\":\n" << ok.Code() << "\n";
        goto exit_parse_elf_patcher_config;
    }

    if (!doc.IsArray()) {
        GNOMES_ERROR << "Failed to read json as an array.\n";
        goto exit_parse_elf_patcher_config;
    }

    node = doc.GetArray();
    ret = get_elf_patcher_config(&node);

exit_parse_elf_patcher_config:
    return ret;
}

void free_elf_patcher_patch(struct elf_patch *patch)
{
    if (patch->symbol) delete patch->symbol;

    switch (patch->patch_data_type) {
    case AssemblyPatch:
        for (uint64_t j = 0;
             j < patch->p.assembly.num_instrs &&
                 patch->p.assembly.instructions != nullptr &&
                 patch->p.assembly.instructions[j] != nullptr;
             ++j)
            delete patch->p.assembly.instructions[j];
        if (patch->p.assembly.instructions) free(patch->p.assembly.instructions);
        break;
    case BinaryPatch:
        for (uint64_t j = 0;
             j < patch->p.binary.reloc_size &&
                 patch->p.binary.reloc_data != nullptr;
             ++j)
            if (patch->p.binary.reloc_data[j].symbol)
                delete patch->p.binary.reloc_data[j].symbol;
        if (patch->p.binary.reloc_data) delete patch->p.binary.reloc_data;
        if (patch->p.binary.data) delete patch->p.binary.data;
        break;
    default:
        gnomes_warn("Patching data type is not supported.");
        break;
    }
}

void free_elf_patcher_config(struct elf_patcher_config *config)
{
    if (config == nullptr) return;

    for (uint64_t i = 0; i < config->num_patches && config->patches != nullptr; ++i) {
        struct elf_patch *patch = &(config->patches[i]);
        free_elf_patcher_patch(patch);
    }

    if (config->patches) delete config->patches;
    delete config;
}
