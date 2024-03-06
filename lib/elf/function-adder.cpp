/*
 * Copyright (C) 2666680 Ontario Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 */
#include <elf/base.hpp>
#include <elf/editor.hpp>
#include <elf/format.hpp>
#include <elf/function-adder.h>
#include <gnomes/editor.h>
#include <gnomes/logger.h>

#include <algorithm>
#include <mutex>
#include <set>

#include <elf.h>

static std::mutex mut;

static int edit_bin(
    struct gnome_info *gnome_data,
    ELFFormat *bin
)
{
    int ret = EINVAL;
    struct elf_function_adder_config *config =
        (struct elf_function_adder_config*) gnome_data->config_ptr;

    gnomes_notice("Running function addition GNOME...");

    for (uint64_t i = 0; i < config->num_symbols; ++i) {
        struct elf_function_adder_symbol *sym = &(config->symbols[i]);
        std::string section_name = sym->section;
        std::string str_section_name =
            sym->str_section == nullptr ? std::string() : sym->str_section;
        std::string sym_section_name = sym->sym_section;
        std::string symbol = sym->symbol;

        std::shared_ptr<ELFSectionInterface> section = nullptr;
        std::shared_ptr<ELFSectionInterface> str_section =
            str_section_name.empty() ? bin->strtab : nullptr;
        std::shared_ptr<ELFSectionInterface> sym_section = nullptr;

        for (auto &s : bin->sections) {
            if (section &&
                str_section &&
                sym_section)
                break;

            if (s->name == sym_section_name && sym_section == nullptr) {
                gnomes_info("Found symbol section %s", sym->sym_section);
                sym_section = s;
            }
            if (s->name == section_name && section == nullptr) {
                gnomes_info("Found section %s", sym->section);
                section = s;
            }

            if (!str_section_name.empty() &&
                s->name == str_section_name &&
                str_section == nullptr) {
                gnomes_info("Found string section %s", sym->str_section);
                str_section = s;
            }
        }

        if (section == nullptr ||
            sym_section == nullptr ||
            str_section == nullptr) {
            gnomes_error("Could not find sections required to add function to.");
            goto exit_edit_bin;
        }

        if (bin->elf64()) {
            ret = elf_add_function<Elf64_Shdr, 64>(
                std::static_pointer_cast<ELFSection<Elf64_Shdr>>(bin->hashtab),
                std::static_pointer_cast<ELFSection<Elf64_Shdr>>(section),
                std::static_pointer_cast<ELFSection<Elf64_Shdr>>(str_section),
                std::static_pointer_cast<ELFSection<Elf64_Shdr>>(sym_section),
                symbol,
                sym->offset
            );
        } else {
            ret = elf_add_function<Elf32_Shdr, 32>(
                std::static_pointer_cast<ELFSection<Elf32_Shdr>>(bin->hashtab),
                std::static_pointer_cast<ELFSection<Elf32_Shdr>>(section),
                std::static_pointer_cast<ELFSection<Elf32_Shdr>>(str_section),
                std::static_pointer_cast<ELFSection<Elf32_Shdr>>(sym_section),
                symbol,
                sym->offset
            );
        }

        if (ret) goto exit_edit_bin;
    }

    gnome_data->is_valid = 1;

exit_edit_bin:
    return ret;
}

const struct GnomeEditorAPI gnome_elf_function_adder_api = {
.init = [](struct gnome_info *data, void *ptr) -> int { return (get_init_function(&mut))(data, ptr); },
.edit_bin = [](struct gnome_info *data, const char *name) -> int {
    return (get_edit_bin_function(edit_bin, &mut))(data, name);
},
.extract = [](struct gnome_info *data, void *ptr) -> int { return (get_extract_function(&mut))(data, ptr); }
};
