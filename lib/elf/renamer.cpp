/*
 * Copyright (C) 2666680 Ontario Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 */
#include <elf/base.hpp>
#include <elf/renamer.h>
#include <gnomes/editor.h>
#include <gnomes/logger.h>

#include <elfio/elfio.hpp>

#include <mutex>
#include <set>

#include <elf.h>

static std::mutex mut;

static uint8_t init(
    struct gnome_info *gnome_data,
    void *ptr
)
{
    uint8_t ret = 0;
    std::lock_guard<std::mutex> init_lock(mut);

    if (gnome_data->is_valid) {
        gnome_data->is_valid = 0;
    }

    if (ptr != nullptr)
        gnome_data->config_ptr = ptr;

    ret = 1;

    return ret;
}

static int edit_bin(
    struct gnome_info *gnome_data,
    const char *binary
)
{
    int ret = 0;
    struct elf_renamer_config *config = nullptr;
    ELFIO::elfio *elf = nullptr;
    ELFIO::section *symtab = nullptr;
    ELFIO::section *strtab = nullptr;
    std::string file_name = binary == nullptr ? "N/A" : binary;
    std::lock_guard<std::mutex> edit_lock(mut);

    if (gnome_data->output == nullptr) {
        elf = new ELFIO::elfio();
        if (elf == nullptr || (binary != nullptr && !elf->load(file_name))) {
            gnomes_error("Could not load file %s", binary);
            ret = ENOENT;
            goto exit_edit_bin;
        } else if (binary == nullptr) {
            ret = ENOENT;
            goto exit_edit_bin;
        }
        gnome_data->output = (void*) elf;
    } else
        elf = (ELFIO::elfio*) gnome_data->output;

    if (gnome_data->config_ptr == nullptr) {
        gnomes_error("Invalid configuration.");
        if (gnome_data->output != nullptr) delete ((ELFIO::elfio*) gnome_data->output);
        gnome_data->output = nullptr;
        ret = EINVAL;
        goto exit_edit_bin;
    }

    config = (struct elf_renamer_config*) gnome_data->config_ptr;

    gnomes_notice("Loaded %s inside the ELF Renamer GNOME", binary);

    for (uint32_t i = 0; i < elf->sections.size(); ++i) {
        ELFIO::section *psec = elf->sections[i];
        gnomes_info("\t[%d] %s\t%d", i, psec->get_name().c_str(), psec->get_type());

        if (psec->get_name() == ".symtab" && psec->get_type() == SHT_SYMTAB) {
            symtab = psec;
        } else if (psec->get_name() == ".strtab" && psec->get_type() == SHT_STRTAB) {
            strtab = psec;
        }
    }

    if (symtab != nullptr &&
        strtab != nullptr) {
        for (uint64_t i = 0; i < config->num_symbols; ++i) {
            ELFIO::string_section_accessor str_section(strtab);

            struct elf_renamer_symbol *symbol = &config->symbols[i];

            std::string old_symbol = symbol->old_symbol;
            std::string new_symbol = symbol->new_symbol;

            uint32_t string_idx = 0;
            const int32_t string_diff = new_symbol.size() - old_symbol.size();

            char *new_symbol_data = nullptr;
            char *new_string_data = nullptr;

            const char *string_data = strtab->get_data();

            if (!elf_find_string_offset(&str_section, old_symbol, &string_idx)) {
                gnomes_warn("Symbol %s is not found inside the binary: %s", symbol->old_symbol, binary);
                continue;
            }

            new_symbol_data = new char[symtab->get_size()]();
            new_string_data = new char[strtab->get_size() + string_diff + 1]();

            gnomes_info("Adding symbol %s to the binary %s", symbol->new_symbol, binary);

            memcpy(new_symbol_data, symtab->get_data(), symtab->get_size());
            memcpy(new_string_data, string_data, string_idx);
            memcpy(new_string_data + string_idx, symbol->new_symbol, new_symbol.size());
            memcpy(
                new_string_data + string_idx + new_symbol.size(),
                string_data + string_idx + old_symbol.size(),
                strtab->get_size() - (string_idx + old_symbol.size())
            );

            for (uint64_t j = 0; j < symtab->get_size();) {
                if (elf->get_class() == ELFCLASS64) {
                    Elf64_Sym *sym_info = (Elf64_Sym*) &(new_symbol_data[j]);
                    if (sym_info->st_name > string_idx) sym_info->st_name += string_diff;
                    j += sizeof(Elf64_Sym);
                } else if (elf->get_class() == ELFCLASS32) {
                    Elf32_Sym *sym_info = (Elf32_Sym*) &(new_symbol_data[j]);
                    if (sym_info->st_name > string_idx) sym_info->st_name += string_diff;
                    j += sizeof(Elf32_Sym);
                }
            }

            symtab->set_data(new_symbol_data, symtab->get_size());
            strtab->set_data(new_string_data, strtab->get_size() + string_diff + 1);

            delete new_symbol_data;
            delete new_string_data;
        }

        gnome_data->is_valid = 1;
    }

exit_edit_bin:
    return ret;
}

static int extract(
    struct gnome_info *gnome_data,
    void *output_buffer
)
{
    int ret = 0;
    std::lock_guard<std::mutex> extract_lock(mut);

    if (gnome_data->is_valid) {
        ELFIO::elfio *elf = (ELFIO::elfio*) gnome_data->output;
        ret = elf->save((const char*) output_buffer);
        gnomes_info("Wrote into file: %s", (const char*) output_buffer);
        gnome_data->is_valid = 0;
        if (gnome_data->output != nullptr) {
            delete ((ELFIO::elfio*) gnome_data->output);
            gnome_data->output = nullptr;
        }
    } else {
        gnomes_error("Output data is not valid yet.");
        ret = EINVAL;
    }

    return ret;
}

const struct GnomeEditorAPI gnome_elf_renamer_api = {
.init = init,
.edit_bin = edit_bin,
.extract = extract
};
