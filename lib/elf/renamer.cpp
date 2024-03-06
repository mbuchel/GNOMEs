/*
 * Copyright (C) 2666680 Ontario Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 */
#include <elf/base.hpp>
#include <elf/editor.hpp>
#include <elf/renamer.h>
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
    struct elf_renamer_config *config =
        (struct elf_renamer_config*) gnome_data->config_ptr;

    gnomes_notice("Running function renamer GNOME...");

    for (uint64_t i = 0; i < config->num_symbols; ++i) {
        struct elf_renamer_symbol *symbol = &config->symbols[i];

        std::string old_symbol = symbol->old_symbol;
        std::string new_symbol = symbol->new_symbol;

        const int32_t string_diff = new_symbol.size() - old_symbol.size();

        if (bin->elf64()) {
            uint64_t str_offset = elf_find_str(bin->strtab, old_symbol);

            std::shared_ptr<ELFSection<Elf64_Shdr>> hashtab =
                std::static_pointer_cast<ELFSection<Elf64_Shdr>>(bin->hashtab);
            std::shared_ptr<ELFSection<Elf64_Shdr>> strtab =
                std::static_pointer_cast<ELFSection<Elf64_Shdr>>(bin->strtab);
            std::shared_ptr<ELFSection<Elf64_Shdr>> symtab =
                std::static_pointer_cast<ELFSection<Elf64_Shdr>>(bin->symtab);

            Elf64_Sym *old_sym = elf_find_sym<Elf64_Word, Elf64_Sym, Elf64_Shdr>(
                hashtab, strtab, symtab, old_symbol
            );

            if (old_sym == nullptr || !strtab->remove_str(old_sym->st_name)) {
                gnomes_error("Could not remove the old symbol's name.");
                goto failed_edit_bin;
            }

            if (!strtab->insert(new_symbol, old_sym->st_name)) {
                gnomes_error("Could not insert the new symbol's name.");
                goto failed_edit_bin;
            }

            for (uint64_t i = 0; i < symtab->entries<Elf64_Sym>(); ++i) {
                Elf64_Sym *sym = symtab->get<Elf64_Sym>(i);
                if (sym->st_name > old_sym->st_name) sym->st_name += string_diff;
            }
        } else {
            uint64_t str_offset = elf_find_str(bin->strtab, old_symbol);

            std::shared_ptr<ELFSection<Elf32_Shdr>> hashtab =
                std::static_pointer_cast<ELFSection<Elf32_Shdr>>(bin->hashtab);
            std::shared_ptr<ELFSection<Elf32_Shdr>> strtab =
                std::static_pointer_cast<ELFSection<Elf32_Shdr>>(bin->strtab);
            std::shared_ptr<ELFSection<Elf32_Shdr>> symtab =
                std::static_pointer_cast<ELFSection<Elf32_Shdr>>(bin->symtab);

            Elf32_Sym *old_sym = elf_find_sym<Elf32_Word, Elf32_Sym, Elf32_Shdr>(
                hashtab, strtab, symtab, old_symbol
            );

            if (old_sym == nullptr || !strtab->remove_str(old_sym->st_name)) {
                gnomes_error("Could not remove the old symbol's name.");
                goto failed_edit_bin;
            }

            if (!strtab->insert(new_symbol, old_sym->st_name)) {
                gnomes_error("Could not insert the new symbol's name.");
                goto failed_edit_bin;
            }

            for (uint64_t i = 0; i < symtab->entries<Elf32_Sym>(); ++i) {
                Elf32_Sym *sym = symtab->get<Elf32_Sym>(i);
                if (sym->st_name > old_sym->st_name) sym->st_name += string_diff;
            }
        }
    }

    gnome_data->is_valid = 1;

    goto exit_edit_bin;

failed_edit_bin:
    ret = EINVAL;

exit_edit_bin:
    return ret;
}

const struct GnomeEditorAPI gnome_elf_renamer_api = {
.init = [](struct gnome_info *data, void *ptr) -> int { return (get_init_function(&mut))(data, ptr); },
.edit_bin = [](struct gnome_info *data, const char *name) -> int {
    return (get_edit_bin_function(edit_bin, &mut))(data, name);
},
.extract = [](struct gnome_info *data, void *ptr) -> int { return (get_extract_function(&mut))(data, ptr); }
};
