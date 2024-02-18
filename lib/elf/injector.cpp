/*
 * Copyright (C) 2666680 Ontario Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 */
#include <elf/base.hpp>
#include <elf/injector.h>
#include <gnomes/editor.h>
#include <gnomes/logger.h>

#include <elfio/elfio.hpp>

#include <mutex>
#include <set>

static std::mutex mut;

static std::set<uint64_t> get_blacklist_offsets(
    ELFIO::symbol_section_accessor *syms,
    struct elf_injector_symbol *symbol
)
{
    std::set<uint64_t> ret;

    for (uint64_t i = 0; i < symbol->num_blacklisted; ++i) {
        const struct elf_injector_blacklisted_symbol *blacklisted_symbol =
            &symbol->blacklist[i];
        std::string sym_name = blacklisted_symbol->symbol;
        uint64_t offset = 0;

        if (elf_find_symbol_offset(syms, sym_name, &offset)) {
            const uint32_t new_offset = offset + blacklisted_symbol->offset;
            gnomes_info(
                "\tAdding to %s list: 0x%.8X",
                symbol->inverse ? "whitelist" : "blacklist",
                new_offset
            );
            ret.insert(new_offset);
        }
    }

    return ret;
}

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
    struct elf_injector_config *config = nullptr;
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

    config = (struct elf_injector_config*) gnome_data->config_ptr;

    gnomes_notice("Loaded %s inside the ELF Injector GNOME", binary);

    for (uint32_t i = 0; i < elf->sections.size(); ++i) {
        ELFIO::section *psec = elf->sections[i];
        gnomes_info("\t[%d] %s\t%d", i, psec->get_name().c_str(), psec->get_type());

        if (psec->get_name() == ".symtab" && psec->get_type() == ELFIO::SHT_SYMTAB) {
            symtab = psec;
        } else if (psec->get_name() == ".strtab" && psec->get_type() == ELFIO::SHT_STRTAB) {
            strtab = psec;
        }
    }

    if (symtab != nullptr &&
        strtab != nullptr) {
        ELFIO::symbol_section_accessor sym_section(*elf, symtab);
        ELFIO::string_section_accessor str_section(strtab);

        for (uint64_t i = 0; i < config->num_symbols; ++i) {
            struct elf_injector_symbol *symbol = &config->symbols[i];
            ELFIO::section *osec = nullptr;
            ELFIO::section *rsec = nullptr;

            std::set<uint64_t> offsets = get_blacklist_offsets(&sym_section, symbol);

            std::string old_symbol = symbol->old_symbol;
            std::string new_symbol = symbol->new_symbol;

            std::string rela_name;

            std::vector<struct elf_reloc_info> relocs;

            uint64_t old_offset = 0;
            uint64_t old_idx = 0;
            uint64_t new_offset = 0;
            uint64_t new_idx = 0;

            uint16_t section_idx = 0;

            if (!elf_find_symbol_offset(&sym_section, old_symbol, &old_offset, &old_idx, &section_idx)) {
                gnomes_warn("Symbol %s is not found inside the binary: %s", symbol->old_symbol, binary);
                continue;
            }

            if (!elf_find_symbol_offset(&sym_section, new_symbol, &new_offset, &new_idx)) {
                uint32_t string_idx = 0;

                gnomes_info("Adding symbol %s to the binary %s", symbol->new_symbol, binary);

                if (!elf_find_string_offset(&str_section, new_symbol, &string_idx))
                    string_idx = str_section.add_string(new_symbol);

                new_idx = sym_section.add_symbol(
                    string_idx,
                    0, 0,
                    ELFIO::STB_GLOBAL, 0,
                    0, 0
                );
            }

            rela_name = ".rela" + elf->sections[section_idx]->get_name();

            for (uint32_t j = 0; j < elf->sections.size(); ++j) {
                rsec = elf->sections[j];
                if (rsec->get_name() == rela_name &&
                    rsec->get_type() == ELFIO::SHT_RELA)
                    break;
                rsec = nullptr;
            }

            if (rsec != nullptr) {
                ELFIO::relocation_section_accessor rela_section(*elf, rsec);
                relocs = elf_find_relocation_indexs(&rela_section, old_idx);
                for (const struct elf_reloc_info &reloc_info : relocs) {
                    if ((offsets.find(reloc_info.offset) != offsets.end() &&
                         symbol->inverse) ||
                        (offsets.find(reloc_info.offset) == offsets.end() &&
                         !symbol->inverse)) {
                        std::pair<std::string, uint64_t> sym_info =
                            elf_find_symbol_offset(&sym_section, reloc_info.offset);

                        gnomes_notice(
                            "Updating symbol offset: 0x%.8X to 0x%.8X at %s:0x%.8X",
                            reloc_info.symbol, new_idx, sym_info.first.c_str(), sym_info.second
                        );
                        rela_section.set_entry(
                            reloc_info.index, reloc_info.offset, new_idx,
                            reloc_info.type, reloc_info.addend
                        );
                    }
                }
            }
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

const struct GnomeEditorAPI gnome_elf_injector_api = {
.init = init,
.edit_bin = edit_bin,
.extract = extract
};
