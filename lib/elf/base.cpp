/*
 * Copyright (C) 2666680 Ontario Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 */
#include <elf/base.hpp>
#include <gnomes/logger.h>

#include <elf.h>

uint8_t elf_find_symbol_offset(
    ELFIO::symbol_section_accessor *syms,
    const std::string &symbol,
    uint64_t *offset,
    uint64_t *index,
    uint16_t *section_idx
)
{
    uint8_t ret = 0;

    if (syms == nullptr) return ret;

    for (uint64_t i = 0; i < syms->get_symbols_num(); ++i) {
        std::string name;
        ELFIO::Elf64_Addr value;
        ELFIO::Elf_Xword size;
        uint8_t bind;
        uint8_t type;
        ELFIO::Elf_Half section_index;
        uint8_t other;

        syms->get_symbol(
            i, name, value, size, bind,
            type, section_index, other
        );

        if (symbol == name) {
            ret = 1;
            if (offset != nullptr) *offset = value;
            if (index != nullptr) *index = i;
            if (section_idx != nullptr) *section_idx = section_index;
            break;
        }
    }

    return ret;
}

uint8_t elf_find_string_offset(
    ELFIO::string_section_accessor *strs,
    const std::string &str,
    uint32_t *offset
)
{
    uint8_t ret = 0;
    uint64_t i = 0;

    if (strs == nullptr) return ret;

    while (strs->get_string(i) != nullptr) {
        std::string s = strs->get_string(i);
        if (s == str) {
            ret = 1;
            break;
        }
        ++i;
    }

    if (ret && offset != nullptr)
        *offset = i;

    return ret;
}

std::vector<struct elf_reloc_info> elf_find_relocation_indexs(
    ELFIO::relocation_section_accessor *rela,
    uint64_t symbol_idx
)
{
    std::vector<struct elf_reloc_info> ret;

    if (rela == nullptr) return ret;

    for (uint64_t i = 0; i < rela->get_entries_num(); ++i) {
        struct elf_reloc_info reloc_info = {};

        reloc_info.index = i;

        if (rela->get_entry(reloc_info.index, reloc_info.offset, reloc_info.symbol, reloc_info.type, reloc_info.addend) &&
            symbol_idx == reloc_info.symbol) {
            ret.push_back(reloc_info);
        }
    }

    return ret;
}

std::pair<std::string, uint64_t> elf_find_symbol_offset(
    ELFIO::symbol_section_accessor *syms,
    uint64_t offset
)
{
    std::pair<std::string, uint64_t> ret;

    uint64_t lower_offset = 0;

    if (syms == nullptr) return ret;

    for (uint64_t i = 0; i < syms->get_symbols_num(); ++i) {
        std::string name;
        ELFIO::Elf64_Addr value;
        ELFIO::Elf_Xword size;
        uint8_t bind;
        uint8_t type;
        ELFIO::Elf_Half section_index;
        uint8_t other;

        syms->get_symbol(
            i, name, value, size, bind,
            type, section_index, other
        );

        if (value > lower_offset && value < offset) {
            ret.first = name;
            ret.second = offset - value;
            lower_offset = value;
        }
    }

    return ret;
}

void elf_patch_relocations(
    ELFIO::elfio *elf,
    ELFIO::section *rsec,
    const uint64_t lower_bound,
    const uint64_t upper_bound,
    int64_t net_diff
)
{
    if (elf == nullptr || rsec == nullptr) return;

    ELFIO::relocation_section_accessor rela(*elf, rsec);
    const char *rela_data = rsec->get_data();

    char *new_rela_data = new char[rsec->get_size()];

    uint64_t i = 0;
    uint64_t j = 0;

    gnomes_debug("Relocation entries have a size of: %ld", rela.get_entries_num());
    for (i = 0; i < rela.get_entries_num(); ++i) {
        struct elf_reloc_info reloc_info = {};

        reloc_info.index = i;

        if (rela.get_entry(reloc_info.index, reloc_info.offset, reloc_info.symbol, reloc_info.type, reloc_info.addend)) {
            const uint64_t copy_size = 0x18;

            if (reloc_info.offset >= lower_bound && reloc_info.offset <= upper_bound) {
                gnomes_debug("Deleting relocation entry index: %d", reloc_info.index);
                continue;
            }

            memcpy(
                new_rela_data + j,
                rela_data + i * copy_size,
                copy_size
            );

            if (reloc_info.offset > lower_bound && net_diff != 0) {
                reloc_info.offset += net_diff;
                memcpy(
                    new_rela_data + j,
                    &reloc_info.offset,
                    sizeof(reloc_info.offset)
                );
            }

            j += copy_size;
        }
    }

    rsec->set_data(new_rela_data, j);

    gnomes_debug("Relocation entries have a size of: %ld", rela.get_entries_num());

    delete new_rela_data;
}

void elf_patch(
    ELFIO::elfio *elf,
    ELFIO::section *symtab,
    ELFIO::section *osec,
    ELFIO::section *rsec,
    const uint64_t fn_offset,
    const uint64_t lower_bound,
    struct elf_binary_patch *bin,
    int64_t net_diff
)
{
    if (elf == nullptr ||
        symtab == nullptr ||
        osec == nullptr ||
        bin == nullptr ||
        (osec->get_size() + net_diff) < 0)
        return;

    const uint64_t upper_bound = lower_bound + bin->size;

    ELFIO::symbol_section_accessor syms(*elf, symtab);
    const char *data = osec->get_data();

    char *new_data = new char[osec->get_size() + net_diff];
    char *new_sym_data = new char[symtab->get_size()];

    uint64_t i = 0;
    uint64_t j = 0;

    uint64_t next_func = 0xFFFFFFFFFFFFFFFF;

    void *og_sym = nullptr;

    gnomes_debug("Text section now has a size of: %ld", osec->get_size());

    memcpy(
        new_sym_data,
        symtab->get_data(),
        symtab->get_size()
    );

    if (net_diff == 0) {
        memcpy(
            new_data,
            data,
            osec->get_size()
        );
        memcpy(
            new_data + lower_bound,
            bin->data,
            bin->size
        );
    } else if (net_diff < 0) {
        memcpy(
            new_data,
            data,
            lower_bound
        );
        memcpy(
            new_data + lower_bound,
            data + upper_bound,
            osec->get_size() - upper_bound
        );
    } else if (net_diff > 0) {
        memcpy(
            new_data,
            data,
            lower_bound
        );
        memcpy(
            new_data + lower_bound,
            bin->data,
            bin->size
        );
        memcpy(
            new_data + upper_bound,
            data + lower_bound,
            osec->get_size() - lower_bound
        );
    }

    gnomes_debug("Symbols section originally has %ld symbols", syms.get_symbols_num());

    for (i = 0, j = 0; i < syms.get_symbols_num(); ++i) {
        if (elf->get_class() == ELFCLASS64) {
            Elf64_Sym *sym_info = &((Elf64_Sym*) new_sym_data)[i];
            if (sym_info->st_value > lower_bound &&
                sym_info->st_value <= upper_bound &&
                i != syms.get_symbols_num()) {
                if (og_sym != nullptr) ((Elf64_Sym*) og_sym)->st_size += sym_info->st_size;
                memcpy(
                    sym_info,
                    &sym_info[i],
                    (syms.get_symbols_num() - (i + 1)) * sizeof(Elf64_Sym)
                );
                continue;
            }
            if (fn_offset == sym_info->st_value) {
                og_sym = (void*) sym_info;
                sym_info->st_size += net_diff;
            }
            if (sym_info->st_value > lower_bound) {
                if (sym_info->st_value < next_func) next_func = sym_info->st_value;
                sym_info->st_value += net_diff;
            }
            j += sizeof(Elf64_Sym);
        } else {
            Elf32_Sym *sym_info = &((Elf32_Sym*) new_sym_data)[i];
            if (sym_info->st_value > lower_bound &&
                sym_info->st_value <= upper_bound &&
                i != syms.get_symbols_num()) {
                if (og_sym != nullptr) ((Elf32_Sym*) og_sym)->st_size += sym_info->st_size;
                memcpy(
                    sym_info,
                    &sym_info[i],
                    (syms.get_symbols_num() - (i + 1)) * sizeof(Elf32_Sym)
                );
                continue;
            }
            if (fn_offset == sym_info->st_value) {
                og_sym = (void*) sym_info;
                sym_info->st_size += net_diff;
            }
            if (sym_info->st_value > lower_bound) {
                if (sym_info->st_value < next_func) next_func = sym_info->st_value;
                sym_info->st_value += net_diff;
            }
            j += sizeof(Elf32_Sym);
        }
    }

    elf_patch_relocations(elf, rsec, lower_bound, upper_bound, net_diff);

    symtab->set_data(new_sym_data, j);
    osec->set_data(new_data, osec->get_size() + net_diff);

    gnomes_debug("Text section now has a size of: %ld", osec->get_size());
    gnomes_debug("After deletion of unused symbols symbols table has %ld symbols", syms.get_symbols_num());

    delete new_data;
    delete new_sym_data;
}
