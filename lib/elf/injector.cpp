/*
 * Copyright (C) 2666680 Ontario Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 */
#include <elf/base.hpp>
#include <elf/editor.hpp>
#include <elf/injector.h>
#include <gnomes/editor.h>
#include <gnomes/logger.h>

#include <algorithm>
#include <mutex>
#include <set>

#include <elf.h>

static std::mutex mut;

template <typename W, typename S, typename H>
static std::set<uint64_t> get_blacklist_offsets(
    std::shared_ptr<ELFSection<H>> hashtab,
    std::shared_ptr<ELFSection<H>> strtab,
    std::shared_ptr<ELFSection<H>> symtab,
    struct elf_injector_symbol *symbol
)
{
    std::set<uint64_t> ret;

    for (uint64_t i = 0; i < symbol->num_blacklisted; ++i) {
        const struct elf_injector_blacklisted_symbol *blacklisted_symbol =
            &symbol->blacklist[i];
        std::string sym_name = blacklisted_symbol->symbol;
        S *sym = elf_find_sym<W, S, H>(hashtab, strtab, symtab, sym_name);

        if (sym != nullptr)
            ret.insert(sym->st_value);
    }

    return ret;
}

static int edit_bin(
    struct gnome_info *gnome_data,
    ELFFormat *bin
)
{
    int ret = EINVAL;
    struct elf_injector_config *config =
        (struct elf_injector_config*) gnome_data->config_ptr;

    gnomes_notice("Running function injector GNOME...");

    for (uint64_t i = 0; i < config->num_symbols; ++i) {
        struct elf_injector_symbol *symbol = &config->symbols[i];

        std::string old_symbol = symbol->old_symbol;
        std::string new_symbol = symbol->new_symbol;

        std::set<uint64_t> offsets;

        if (bin->elf64()) {
            Elf64_Sym *new_sym = nullptr;
            Elf64_Sym *old_sym = nullptr;

            std::string rel_name;
            std::string rela_name;

            std::shared_ptr<ELFSection<Elf64_Shdr>> reloctab = nullptr;
            std::shared_ptr<ELFSection<Elf64_Shdr>> hashtab =
                std::static_pointer_cast<ELFSection<Elf64_Shdr>>(bin->hashtab);
            std::shared_ptr<ELFSection<Elf64_Shdr>> strtab =
                std::static_pointer_cast<ELFSection<Elf64_Shdr>>(bin->strtab);
            std::shared_ptr<ELFSection<Elf64_Shdr>> symtab =
                std::static_pointer_cast<ELFSection<Elf64_Shdr>>(bin->symtab);

            offsets = get_blacklist_offsets<Elf64_Word, Elf64_Sym, Elf64_Shdr>(
                hashtab, strtab, symtab, symbol
            );

            old_sym = elf_find_sym<Elf64_Word, Elf64_Sym, Elf64_Shdr>(
                hashtab, strtab, symtab, old_symbol
            );

            if (old_sym == nullptr) {
                gnomes_warn("Symbol %s is not found.", old_symbol.c_str());
                continue;
            }

            new_sym = elf_find_sym<Elf64_Word, Elf64_Sym, Elf64_Shdr>(
                hashtab, strtab, symtab, new_symbol
            );

            if (new_sym == nullptr) {
                gnomes_info("Adding symbol %s to symtable.", new_symbol.c_str());
                ret = elf_add_function<Elf64_Shdr, 64>(
                    hashtab,
                    std::static_pointer_cast<ELFSection<Elf64_Shdr>>(bin->sections[0]),
                    strtab,
                    symtab,
                    new_symbol,
                    0
                );
                new_sym = elf_find_sym<Elf64_Word, Elf64_Sym, Elf64_Shdr>(
                    hashtab, strtab, symtab, new_symbol
                );
            }

            if (ret || new_sym == nullptr) goto failed_edit_bin;

            rel_name = ".rel" + bin->sections[old_sym->st_shndx]->name;
            rela_name = ".rela" + bin->sections[old_sym->st_shndx]->name;

            for (const auto &section : bin->sections) {
                std::shared_ptr<ELFSection<Elf64_Shdr>> s =
                    std::static_pointer_cast<ELFSection<Elf64_Shdr>>(section);
                if (section->name == rel_name && s->hdr->sh_type == SHT_REL) {
                    reloctab = s;
                    break;
                }
                if (section->name == rela_name && s->hdr->sh_type == SHT_RELA) {
                    reloctab = s;
                    break;
                }
            }

            if (reloctab == nullptr) goto failed_edit_bin;

            if (reloctab->hdr->sh_type == SHT_REL) {
                const uint64_t new_idx = (new_sym - symtab->get<Elf64_Sym>(0)) / sizeof(Elf64_Sym);
                for (uint64_t i = 0; i < reloctab->entries<Elf64_Rel>(); ++i) {
                    Elf64_Rel *rel = reloctab->get<Elf64_Rel>(i);
                    Elf64_Sym *sym = symtab->get<Elf64_Sym>(ELF64_R_SYM(rel->r_info));
                    if (sym != old_sym) continue;
                    if ((offsets.find(rel->r_offset) != offsets.end() &&
                         symbol->inverse) ||
                        (offsets.find(rel->r_offset) == offsets.end() &&
                         !symbol->inverse)) {
                        std::pair<Elf64_Sym*, uint64_t> sym_info =
                            elf_find_sym_offset<Elf64_Sym, Elf64_Shdr>(symtab, rel->r_offset);

                        gnomes_notice(
                            "Updating symbol entry: 0x%.8X to 0x%.8X at %s:0x%.8X",
                            ELF64_R_SYM(rel->r_info),
                            new_idx,
                            (*strtab)[sym_info.first->st_name].c_str(),
                            sym_info.second
                        );

                        rel->r_info = ELF64_R_INFO(new_idx, ELF64_R_TYPE(rel->r_info));
                    }
                }
            } else {
                const uint64_t new_idx = (new_sym - symtab->get<Elf64_Sym>(0)) / sizeof(Elf64_Sym);
                for (uint64_t i = 0; i < reloctab->entries<Elf64_Rela>(); ++i) {
                    Elf64_Rela *rela = reloctab->get<Elf64_Rela>(i);
                    Elf64_Sym *sym = symtab->get<Elf64_Sym>(ELF64_R_SYM(rela->r_info));
                    if (sym != old_sym) continue;
                    if ((offsets.find(rela->r_offset) != offsets.end() &&
                         symbol->inverse) ||
                        (offsets.find(rela->r_offset) == offsets.end() &&
                         !symbol->inverse)) {
                        std::pair<Elf64_Sym*, uint64_t> sym_info =
                            elf_find_sym_offset<Elf64_Sym, Elf64_Shdr>(symtab, rela->r_offset);

                        gnomes_notice(
                            "Updating symbol entry: 0x%.8X to 0x%.8X at %s:0x%.8X",
                            ELF64_R_SYM(rela->r_info),
                            new_idx,
                            (*strtab)[sym_info.first->st_name].c_str(),
                            sym_info.second
                        );

                        rela->r_info = ELF64_R_INFO(new_idx, ELF64_R_TYPE(rela->r_info));
                    }
                }
            }
        } else {
            Elf32_Sym *new_sym = nullptr;
            Elf32_Sym *old_sym = nullptr;

            std::string rel_name;
            std::string rela_name;

            std::shared_ptr<ELFSection<Elf32_Shdr>> reloctab = nullptr;
            std::shared_ptr<ELFSection<Elf32_Shdr>> hashtab =
                std::static_pointer_cast<ELFSection<Elf32_Shdr>>(bin->hashtab);
            std::shared_ptr<ELFSection<Elf32_Shdr>> strtab =
                std::static_pointer_cast<ELFSection<Elf32_Shdr>>(bin->strtab);
            std::shared_ptr<ELFSection<Elf32_Shdr>> symtab =
                std::static_pointer_cast<ELFSection<Elf32_Shdr>>(bin->symtab);

            offsets = get_blacklist_offsets<Elf32_Word, Elf32_Sym, Elf32_Shdr>(
                hashtab, strtab, symtab, symbol
            );

            old_sym = elf_find_sym<Elf32_Word, Elf32_Sym, Elf32_Shdr>(
                hashtab, strtab, symtab, old_symbol
            );

            if (old_sym == nullptr) {
                gnomes_warn("Symbol %s is not found.", old_symbol.c_str());
                continue;
            }

            new_sym = elf_find_sym<Elf32_Word, Elf32_Sym, Elf32_Shdr>(
                hashtab, strtab, symtab, new_symbol
            );

            if (new_sym == nullptr) {
                gnomes_info("Adding symbol %s to symtable.", new_symbol.c_str());
                ret = elf_add_function<Elf32_Shdr, 32>(
                    hashtab,
                    std::static_pointer_cast<ELFSection<Elf32_Shdr>>(bin->sections[0]),
                    strtab,
                    symtab,
                    new_symbol,
                    0
                );
                new_sym = elf_find_sym<Elf32_Word, Elf32_Sym, Elf32_Shdr>(
                    hashtab, strtab, symtab, new_symbol
                );
            }

            if (ret || new_sym == nullptr) goto failed_edit_bin;

            rel_name = ".rel" + bin->sections[old_sym->st_shndx]->name;
            rela_name = ".rela" + bin->sections[old_sym->st_shndx]->name;

            for (const auto &section : bin->sections) {
                std::shared_ptr<ELFSection<Elf32_Shdr>> s =
                    std::static_pointer_cast<ELFSection<Elf32_Shdr>>(section);
                if (section->name == rel_name && s->hdr->sh_type == SHT_REL) {
                    reloctab = s;
                    break;
                }
                if (section->name == rela_name && s->hdr->sh_type == SHT_RELA) {
                    reloctab = s;
                    break;
                }
            }

            if (reloctab == nullptr) goto failed_edit_bin;

            if (reloctab->hdr->sh_type == SHT_REL) {
                const uint64_t new_idx = (new_sym - symtab->get<Elf32_Sym>(0)) / sizeof(Elf32_Sym);
                for (uint64_t i = 0; i < reloctab->entries<Elf32_Rel>(); ++i) {
                    Elf32_Rel *rel = reloctab->get<Elf32_Rel>(i);
                    Elf32_Sym *sym = symtab->get<Elf32_Sym>(ELF32_R_SYM(rel->r_info));
                    if (sym != old_sym) continue;
                    if ((offsets.find(rel->r_offset) != offsets.end() &&
                         symbol->inverse) ||
                        (offsets.find(rel->r_offset) == offsets.end() &&
                         !symbol->inverse)) {
                        std::pair<Elf32_Sym*, uint64_t> sym_info =
                            elf_find_sym_offset<Elf32_Sym, Elf32_Shdr>(symtab, rel->r_offset);

                        gnomes_notice(
                            "Updating symbol entry: 0x%.8X to 0x%.8X at %s:0x%.8X",
                            ELF32_R_SYM(rel->r_info),
                            new_idx,
                            (*strtab)[sym_info.first->st_name].c_str(),
                            sym_info.second
                        );

                        rel->r_info = ELF32_R_INFO(new_idx, ELF32_R_TYPE(rel->r_info));
                    }
                }
            } else {
                const uint64_t new_idx = (new_sym - symtab->get<Elf32_Sym>(0)) / sizeof(Elf32_Sym);
                for (uint64_t i = 0; i < reloctab->entries<Elf32_Rela>(); ++i) {
                    Elf32_Rela *rela = reloctab->get<Elf32_Rela>(i);
                    Elf32_Sym *sym = symtab->get<Elf32_Sym>(ELF32_R_SYM(rela->r_info));
                    if (sym != old_sym) continue;
                    if ((offsets.find(rela->r_offset) != offsets.end() &&
                         symbol->inverse) ||
                        (offsets.find(rela->r_offset) == offsets.end() &&
                         !symbol->inverse)) {
                        std::pair<Elf32_Sym*, uint64_t> sym_info =
                            elf_find_sym_offset<Elf32_Sym, Elf32_Shdr>(symtab, rela->r_offset);

                        gnomes_notice(
                            "Updating symbol entry: 0x%.8X to 0x%.8X at %s:0x%.8X",
                            ELF32_R_SYM(rela->r_info),
                            new_idx,
                            (*strtab)[sym_info.first->st_name].c_str(),
                            sym_info.second
                        );

                        rela->r_info = ELF32_R_INFO(new_idx, ELF32_R_TYPE(rela->r_info));
                    }
                }
            }
        }
    }

    gnome_data->is_valid = 1;

    goto exit_edit_bin;

failed_edit_bin:
    gnomes_error("Failure");
    ret = EINVAL;

exit_edit_bin:
    return ret;
}

const struct GnomeEditorAPI gnome_elf_injector_api = {
.init = [](struct gnome_info *data, void *ptr) -> int { return (get_init_function(&mut))(data, ptr); },
.edit_bin = [](struct gnome_info *data, const char *name) -> int {
    return (get_edit_bin_function(edit_bin, &mut))(data, name);
},
.extract = [](struct gnome_info *data, void *ptr) -> int { return (get_extract_function(&mut))(data, ptr); }
};
