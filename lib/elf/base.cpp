/*
 * Copyright (C) 2666680 Ontario Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 */
#include <elf/base.hpp>
#include <elf/format.hpp>
#include <gnomes/logger.h>

#include <string.h>

#include <elf.h>

uint32_t elf_hash(const char *name)
{
    uint64_t h = 0, g;

    while (*name) {
        h = (h << 4) + *name++;
        if (g = h & 0xf0000000)
            h ^= g >> 24;
        h &= ~g;
    }

    return h;
}

uint64_t elf_find_str(
    std::shared_ptr<ELFSectionInterface> strs,
    const std::string &str
)
{
    uint64_t ret = 0;
    std::string tmp;

    if (strs == nullptr || str.empty()) goto exit_elf_find_str;

    while (ret < strs->get_size()) {
        tmp = (*strs)[ret];
        if (tmp.empty()) ret += 1;
        else if (tmp == str) break;
        else ret += tmp.size() + 1;
    }

    if (ret >= strs->get_size()) ret = 0;

exit_elf_find_str:
    return ret;
}

template <typename W, typename S, typename H>
S *elf_find_sym(
    std::shared_ptr<ELFSection<H>> hashtab,
    std::shared_ptr<ELFSection<H>> strtab,
    std::shared_ptr<ELFSection<H>> symtab,
    std::string name,
    S *og
)
{
    if (strtab == nullptr || symtab == nullptr) return nullptr;

    if (hashtab == nullptr) {
        for (uint64_t i = 0; i < symtab->template entries<S>(); ++i) {
            S *sym = symtab->template get<S>(i);
            if ((*strtab)[sym->st_name] == name && og != nullptr && sym == og) return sym;
            else if ((*strtab)[sym->st_name] == name && og == nullptr) return sym;
        }
    } else {
        const W bucket_size = *(hashtab->template get<W>(0));
        const W chain_size = *(hashtab->template get<W>(1));
        W *chain = hashtab->template get<W>(2 + bucket_size);
        W chain_idx = *(hashtab->template get<W>(elf_hash(name.c_str()) % bucket_size + 2));

        S *sym = nullptr;
        for (W i = 0;
             chain_idx > 0 &&
                 chain_idx < chain_size &&
                 i < symtab->template entries<S>();
             ++i) {
            sym = symtab->template get<S>(chain_idx);
            if ((*strtab)[sym->st_name] == name && og != nullptr && sym == og) return sym;
            else if ((*strtab)[sym->st_name] == name && og == nullptr) return sym;
            chain_idx = chain[chain_idx];
        }
        return sym;
    }

    return nullptr;
}
#define CREATE_FIND_SYM(X, Y, Z)                                                    \
    template Y *elf_find_sym<X, Y, Z>(                                              \
       std::shared_ptr<ELFSection<Z>>,                                              \
       std::shared_ptr<ELFSection<Z>>,                                              \
       std::shared_ptr<ELFSection<Z>>,                                              \
       std::string,                                                                 \
       Y*                                                                           \
    );

CREATE_FIND_SYM(Elf32_Word, Elf32_Sym, Elf32_Shdr);
CREATE_FIND_SYM(Elf64_Word, Elf64_Sym, Elf64_Shdr);

#undef CREATE_FIND_SYM

template <typename W, typename S, typename H>
void elf_fix_hash_table(
    std::shared_ptr<ELFSection<H>> hashtab,
    std::shared_ptr<ELFSection<H>> strtab,
    std::shared_ptr<ELFSection<H>> symtab
)
{
    if (hashtab == nullptr || strtab == nullptr || symtab == nullptr) return;

    const W og_bucket_size = *(hashtab->template get<W>(0));
    const W og_chain_size = *(hashtab->template get<W>(1));
    const W og_sym_entries = symtab->template entries<S>();

    bool recreate = false;

    W *chain = hashtab->template get<W>(2 + og_bucket_size);

    for (W i = 1; i < og_sym_entries; ++i) {
        S *sym = symtab->template get<S>(i);
        std::string sym_name = (*strtab)[sym->st_name];
        S *nsym = elf_find_sym<W, S, H>(hashtab, strtab, symtab, sym_name, sym);
        W *bucket = hashtab->template get<W>(elf_hash(sym_name.c_str()) % og_bucket_size + 2);
        W chain_idx = nsym == nullptr ? *bucket : (nsym - symtab->template get<S>(0)) / sizeof(S);

        while (nsym != nullptr && nsym != sym) {
            if (chain[chain_idx] == 0) break;
            chain_idx = chain[chain_idx];
            nsym = symtab->template get<S>(chain_idx);
        }

        if (nsym != sym) {
            gnomes_warn("Recreating hash table to add %s", sym_name.c_str());
            recreate = true;
            break;
        }
    }

    if (recreate || og_sym_entries != og_chain_size) {
        hashtab->section_data = std::make_unique<uint8_t[]>((og_bucket_size + og_sym_entries + 2) * sizeof(W));

        memset(hashtab->section_data.get(), 0, (og_bucket_size + og_sym_entries + 2) * sizeof(W));

        ((W*) hashtab->section_data.get())[0] = og_bucket_size;
        ((W*) hashtab->section_data.get())[1] = og_sym_entries;

        chain = hashtab->template get<W>(2 + og_bucket_size);

        for (W i = 1; i < og_sym_entries; ++i) {
            S *sym = symtab->template get<S>(i);
            std::string sym_name = (*strtab)[sym->st_name];
            S *nsym = elf_find_sym<W, S, H>(hashtab, strtab, symtab, sym_name, sym);
            W *bucket = hashtab->template get<W>(elf_hash(sym_name.c_str()) % og_bucket_size + 2);
            W chain_idx = nsym == nullptr ? (*bucket) : (nsym - symtab->template get<S>(0)) / sizeof(S);

            if (nsym == nullptr) {
                *bucket = i;
                continue;
            }

            if (nsym != sym) {
                chain[i] = *bucket;
                *bucket = i;
            }
        }

        hashtab->priv_hdr->sh_size = (og_bucket_size + og_sym_entries + 2) * sizeof(W);
        gnomes_notice("Fixed hash table.", hashtab->get_size());
    }
}
#define CREATE_FIX_HASH_TABLE(X, Y, Z)                                    \
    template void elf_fix_hash_table<X, Y, Z>(                            \
        std::shared_ptr<ELFSection<Z>>,                                   \
        std::shared_ptr<ELFSection<Z>>,                                   \
        std::shared_ptr<ELFSection<Z>>                                    \
    );

CREATE_FIX_HASH_TABLE(Elf32_Word, Elf32_Sym, Elf32_Shdr);
CREATE_FIX_HASH_TABLE(Elf64_Word, Elf64_Sym, Elf64_Shdr);

#undef CREATE_FIX_HASH_TABLE

template <typename X, int bits>
int elf_add_function(
    std::shared_ptr<ELFSection<X>> hash,
    std::shared_ptr<ELFSection<X>> sect,
    std::shared_ptr<ELFSection<X>> strs,
    std::shared_ptr<ELFSection<X>> syms,
    std::string symbol,
    uint64_t offset
)
{
    int ret = EINVAL;

    uint64_t str_offset = 0;

    if (bits != 32 && bits != 64) goto exit_add_function;

    str_offset = elf_find_str(strs, symbol);

    if (str_offset == 0) {
        str_offset = strs->hdr->sh_size;
        strs->append(symbol);
    }

    if (bits == 64) {
        const uint64_t entries = syms->template entries<Elf64_Sym>();
        Elf64_Dyn *dyn = nullptr;
        Elf64_Sym *sym = nullptr;
        uint64_t sym_idx = 0;

        // NOTE: First we iterate through and ensure there is no symbol
        //       currently pointing to that location, if there is we just
        //       rename the function.
        for (sym_idx = 0; sym_idx < entries; ++sym_idx) {
            sym = syms->template get<Elf64_Sym>(sym_idx);
            if (sym->st_shndx == (sect != nullptr ? sect->idx : 0) &&
                sym->st_value == offset)
                break;
        }

        if (sym != nullptr && sym_idx != entries) {
            sym->st_name = str_offset;
            ret = 0;
        } else {
            Elf64_Sym new_sym = {
               .st_name = (Elf64_Word) str_offset,
               .st_info = ELF64_ST_INFO(STB_GLOBAL, STT_NOTYPE),
               .st_other = ELF64_ST_VISIBILITY(STV_DEFAULT),
               .st_shndx = (Elf64_Half) (sect != nullptr ? sect->idx : 0),
               .st_value = (Elf64_Addr) offset,
               .st_size = (Elf64_Xword) 0
            };

            if (syms->template append<Elf64_Sym>(&new_sym))
                sym = syms->template get<Elf64_Sym>(entries);
            else
                goto exit_add_function;
        }

        gnomes_info(
            "Symbol now looks like:\n"
            "\tname: (0x%.8lX) %s\n"
            "\tinfo: 0x%.8lX\n"
            "\tother: 0x%.8lX\n"
            "\tshndx: %d\n"
            "\tvalue: 0x%.8lX\n"
            "\tsize: 0x%.8lX",
            sym->st_name, (*strs)[sym->st_name].c_str(),
            sym->st_info,
            sym->st_other,
            sym->st_shndx,
            sym->st_value,
            sym->st_size
        );

        elf_fix_hash_table<Elf64_Word, Elf64_Sym>(hash, strs, syms);
    } else {
        const uint64_t entries = syms->template entries<Elf32_Sym>();
        Elf32_Sym *sym = nullptr;
        uint64_t sym_idx = 0;

        // NOTE: First we iterate through and ensure there is no symbol
        //       currently pointing to that location, if there is we just
        //       rename the function.
        for (sym_idx = 0; sym_idx < entries; ++sym_idx) {
            sym = syms->template get<Elf32_Sym>(sym_idx);
            if (sym->st_shndx == (sect != nullptr ? sect->idx : 0) &&
                sym->st_value == offset)
                break;
        }

        if (sym != nullptr && sym_idx != entries) {
            sym->st_name = str_offset;
            ret = 0;
        } else {
            Elf32_Sym new_sym = {
               .st_name = (Elf32_Word) str_offset,
               .st_value = (Elf32_Addr) offset,
               .st_size = (Elf32_Word) 0,
               .st_info = ELF32_ST_INFO(STB_GLOBAL, STT_NOTYPE),
               .st_other = ELF32_ST_VISIBILITY(STV_DEFAULT),
               .st_shndx = (Elf32_Half) (sect != nullptr ? sect->idx : 0)
            };

            if (syms->template append<Elf32_Sym>(&new_sym))
                sym = syms->template get<Elf32_Sym>(entries);
            else
                goto exit_add_function;
        }

        gnomes_info(
            "Symbol now looks like:\n"
            "\tname: (0x%.8lX) %s\n"
            "\tinfo: 0x%.8lX\n"
            "\tother: 0x%.8lX\n"
            "\tshndx: %d\n"
            "\tvalue: 0x%.8lX\n"
            "\tsize: 0x%.8lX",
            sym->st_name, (*strs)[sym->st_name].c_str(),
            sym->st_info,
            sym->st_other,
            sym->st_shndx,
            sym->st_value,
            sym->st_size
        );

        elf_fix_hash_table<Elf32_Word, Elf32_Sym>(hash, strs, syms);
    }

    ret = 0;

exit_add_function:
    return ret;
}
#define CREATE_ADD_FUNCTION(X, Y)                                        \
    template int elf_add_function<X, Y>(                                 \
        std::shared_ptr<ELFSection<X>>,                                  \
        std::shared_ptr<ELFSection<X>>,                                  \
        std::shared_ptr<ELFSection<X>>,                                  \
        std::shared_ptr<ELFSection<X>>,                                  \
        std::string,                                                     \
        uint64_t                                                         \
    );

CREATE_ADD_FUNCTION(Elf32_Shdr, 32);
CREATE_ADD_FUNCTION(Elf64_Shdr, 64);

#undef CREATE_ADD_FUNCTION

template <typename S, typename H>
std::pair<S*, uint64_t> elf_find_sym_offset(
    std::shared_ptr<ELFSection<H>> symtab,
    uint64_t offset
)
{
    std::pair<S*, uint64_t> ret = {nullptr, 0};

    uint64_t lower_offset = 0;

    if (symtab == nullptr) return ret;

    for (uint64_t i = 0; i < symtab->template entries<S>(); ++i) {
        S *sym = symtab->template get<S>(i);
        if (sym->st_value > lower_offset && sym->st_value < offset) {
            ret.first = sym;
            ret.second = offset - sym->st_value;
            lower_offset = sym->st_value;
        }
    }

    return ret;
}
#define CREATE_FIND_SYM_OFFSET(X, Y)                                     \
    template std::pair<X*, uint64_t> elf_find_sym_offset(                \
        std::shared_ptr<ELFSection<Y>>,                                  \
        uint64_t                                                         \
    );

CREATE_FIND_SYM_OFFSET(Elf32_Sym, Elf32_Shdr);
CREATE_FIND_SYM_OFFSET(Elf64_Sym, Elf64_Shdr);

#undef CREATE_FIND_SYM_OFFSET

template <typename WORD, typename HDR, typename SYM, typename REL, typename RELA, int bits>
int elf_patch(
    std::shared_ptr<ELFSection<HDR>> hashtab,
    std::shared_ptr<ELFSection<HDR>> strtab,
    std::shared_ptr<ELFSection<HDR>> symtab,
    std::shared_ptr<ELFSection<HDR>> osec,
    std::shared_ptr<ELFSection<HDR>> rsec,
    SYM *sym,
    struct elf_patch *patch,
    int64_t net_diff
)
{
    int ret = EINVAL;

    struct elf_binary_patch *bin_patch = nullptr;

    uint64_t lower_bound;
    uint64_t upper_bound;

    std::vector<uint64_t> entries_to_remove;

    if (bits != 32 && bits != 64) goto exit_patch;

    if (strtab == nullptr ||
        symtab == nullptr ||
        osec == nullptr ||
        sym == nullptr ||
        patch == nullptr ||
        patch->patch_data_type != BinaryPatch)
        goto exit_patch;

    bin_patch = &(patch->p.binary);

    lower_bound = sym->st_value + patch->offset;
    upper_bound = lower_bound + bin_patch->size;

    if (!osec->patch(bin_patch->data, lower_bound, bin_patch->size, net_diff)) {
        gnomes_warn("Could not patch this section.");
        goto exit_patch;
    }

    for (uint64_t i = 0; i < symtab->template entries<SYM>(); ++i) {
        SYM *s = symtab->template get<SYM>(i);
        if (s == sym) {
            sym->st_size += net_diff;
        } else if (s->st_value > lower_bound && s->st_value <= upper_bound) {
            entries_to_remove.push_back(i);
            sym->st_size += s->st_size;
        }
    }

    for (const auto &entry : entries_to_remove)
        symtab->template remove<SYM>(entry);

    entries_to_remove.clear();

    if (rsec->hdr->sh_type == SHT_REL) {
        for (uint64_t i = 0; i < rsec->template entries<REL>(); ++i) {
            REL *rel = symtab->template get<REL>(i);
            if (rel->r_offset > lower_bound && rel->r_offset <= upper_bound)
                entries_to_remove.push_back(i);
        }
    } else {
        for (uint64_t i = 0; i < rsec->template entries<RELA>(); ++i) {
            RELA *rela = symtab->template get<RELA>(i);
            if (rela->r_offset > lower_bound && rela->r_offset <= upper_bound)
                entries_to_remove.push_back(i);
        }
    }

    for (uint64_t i = 0;
         i < bin_patch->reloc_size &&
             bin_patch->reloc_data != nullptr &&
             rsec != nullptr;
         ++i) {
        uint64_t new_sym_idx;
        std::string sym_name = bin_patch->reloc_data[i].symbol;
        SYM *rsym = elf_find_sym<WORD, SYM, HDR>(
            hashtab,
            strtab,
            symtab,
            sym_name
        );

        if (rsym == nullptr) {
            ret = elf_add_function<HDR, bits>(
                hashtab,
                nullptr,
                strtab,
                symtab,
                sym_name,
                0
            );
            rsym = elf_find_sym<WORD, SYM, HDR>(
                hashtab,
                strtab,
                symtab,
                sym_name
            );
        }

        if (rsym == nullptr || ret) {
            gnomes_warn("Symbol %s not added to %s", sym_name.c_str(), symtab->name.c_str());
            goto exit_patch;
        }

        new_sym_idx = (rsym - symtab->template get<SYM>(0)) / sizeof(SYM);

        if (rsec->hdr->sh_type == SHT_REL) {
            REL rel;
            rel.r_offset = sym->st_value + patch->offset + bin_patch->reloc_data[i].offset;
            rel.r_info =
                bits == 64 ?
                ELF64_R_INFO(new_sym_idx, STT_NOTYPE) :
                ELF32_R_INFO(new_sym_idx, STT_NOTYPE);
            rsec->template append<REL>(&rel);
        } else {
            RELA rela;
            rela.r_offset = sym->st_value + patch->offset + bin_patch->reloc_data[i].offset;
            rela.r_info =
                bits == 64 ?
                ELF64_R_INFO(new_sym_idx, STT_NOTYPE) :
                ELF32_R_INFO(new_sym_idx, STT_NOTYPE);
            rela.r_addend = bits == 64 ? ((Elf64_Sword) 0) : (Elf32_Sword) 0;
            rsec->template append<RELA>(&rela);
        }
    }

    ret = 0;

exit_patch:
    return ret;
}
#define CREATE_PATCH(A, B, C, D, E, bits)                                \
    template int elf_patch<A, B, C, D, E, bits>(                         \
        std::shared_ptr<ELFSection<B>>,                                  \
        std::shared_ptr<ELFSection<B>>,                                  \
        std::shared_ptr<ELFSection<B>>,                                  \
        std::shared_ptr<ELFSection<B>>,                                  \
        std::shared_ptr<ELFSection<B>>,                                  \
        C*,                                                              \
        struct elf_patch*,                                               \
        int64_t                                                          \
    );

CREATE_PATCH(Elf32_Word, Elf32_Shdr, Elf32_Sym, Elf32_Rel, Elf32_Rela, 32);
CREATE_PATCH(Elf64_Word, Elf64_Shdr, Elf64_Sym, Elf64_Rel, Elf64_Rela, 64);

#undef CREATE_PATCH
