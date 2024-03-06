/*
 * Copyright (C) 2666680 Ontario Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 */
#ifndef ELF_BASE_HPP
#define ELF_BASE_HPP

#include <elf/patcher.h>

#include <elf/format.hpp>

#include <stdint.h>

#include <map>
#include <memory>
#include <utility>
#include <vector>

#ifdef __cplusplus

/*! \brief Performs an ELF hash on the name.
 *
 * If a program is executable, a hash table SHOULD be given, if one
 * exists we need to add all symbols to the elf_hash.
 *
 * NOTES:
 * -# Only SYS-V version of the hash function is implemented.
 *
 * \param name - Name of the symbol
 * \return Hash for the table.
 */
uint32_t elf_hash(const char *name);

/*! \brief Finds a string inside the string table.
 *
 * This is a system to find a string inside the string table.
 *
 * NOTES:
 * -# This function checks to ensure the section pointer passed is actually a string table.
 *
 * \param strs - String section smart pointer.
 * \param str - String to search for.
 * \return 0 If not found, or index if it is found.
 */
uint64_t elf_find_str(
    std::shared_ptr<ELFSectionInterface> strs,
    const std::string &str
);

/*! \brief Finds a pointer to the symbol we are looking for.
 *
 * This is a tool to quickly lookup if a symbol with a particular name already exists.
 *
 * NOTES:
 * -# If we have an empty bucket, this returns the null pointer.
 * -# If we get a value, we need to ensure that the chain is pointing to the correct value.
 * -# To determine the offset you need to perform (ret - symtab->section_data) / sizeof(S)
 * -# This is limited to:
 *    - Elf32_Word, Elf32_Sym, Elf32_Shdr
 *    - Elf64_Word, Elf64_Sym, Elf64_Shdr
 * -# If og is a nullptr, we find the last in the chain, if it is a value than we find that
 *    particular symbol.
 */
template <typename W, typename S, typename H>
S *elf_find_sym(
    std::shared_ptr<ELFSection<H>> hashtab,
    std::shared_ptr<ELFSection<H>> strtab,
    std::shared_ptr<ELFSection<H>> symtab,
    std::string name,
    S *og = nullptr
);

/*! \brief Templated function to help fix the hash tables.
 *
 * This ensures we have a fixed hash table and is used in several locations.
 *
 * NOTES:
 * -# If the hashtab variable is null than we ignore this completely.
 * -# This is limited to:
 *    - Elf32_Word, Elf32_Sym, Elf32_Shdr
 *    - Elf64_Word, Elf64_Sym, Elf64_Shdr
 *
 * \param hashtab - Hashtable to fix.
 * \param strtab - String table to use.
 * \param symtab - Symbol table to use.
 * \return Performed for side effects on the fix hash table.
 */
template <typename W, typename S, typename H>
void elf_fix_hash_table(
    std::shared_ptr<ELFSection<H>> hashtab,
    std::shared_ptr<ELFSection<H>> strtab,
    std::shared_ptr<ELFSection<H>> symtab
);

/*! \brief Templated function to add a function properly to the symtable.
 *
 * This function is used to add functions to the symbol table in a manner that
 * is correct.
 *
 * NOTES:
 * -# Supports Elf32_Shdr with bits = 32
 * -# Supports Elf64_Shdr with bits = 64
 *
 * \param hash - Hashtable for the additional function.
 * \param sect - Section to add it into.
 * \param strs - String table to add it into.
 * \param syms - Symbol table to add it into.
 * \param symbol - Symbol's name.
 * \param offset - Offset of the symbol.
 */
template <typename X, int bits>
int elf_add_function(
    std::shared_ptr<ELFSection<X>> hash,
    std::shared_ptr<ELFSection<X>> sect,
    std::shared_ptr<ELFSection<X>> strs,
    std::shared_ptr<ELFSection<X>> syms,
    std::string symbol,
    uint64_t offset
);

/*! \brief Finds a nice user explained closest symbol.
 *
 * This is a tool to find a symbol + offset inside a binary.
 *
 * \param symtab - Symbol table.
 * \param offset - Offset into the binary.
 * \return Returns a tuple of a symbol name with offset.
 */
template <typename S, typename H>
std::pair<S*, uint64_t> elf_find_sym_offset(
    std::shared_ptr<ELFSection<H>> symtab,
    uint64_t offset
);

/*! \brief Patches an ELF formatted function.
 *
 * This function performs a patch, and modifies the relocation table to handle the patch.
 *
 * \param hashtab - Hash table to add the new function to.
 * \param strtab - String table for function names.
 * \param symtab - Symbol table for functions.
 * \param osec - Section to modify.
 * \param rsec - Relocation section to modify.
 * \param sym - Symbol to modify.
 * \param patch - Patch to apply, must be a binary patch.
 * \param net_diff - Difference in the new function's size.
 */
template <typename WORD, typename HDR, typename SYM, typename REL, typename RELA, int bits>
int elf_patch(
    std::shared_ptr<ELFSection<HDR>> hashtab,
    std::shared_ptr<ELFSection<HDR>> strtab,
    std::shared_ptr<ELFSection<HDR>> symtab,
    std::shared_ptr<ELFSection<HDR>> osec,
    std::shared_ptr<ELFSection<HDR>> rsec,
    SYM *sym,
    struct elf_patch *patch,
    int64_t net_diff = 0
);

#if 0
/*! \brief Patches the relocations between 2 points, removing any of those relocations.
 *
 * This function removes the relocations to provide a new relocation table to prepare
 * a new relocation with corrected information.
 *
 * \param elf - ELF format pointer.
 * \param rsec - This is relocation section information.
 * \param lower_bound - Starting offset for the patch.
 * \param upper_bound - Ending offset for the patch.
 * \param net_diff - Net difference in the pre patch, and current patch file.
 * \return Performed for side effects, if done correctly creates a patch which will
 *         be applied to the file.
 */
void elf_patch_relocations(
    ELFIO::elfio *elf,
    ELFIO::section *rsec,
    const uint64_t lower_bound,
    const uint64_t upper_bound,
    int64_t net_diff = 0
);

/*! \brief Patches the binary between 2 points.
 *
 * This function performs the patching logic on the binary.
 *
 * \param elf - ELF format pointer.
 * \param symtab - Symbol table for relocation patching in case of additive/destructive patches.
 * \param osec - This is the corresponding section to work with.
 * \param rsec - This is relocation section information.
 * \param fn_offset - Function's offset.
 * \param lower_bound - Starting offset for the patch.
 * \param bin - Binary patch to apply to the elf file.
 * \param net_diff - Net difference in the pre patch, and current patch file.
 * \return Performed for side effects, if done correctly creates a patch which will
 *         be applied to the file.
 */
void elf_patch(
    ELFIO::elfio *elf,
    ELFIO::section *symtab,
    ELFIO::section *osec,
    ELFIO::section *rsec,
    const uint64_t fn_offset,
    const uint64_t lower_bound,
    struct elf_binary_patch *bin,
    int64_t net_diff = 0
);
#endif

#endif

#endif
