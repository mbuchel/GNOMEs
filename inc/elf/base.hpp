/*
 * Copyright (C) 2666680 Ontario Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 */
#ifndef ELF_BASE_HPP
#define ELF_BASE_HPP

#include <elf/patcher.h>

#include <elfio/elfio.hpp>

#include <stdint.h>

#include <utility>
#include <vector>

#ifdef __cplusplus

/*! \brief Relocation information for an ELF.
 *
 * This is relocation data for ELF relocation entries.
 */
struct elf_reloc_info {
    uint64_t index;                           //!< Index in the relocation table.
    uint64_t offset;                          //!< Offset the relocation happens at.
    uint32_t symbol;                          //!< Symbol's offset.
    uint32_t type;                            //!< Type of relocation.
    int64_t addend;                           //!< Addend information.
};

/*! \brief Finds the symbol's offset given a string.
 *
 * This is a helper function to find a specific offset to a given symbol name.
 *
 * \param syms - Symbol section pointer.
 * \param symbol - Symbol's name as a string.
 * \param offset - Where the offset is placed into.
 * \param index - Index for the symbol in the symbol table.
 * \param section_idx - Section's index to determine which section the offset is in.
 * \return 1 if symbol is found, 0 if symbol is not found.
 */
uint8_t elf_find_symbol_offset(
    ELFIO::symbol_section_accessor *syms,
    const std::string &symbol,
    uint64_t *offset = nullptr,
    uint64_t *index = nullptr,
    uint16_t *section_idx = nullptr
);

/*! \brief Finds a string's offset given a string.
 *
 * This is a helper function to find a specific offset to a string found.
 *
 * \param strs - Strings section pointer.
 * \param str - String to find in the string table.
 * \param offset - Offset inside the string table.
 * \return 1 if string is found, 0 if string is not found.
 */
uint8_t elf_find_string_offset(
    ELFIO::string_section_accessor *strs,
    const std::string &str,
    uint32_t *offset = nullptr
);

/*! \brief Finds all the relocation indexs
 *
 * This is a helper function to get the relocations.
 *
 * \param rela - Relocation table pointer.
 * \param symbol_idx - Index of the old symbol.
 * \return Returns a vector of all the relocation information.
 */
std::vector<struct elf_reloc_info> elf_find_relocation_indexs(
    ELFIO::relocation_section_accessor *rela,
    uint64_t symbol_idx
);

/*! \brief Finds a nice user explained closest symbol.
 *
 * This is a tool to find a symbol + offset inside a binary.
 *
 * \param syms - Symbol table.
 * \param offset - Offset into the binary.
 * \return Returns a tuple of a symbol name with offset.
 */
std::pair<std::string, uint64_t> elf_find_symbol_offset(
    ELFIO::symbol_section_accessor *syms,
    uint64_t offset
);

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
