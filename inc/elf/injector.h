/*
 * Copyright (C) 2666680 Ontario Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 */
#ifndef ELF_INJECTOR_H
#define ELF_INJECTOR_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*! \brief Blacklisted symbol + offsets.
 *
 * Some replacements of symbols is not ideal, as a result
 * this structure provides a mechanism to avoid certain
 * replacements.
 */
struct elf_injector_blacklisted_symbol {
    char *symbol;                                          //!< Symbol in which we ignore the relocation.
    uint64_t offset;                                       //!< Offset in that symbol to ignore the relocation requirement.
};

/*! \brief Old symbol + new symbol + blacklisted symbols + inverse.
 *
 * Each old symbol gets replaced with the new symbol, with the exception
 * of the blacklisted substructure. If the inverse flag is set the
 * blacklist is considered a whitelist and only replaces in those regions.
 */
struct elf_injector_symbol {
    uint8_t inverse;                                       //!< If true changes the blacklist to a whitelist.
    uint32_t relocation_type;                              //!< Relocation type.
    char *old_symbol;                                      //!< Old symbol's name.
    char *new_symbol;                                      //!< New symbol's name.
    uint64_t num_blacklisted;                              //!< Number of blacklisted symbols.
    struct elf_injector_blacklisted_symbol *blacklist;     //!< List of blacklist symbols.
};

/*! \brief Injector configuration.
 *
 * This is a vector of elf injector symbols.
 */
struct elf_injector_config {
    uint64_t num_symbols;                                  //!< Number of symbols to inject.
    struct elf_injector_symbol *symbols;                   //!< Array of symbols to inject into the ELF file.
};

#ifdef __cplusplus
};
#endif

#endif
