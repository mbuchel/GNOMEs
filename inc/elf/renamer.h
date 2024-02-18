/*
 * Copyright (C) 2666680 Ontario Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 */
#ifndef ELF_RENAMER_H
#define ELF_RENAMER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*! \brief Symbols to rename. */
struct elf_renamer_symbol {
    char *old_symbol;                    //!< Symbol to rename.
    char *new_symbol;                    //!< Symbol to rename to.
};

/*! \brief Renaming configuration. */
struct elf_renamer_config {
    uint32_t num_symbols;                //!< Number of symbols we are renaming.
    struct elf_renamer_symbol *symbols;  //!< Symbols to rename.
};

#ifdef __cplusplus
};
#endif

#endif
