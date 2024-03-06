/*
 * Copyright (C) 2666680 Ontario Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 */
#ifndef ELF_FUNCTION_ADDER_H
#define ELF_FUNCTION_ADDER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*! \brief Offset and symbol.
 *
 * This is a symbol to add/rename at a certain offset in the file.
 */
struct elf_function_adder_symbol {
    char *section;                                         //!< Section for where the symbol is.
    char *str_section;                                     //!< String section to use.
    char *sym_section;                                     //!< Symbol section to export into.
    char *symbol;                                          //!< Function name.
    uint64_t offset;                                       //!< Offset at which place to add a function.
};

/*! \brief Function adder configuration.
 *
 * This is a vector of elf function adder symbols.
 */
struct elf_function_adder_config {
    uint64_t num_symbols;                                  //!< Number of symbols to add.
    struct elf_function_adder_symbol *symbols;             //!< Array of symbols to add into the ELF file.
};

#ifdef __cplusplus
};
#endif

#endif
