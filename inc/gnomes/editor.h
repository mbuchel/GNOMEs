/*
 * Copyright (C) 2666680 Ontario Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 */
#ifndef GNOMES_EDITOR_H
#define GNOMES_EDITOR_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*! \brief Basic GNOME information for the editors.
 *
 * NOTE: This structure does not provide support for streaming GNOMEs.
 * TODO: Create streaming GNOMEs.
 */
struct gnome_info {
    uint8_t is_valid;                                  //!< This is a flag to determine if we are valid or not.
    void *config_ptr;                                  //!< Pointer to a GNOME specific configuration.
    void *output;                                      //!< Pointer to the output buffer, this buffer is
                                                       //   not valid before the edit command is finished
                                                       //   processing, it is recommended to check the
                                                       //   is_valid flag before running.
};

//! Helper typedefs to simplify code.
typedef int (*editor_untyped_fn)(struct gnome_info*, void*);
typedef int (*editor_char_fn)(struct gnome_info*, const char*);

/*! \brief API Abstraction for GNOMEs which are being used to modify binaries.
 *
 * The process for using a GNOME is to modify a ELF or DWARF component
 * of a binary. A GNOME API is used with the following steps:
 *
 * -# Initialization of the initial state of the GNOME.
 * -# Edit binary.
 * -# Wait till is_valid flag is set inside the gnome_info binary.
 * -# Extract output for the set binary file.
 *
 * The individual GNOME implementations maybe done in C++ however all interface
 * functions should be exported into C to allow calling from a C program.
 */
struct GnomeEditorAPI {
    editor_untyped_fn init;                            //!< Creates an initial state for the GNOME.
    editor_char_fn edit_bin;                           //!< Sets the binary to focus on.
    editor_untyped_fn extract;                         //!< Exports the output into the structure.
};

/*! \brief Function adder API.
 *
 * This is to readd a symbol name for a unnamed symbol.
 *
 * NOTES:
 * -# This API finds the offset and if the offset is inside the symbol table, we simply
 *    modify the string index to a new string representing the identifier of that symbol.
 * -# This is used to provide names for functions that are not easily indexed due to individuals
 *    stripping the binary.
 */
extern const struct GnomeEditorAPI gnome_elf_function_adder_api;

/*! \brief Injection API.
 *
 * This API creates a new function which is not previously inside the ELF file,
 * and replaces all instances of a specific symbol with the new functions symbol.
 *
 * NOTES:
 * -# Initializing can either be NULL or a pointer to \ref struct elf_injector_config
 * -# Edit binary sets the output buffer to an ELF format writer.
 * -# Extract expects a const char pointer to a file name for the export.
 */
extern const struct GnomeEditorAPI gnome_elf_injector_api;

/*! \brief Patcher API.
 *
 * This API patches the binary with new data. This can do inplace patching as well
 * as additive/destructive patching. An inplace patch is one which just modifies
 * the data directly without modifying the size of the section we are patching.
 * An additive patch increases the size of the sections, and a destructive patch
 * decreases the size of the sections.
 *
 * NOTES:
 * -# Initializing can either be NULL or a pointer to \ref struct elf_patcher_config
 * -# Edit binary sets the output buffer to an ELF format writer.
 * -# Extract expects a const char pointer to a file name for the export.
 */
extern const struct GnomeEditorAPI gnome_elf_patcher_api;

/*! \brief Renamer API.
 *
 * This API takes the old names in a binary and replaces them with different names.
 */
extern const struct GnomeEditorAPI gnome_elf_renamer_api;

#ifdef __cplusplus
};
#endif

#endif
