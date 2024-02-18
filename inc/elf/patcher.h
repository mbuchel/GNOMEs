/*
 * Copyright (C) 2666680 Ontario Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 */
#ifndef ELF_PATCHER_H
#define ELF_PATCHER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*! \brief Supported types of patches.
 *
 * We support different types of patches:
 *
 * -# Null patches are improperly formatted patches so are simply ignored.
 * -# Inplace are normally safe, proceed with caution.
 * -# Additive are always unsafe, proceed with extreme caution.
 * -# Destructive are always unsafe, proceed with extreme caution.
 *
 * NOTES:
 * - Both additive and destructive patches can cause relocation issues,
 *   but not an unaligned instruction issue (Incorrect in undefined instructions).
 * - Inplace instructions cannot cause relocation issues, but may cause unaligned
 *   instructions (Incorrect in improperly formated patches).
 */
enum SupportedPatches {
    NullPatch,
    InplacePatch,
    AdditivePatch,
    DestructivePatch
};

/*! \brief Supported types of data for patches.
 *
 * We support both binary patches and assembly patches.
 *
 * NOTES:
 * - Binary patches do not perform proper relocation patching use at own risk.
 * - Whenever possible we recommend the assembly patches.
 */
enum SupportedPatchData {
    AssemblyPatch,
    BinaryPatch
};

/*! \brief Relocation data for binary patch data.
 *
 * These are offsets inside the binary patch info.
 */
struct elf_binary_reloc {
    uint64_t offset;                         //!< Offset inside the binary patch.
    char *symbol;                            //!< Symbol to relocate to instead.
};

/*! \brief Assembly patch object.
 *
 * Instructions which need to be assembled to the x86_64 machine language and injected.
 */
struct elf_assembly_patch {
    uint64_t num_instrs;                     //!< Number of instructions for the assembly patch.
    char **instructions;                     //!< Instructions vector.
};

/*! \brief Binary patch object.
 *
 * This is a patch for a binary object.
 *
 * NOTE: The binary patch does not support relocations inside the JSON config yet,
 *       however it does support it in the assembly patches.
 */
struct elf_binary_patch {
    uint64_t size;                           //!< Size of the binary patch.
    uint8_t *data;                           //!< Data of the binary patch.
    uint64_t reloc_size;                     //!< Relocation data size.
    struct elf_binary_reloc *reloc_data;     //!< Relocation data information.
};

/*! \brief Patch for an elf object.
 *
 * These are single patches for an offset.
 */
struct elf_patch {
    enum SupportedPatches patch_type;        //!< Type of patch to apply.
    enum SupportedPatchData patch_data_type; //!< Type of data passed into the patch.
    char *symbol;                            //!< Symbol's name.
    uint64_t offset;                         //!< Offset inside the symbol.
    union {
        struct elf_assembly_patch assembly;
        struct elf_binary_patch binary;
    } p;                                     //!< Assembly/Binary patch info.
};

/*! \brief Configuration for patching. */
struct elf_patcher_config {
    uint64_t num_patches;                    //!< Number of patches to apply.
    struct elf_patch *patches;               //!< Patches to apply.
};

#ifdef __cplusplus
};
#endif

#endif
