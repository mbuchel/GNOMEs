/*
 * Copyright (C) 2666680 Ontario Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 */
#ifndef CONFIGS_ELF_PATCHER_H
#define CONFIGS_ELF_PATCHER_H

#include <stdint.h>

#include <elf/patcher.h>

#ifdef __cplusplus
extern "C" {
#endif

/*! \brief Reads a config from a JSON node passed in by the void pointer (for compatibility with C code).
 *
 * This is a function called internally by multiple functions to provide the ELF Patcher configuration.
 *
 * \param json_ptr - Void pointer pointing to the JSON node internally.
 * \return ELF Patcher Configuration or a nullptr.
 */
struct elf_patcher_config* get_elf_patcher_config(void *json_ptr);

/*! \brief Reads a string into an ELF Patcher Configuration.
 *
 * This function reads the string into a JSON node and internally calls \a get_elf_patcher_config.
 *
 * \param json_str - String corresponding to the JSON file to deal with an ELF Patcher Configuration.
 * \return ELF Patcher Configuration or a nullptr.
 */
struct elf_patcher_config* parse_elf_patcher_config(const char *json_str);

/*! \brief Free of a single patch, used to provide help when we are dealing with Assembly Patches.
 *
 * \param patch - Patch to free.
 * \return Only performed for the side effects.
 */
void free_elf_patcher_patch(struct elf_patch *patch);

/*! \brief Complex free of all memory components of an ELF Patcher Configuration.
 *
 * \param config - Configuration to free.
 * \return Only performed for the side effects.
 */
void free_elf_patcher_config(struct elf_patcher_config *config);

#ifdef __cplusplus
};
#endif

#ifdef __cplusplus

#include <rapidjson/document.h>

/*! \brief Class to ensure we have a proper freeing of the ELF Patcher config.
 *
 * This is a helper class around the ELF Patcher to ensure proper freeing of C resources.
 */
class ElfPatcherConfig {
public:
    ElfPatcherConfig(rapidjson::Value *json_ptr) {
        ptr = get_elf_patcher_config((void*) json_ptr);
        if (ptr == nullptr) throw std::runtime_error("Incorrect JSON for Patcher");
    }

    ElfPatcherConfig(std::string json_str) {
        ptr = parse_elf_patcher_config(json_str.c_str());
        if (ptr == nullptr) throw std::runtime_error("Incorrect JSON for Patcher");
    }

    ~ElfPatcherConfig() {
        free_elf_patcher_config(ptr);
    }

    struct elf_patcher_config *ptr;
};

#endif

#endif
