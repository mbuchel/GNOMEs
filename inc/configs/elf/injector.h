/*
 * Copyright (C) 2666680 Ontario Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 */
#ifndef CONFIGS_ELF_INJECTOR_H
#define CONFIGS_ELF_INJECTOR_H

#include <stdint.h>

#include <elf/injector.h>

#ifdef __cplusplus
extern "C" {
#endif

/*! \brief Reads a config from a JSON node passed in by the void pointer (for compatibility with C code).
 *
 * This is a function called internally by multiple functions to provide the ELF Injector configuration.
 *
 * \param json_ptr - Void pointer pointing to the JSON node internally.
 * \return ELF Injector Configuration or a nullptr.
 */
struct elf_injector_config* get_elf_injector_config(void *json_ptr);

/*! \brief Reads a string into an ELF Injector Configuration.
 *
 * This function reads the string into a JSON node and internally calls \a get_elf_injector_config.
 *
 * \param json_str - String corresponding to the JSON file to deal with an ELF Injector Configuration.
 * \return ELF Injector Configuration or a nullptr.
 */
struct elf_injector_config* parse_elf_injector_config(const char *json_str);

/*! \brief Complex free of all memory components of an ELF Injector Configuration.
 *
 * \param config - Configuration to free.
 * \return Only performed for the side effects.
 */
void free_elf_injector_config(struct elf_injector_config *config);

#ifdef __cplusplus
};
#endif

#ifdef __cplusplus

#include <rapidjson/document.h>

/*! \brief Class to ensure we have a proper freeing of the ELF Injector config.
 *
 * This is a helper class around the ELF Injector to ensure proper freeing of C resources.
 */
class ElfInjectorConfig {
public:
    ElfInjectorConfig(rapidjson::Value *json_ptr) {
        ptr = get_elf_injector_config((void*) json_ptr);
        if (ptr == nullptr) throw std::runtime_error("Incorrect JSON for Injector");
    }

    ElfInjectorConfig(std::string json_str) {
        ptr = parse_elf_injector_config(json_str.c_str());
        if (ptr == nullptr) throw std::runtime_error("Incorrect JSON for Injector");
    }

    ~ElfInjectorConfig() {
        free_elf_injector_config(ptr);
    }

    struct elf_injector_config *ptr;
};

#endif

#endif
