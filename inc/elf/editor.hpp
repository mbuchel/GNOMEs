/*
 * Copyright (C) 2666680 Ontario Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 */
#ifndef ELF_EDITOR_H
#define ELF_EDITOR_H

#include <elf/base.hpp>
#include <elf/format.hpp>
#include <gnomes/editor.h>

#include <set>
#include <map>
#include <mutex>
#include <functional>

// NOTE: This code is incompatible with GNOMEs that are built using the C API,
//       later we will provide a mechanism for C GNOMEs.
#ifdef __cplusplus

/*! \brief Initialization code.
 *
 * This function curries the mutex to use into an initialization function and passes back a function.
 *
 * NOTES:
 * -# A null pointer for the mutex is a GNOME that blocks to prevent 2 GNOMEs running in parallel.
 *
 * \params mut - Mutex to block the initialization code from running multiple at the same time.
 * \params init_fn - Additional initialization function to run after base initialization if necessary.
 * \return A function to be run which has a curried value.
 */
std::function<int(struct gnome_info*, void*)> get_init_function(
    std::mutex *mut = nullptr,
    editor_untyped_fn init_fn = nullptr
);

/*! \brief Editing code.
 *
 * This is a function that wraps an edit binary function with a lot of different components to ensure
 * we follow a set of rules for creating an editing binary.
 *
 * NOTES:
 * -# A null pointer for the mutex is a GNOME that blocks to prevent 2 GNOMEs running in parallel.
 * -# We validate that the function inside edit bin is passed a none empty binary and valid config pointer.
 * -# This uses a our internal ELF format to spawn up/down the GNOME.
 *
 * \params edit_bin_fn - Edits the binary file according to the configuration parameter.
 * \params mut - Mutex to block the initialization code from running multiple at the same time.
 * \params required_sections - Required sections to filter on before running the edit bin function.
 * \return A function to be run which has a few curried values.
 */
std::function<int(struct gnome_info*, const char*)> get_edit_bin_function(
    int (*edit_bin_fn)(struct gnome_info*, ELFFormat*),
    std::mutex *mut = nullptr,
    std::set<std::string> required_sections = {}
);

/*! \brief Extraction code.
 *
 * This function curries the mutex to use into an extraction function and passes back a function.
 *
 * NOTES:
 * -# A null pointer for the mutex is a GNOME that blocks to prevent 2 GNOMEs running in parallel.
 * -# extract_fn does not require any validation, and expects the output value to be freed.
 * -# If no extract_fn is passed, we assume the file writing extractor is used.
 *
 * \params mut - Mutex to block the extraction code from running multiple at the same time.
 * \params extract_fn - Acutual extraction function.
 * \return A function to be run which has a curried value.
 */
std::function<int(struct gnome_info*, void*)> get_extract_function(
    std::mutex *mut = nullptr,
    editor_untyped_fn extract_fn = nullptr
);

#endif

#endif
