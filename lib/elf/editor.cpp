/*
 * Copyright (C) 2666680 Ontario Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 */
#include <elf/editor.hpp>
#include <gnomes/editor.h>
#include <gnomes/logger.h>

#include <elf.h>
#include <stdint.h>

#include <algorithm>
#include <iterator>
#include <mutex>
#include <fstream>
#include <functional>
#include <filesystem>

static std::mutex global_mut;

static int init(
    editor_untyped_fn init_fn,
    std::mutex *mut,
    struct gnome_info *gnome_data,
    void *ptr
)
{
    int ret = 0;
    std::lock_guard<std::mutex> init_lock(*mut);

    if (gnome_data == nullptr) return -EINVAL;

    if (gnome_data->is_valid) {
        gnome_data->is_valid = 0;
    }

    if (ptr != nullptr)
        gnome_data->config_ptr = ptr;

    if (init_fn != nullptr)
        ret = init_fn(gnome_data, ptr);

    return ret;
}

static int edit_bin(
    int (*edit_bin_fn)(struct gnome_info*, ELFFormat *bin),
    std::mutex *mut,
    std::set<std::string> required_sections,
    struct gnome_info *gnome_data,
    const char *binary
)
{
    int ret = 0;
    ELFFormat *out = (ELFFormat*) gnome_data->output;

    if (out == nullptr) {
        if (binary == nullptr) {
            gnomes_error("Invalid binary used when we have no output.");
            ret = EINVAL;
            goto exit_edit_bin;
        }
        out = new ELFFormat(std::string(binary));
        gnome_data->output = (void*) out;
    }

    if (gnome_data->config_ptr == nullptr) {
        gnomes_error("No configuration.");
        ret = EINVAL;
        goto exit_edit_bin;
    }

    for (const auto &section : out->sections) {
        required_sections.erase(section->name);
    }

    if (!required_sections.empty()) goto exit_edit_bin;

    if (out != nullptr)
        ret = edit_bin_fn(gnome_data, out);

    if (ret == 0)
        out = nullptr;
    else
        gnome_data->output = nullptr;

exit_edit_bin:
    if (out != nullptr) {
        delete out;
    }

    return ret;
}

static int default_extraction(
    struct gnome_info *gnome_data,
    void *output_buffer
)
{
    int ret = 0;
    ELFFormat *elf = (ELFFormat*) gnome_data->output;
    std::unique_ptr<uint8_t[]> binary = elf->binary();
    if (binary != nullptr) {
        std::string file_name = (const char*) output_buffer;
        std::ofstream out_file;

        out_file.open(file_name, std::ios::trunc);
        std::copy(
            binary.get(),
            binary.get() + elf->size(),
            std::ostream_iterator<uint8_t>(out_file)
        );
        out_file.close();

        gnomes_info("Wrote into file %s", file_name.c_str());
    }
    delete elf;
    gnomes_notice("Extracted information.");
    return ret;
}

static int extract(
    editor_untyped_fn extract_fn,
    std::mutex *mut,
    struct gnome_info *gnome_data,
    void *output_buffer
)
{
    int ret = 0;
    std::lock_guard<std::mutex> extract_lock(*mut);

    if (gnome_data != nullptr &&
        gnome_data->is_valid &&
        gnome_data->output != nullptr &&
        output_buffer != nullptr) {
        ret = extract_fn(gnome_data, output_buffer);
        gnome_data->is_valid = 0;
        gnome_data->output = nullptr;
    } else {
        gnomes_error("Output data is not valid yet.");
        ret = EINVAL;
    }

    return ret;
}

std::function<int(struct gnome_info*, void*)> get_init_function(
    std::mutex *mut,
    editor_untyped_fn init_fn
)
{
    if (mut == nullptr)
        mut = &global_mut;

    return
        std::function<int(struct gnome_info*, void*)>(
            [init_fn, mut](struct gnome_info *data, void *ptr) mutable -> int { return init(init_fn, mut, data, ptr); }
        );
}

std::function<int(struct gnome_info*, const char*)> get_edit_bin_function(
    int (*edit_bin_fn)(struct gnome_info*, ELFFormat*),
    std::mutex *mut,
    std::set<std::string> required_sections
)
{
    if (mut == nullptr)
        mut = &global_mut;

    return
        std::function<int(struct gnome_info*, const char*)>(
            [edit_bin_fn, mut, required_sections](struct gnome_info *data, const char *name) mutable -> int {
                return edit_bin(edit_bin_fn, mut, required_sections, data, name);
            }
        );
}

std::function<int(struct gnome_info*, void*)> get_extract_function(
    std::mutex *mut,
    editor_untyped_fn extract_fn
)
{
    if (mut == nullptr)
        mut = &global_mut;

    if (extract_fn == nullptr)
        extract_fn = &default_extraction;

    return
        std::function<int(struct gnome_info*, void*)>(
            [extract_fn, mut](struct gnome_info *data, void *ptr) mutable -> int { return extract(extract_fn, mut, data, ptr); }
        );
}
