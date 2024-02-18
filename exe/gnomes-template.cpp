/*
 * Copyright (C) 2666680 Ontario Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 */
#include <configs/{1}>

#include <gnomes/apis.h>
#include <gnomes/logger.h>

#include <iostream>
#include <fstream>
#include <sstream>

#include <memory>

int main(int argc, const char **argv)
{{
    std::ifstream in_file;
    std::stringstream buffer;
    std::string file_contents;

    std::shared_ptr<{2}Config> config = nullptr;
    const struct GnomeEditorAPI *gnome = GNOMES[{2}];

    struct gnome_info gnome_data = {{}};

    LOGGER = LOGGER_APIS[PrintOnly];
    if (LOGGER->init)
        LOGGER->init(NULL);

#ifdef GNOMES_LOG_DEBUG
    LOGGER->max = LogDebug;
#else
    LOGGER->max = LogInfo;
#endif

    if (argc < 3) {{
        GNOMES_ERROR << argv[0] << " <{0}.json> [files to add to]+\n";
        return EINVAL;
    }}

    in_file.open(argv[1]);
    if (!in_file.is_open()) {{
        GNOMES_ERROR << "Failed to open {0} file.\n";
        return EINVAL;
    }}

    buffer << in_file.rdbuf();
    file_contents = buffer.str();

    config = std::shared_ptr<{2}Config>(new {2}Config(file_contents));
    if (config == nullptr) return EINVAL;

    gnome->init(&gnome_data, config->ptr);

    for (size_t i = 2; i < argc; ++i) {{
        std::string name = argv[i];
        std::string new_name = name + ".new";
        GNOMES_NOTICE << "GNOMEs are stealing " << name << "\n";

        gnome->edit_bin(&gnome_data, name.c_str());

        GNOMES_NOTICE << "GNOMEs are extracting " << name << " into " << new_name << "\n";

        gnome->extract(&gnome_data, (void*) new_name.c_str());
    }}
}}
