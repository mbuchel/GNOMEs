/*
 * Copyright (C) 2666680 Ontario Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 */
#include <configs/elf/function-adder.h>
#include <configs/elf/injector.h>
#include <configs/elf/patcher.h>
#include <configs/elf/renamer.h>

#include <gnomes/apis.h>
#include <gnomes/logger.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <getopt.h>

#include <memory>

#include <rapidjson/document.h>

static int verbose = 0;

static struct option long_options[] = {
    {"help", no_argument, nullptr, 'h'},
    {"verbose", no_argument, &verbose, 'v'},
    {"advanced-help", no_argument, nullptr, 'a'},
    {0, 0, 0, 0}
};

void run_gnomes(std::string config_file)
{
    std::ifstream in_file;
    std::stringstream buffer;
    std::string file_contents;

    rapidjson::Document doc;
    rapidjson::ParseResult ok;

    struct gnome_info gnome_data = {};

    in_file.open(config_file);
    if (!in_file.is_open()) {
        return;
    }

    buffer << in_file.rdbuf();
    file_contents = buffer.str();

    ok = doc.Parse(file_contents.c_str());
    if (!ok) {
        GNOMES_ERROR << "Error parsing: \"" << file_contents << "\":\n" << ok.Code() << "\n";
        return;
    }

    if (!doc.IsArray()) {
        GNOMES_ERROR << "Failed to read json as an array.\n";
        return;
    }

    for (const auto &node : doc.GetArray()) {
        std::string name;
        std::string new_name;

        const char *name_ptr = nullptr;

        struct gnome_info gnome_data = {};

        const struct GnomeEditorAPI *api = nullptr;

        if (node.HasMember("og-file") && node["og-file"].IsString()) {
            name = node["og-file"].GetString();
            gnomes_debug("Dealing with an original file: %s", name.c_str());
        }

        if (node.HasMember("new-file") && node["new-file"].IsString()) {
            new_name = node["new-file"].GetString();
            gnomes_debug("Writing to new file: %s", new_name.c_str());
        }

        if (name.empty() ||
            new_name.empty())
            continue;

        name_ptr = name.c_str();

        if (node.HasMember("elf-function-add") && node["elf-function-add"].IsArray()) {
            ElfFunctionAdderConfig config((rapidjson::Value*) &node["elf-function-add"]);
            api = GNOMES[ElfFunctionAdder];
            api->init(&gnome_data, config.ptr);
            api->edit_bin(&gnome_data, name_ptr);
            if (gnome_data.output != nullptr) name_ptr = nullptr;
        }

        if (node.HasMember("elf-inject") && node["elf-inject"].IsArray()) {
            ElfInjectorConfig config((rapidjson::Value*) &node["elf-inject"]);
            api = GNOMES[ElfInjector];
            api->init(&gnome_data, config.ptr);
            api->edit_bin(&gnome_data, name_ptr);
            if (gnome_data.output != nullptr) name_ptr = nullptr;
        }

        if (node.HasMember("elf-patch") && node["elf-patch"].IsArray()) {
            ElfPatcherConfig config((rapidjson::Value*) &node["elf-patch"]);
            api = GNOMES[ElfPatcher];
            api->init(&gnome_data, config.ptr);
            api->edit_bin(&gnome_data, name_ptr);
            if (gnome_data.output != nullptr) name_ptr = nullptr;
        }

        if (node.HasMember("elf-rename") && node["elf-rename"].IsArray()) {
            ElfRenamerConfig config((rapidjson::Value*) &node["elf-rename"]);
            api = GNOMES[ElfRenamer];
            api->init(&gnome_data, config.ptr);
            api->edit_bin(&gnome_data, name_ptr);
            if (gnome_data.output != nullptr) name_ptr = nullptr;
        }

        if (api != nullptr)
            api->extract(&gnome_data, (void*) new_name.c_str());
    }
}

int main(int argc, char **argv)
{
    int ch = 0;
    int option_idx = 0;

    LOGGER = LOGGER_APIS[PrintOnly];
    if (LOGGER->init)
        LOGGER->init(NULL);

    LOGGER->max = LogInfo;

    while ((ch = getopt_long(argc, argv, "vha", long_options, &option_idx)) != -1) {
        switch (ch) {
        case 'v':
            LOGGER->max = LogDebug;
            break;
        case 'h':
            gnomes_info("The proper usage of this code is as follows: %s [-v|--verbose] <configs.json>+", argv[0]);
            return 0;
        case 'a':
            gnomes_error("THE ELVES HAVE BEEN CONSPIRING AGAINST THE DWARFS (jlt)");
            return 0;
        }
    }

    for (; optind < argc; ++optind) {
        gnomes_info("Reading config file: %s", argv[optind]);
        run_gnomes(std::string(argv[optind]));
    }
}
