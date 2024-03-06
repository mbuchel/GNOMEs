/*
 * Copyright (C) 2666680 Ontario Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 */
#include <iostream>
#include <fstream>
#include <format>
#include <string>
#include <map>
#include <regex>

const std::map<std::string, std::pair<std::string, std::string>> normal_gnomes(
{
    {"elf-function-adder", {"elf/function-adder.h", "ElfFunctionAdder"}},
    {"elf-inject", {"elf/injector.h", "ElfInjector"}},
    {"elf-patch", {"elf/patcher.h", "ElfPatcher"}},
    {"elf-rename", {"elf/renamer.h", "ElfRenamer"}}
}
);

int main(int argc, char **argv)
{
    std::ofstream main_file;

    std::ifstream in_file;
    std::stringstream buffer;
    std::string file_contents;

    if (argc != 3) {
        std::cout << argv[0] << " <source_directory> <binary_directory>\n";
        return EINVAL;
    }

    in_file.open(std::string(argv[1]) + "/exe/gnomes-template.cpp");
    if (!in_file.is_open()) {
        return EINVAL;
    }

    buffer << in_file.rdbuf();
    file_contents = buffer.str();

    for (const auto& [type, gnome] : normal_gnomes) {
        const std::string file_name =
            std::string(argv[2]) + "/gnomes-" + type + ".cpp";
        std::ofstream file(file_name, std::ios::trunc);
        file << std::vformat(file_contents, std::make_format_args(type, gnome.first, gnome.second));
        file.close();
    }

    in_file.close();

    in_file.open(std::string(argv[1]) + "/exe/gnomes-run.cpp");
    if (!in_file.is_open()) {
        return EINVAL;
    }

    buffer.str("");
    buffer << in_file.rdbuf();
    file_contents = buffer.str();

    main_file.open(std::string(argv[2]) + "/gnomes-run.cpp");
    main_file << file_contents;
    main_file.close();

    return 0;
}
