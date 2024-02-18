/*
 * Copyright (C) 2666680 Ontario Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 */
#include <configs/elf/patcher.h>
#include <elf/base.hpp>
#include <elf/patcher.h>
#include <gnomes/editor.h>
#include <gnomes/logger.h>

#include <asmtk/asmtk.h>
#include <asmjit/x86.h>
#include <elfio/elfio.hpp>

#include <mutex>
#include <set>

static std::mutex mut;

static struct elf_binary_patch* extract_binary(
    struct elf_assembly_patch *assembly
)
{
    uint64_t i;

    struct elf_binary_patch *ret = nullptr;
    std::string instructions = "";

    asmjit::Environment env(asmjit::Arch::kX64);
    asmjit::CodeHolder code;

    code.init(env);

    asmjit::x86::Assembler a(&code);
    asmtk::AsmParser p(&a);

    asmtk::Error err;

    asmjit::CodeBuffer *buffer;

    for (i = 0; i < assembly->num_instrs; ++i) {
        std::string new_line =
            std::string(assembly->instructions[i]) +
            (i == (assembly->num_instrs - 1) ? "" : "\n");
        instructions = instructions + "\t" + new_line;
    }

    gnomes_info("The instructions are:\n%s", instructions.c_str());

    err = p.parse(instructions.c_str());
    if (err) {
        gnomes_error("%08x (%s)\n", err, asmjit::DebugUtils::errorAsString(err));
        goto exit_extract_binary;
    }

    buffer = &(code.textSection()->buffer());
    gnomes_info("Buffer size: %d", buffer->size());

    ret = new struct elf_binary_patch();
    if (ret == nullptr) goto exit_extract_binary;

    ret->size = buffer->size();
    ret->data = new uint8_t[ret->size]();

    if (ret->data == nullptr)
        goto failed_extract_binary;

    memcpy(
        ret->data,
        buffer->data(),
        ret->size
    );

    gnomes_debug_hexdump2(
        ret->data,
        ret->size
    );

    i = 0;
    gnomes_debug("Labels in the assembly:");
    for (const auto *label : code.labelEntries()) {
        uint32_t link_num = 0;
        asmjit::LabelLink *link = label->links();

        while (link != nullptr) {
            ++link_num;
            link = link->next;
        }

        i += link_num;

        gnomes_debug(
            "\t%s: %d",
            label->hasName() ? label->name() : "N/A",
            link_num
        );
    }

    ret->reloc_size = i;
    if (ret->reloc_size)
        ret->reloc_data = new struct elf_binary_reloc[ret->reloc_size];

    gnomes_info("Total relocation entry size: %ld", ret->reloc_size);

    i = 0;
    for (const auto *label : code.labelEntries()) {
        asmjit::LabelLink *link = label->links();

        while (link != nullptr) {
            ret->reloc_data[i].offset = link->offset;
            ret->reloc_data[i].symbol = nullptr;

            if (label->hasName()) {
                const char *name = label->name();
                ret->reloc_data[i].symbol = new char[strlen(name) + 1]();

                if (ret->reloc_data[i].symbol)
                    strcpy(ret->reloc_data[i].symbol, name);
            }

            gnomes_info(
                "\tAdded %s relocation to 0x%.16lX inside the binary patch.",
                ret->reloc_data[i].symbol,
                ret->reloc_data[i].offset
            );

            ++i;
            link = link->next;
        }
    }

    goto exit_extract_binary;

failed_extract_binary:
    if (ret->data != nullptr) delete ret->data;
    if (ret->reloc_data != nullptr) {
        for (uint64_t j = 0; j < ret->reloc_size; ++j)
            if (ret->reloc_data[j].symbol != nullptr)
                delete ret->reloc_data[j].symbol;
        delete ret->reloc_data;
    }
    if (ret != nullptr) delete ret;

exit_extract_binary:
    return ret;
}

static uint8_t init(
    struct gnome_info *gnome_data,
    void *ptr
)
{
    uint8_t ret = 0;
    std::lock_guard<std::mutex> init_lock(mut);

    if (gnome_data->is_valid) {
        gnome_data->is_valid = 0;
    }

    if (ptr != nullptr)
        gnome_data->config_ptr = ptr;

    ret = 1;

    return ret;
}

static int edit_bin(
    struct gnome_info *gnome_data,
    const char *binary
)
{
    int ret = 0;
    struct elf_patcher_config *config = nullptr;
    ELFIO::elfio *elf = nullptr;
    ELFIO::section *symtab = nullptr;
    ELFIO::section *strtab = nullptr;
    ELFIO::symbol_section_accessor *syms = nullptr;
    std::string file_name = binary == nullptr ? "N/A" : binary;
    std::lock_guard<std::mutex> edit_lock(mut);

    if (gnome_data->output == nullptr) {
        elf = new ELFIO::elfio();
        if (elf == nullptr || (binary != nullptr && !elf->load(file_name))) {
            gnomes_error("Could not load file %s", binary);
            ret = ENOENT;
            goto exit_edit_bin;
        } else if (binary == nullptr) {
            ret = ENOENT;
            goto exit_edit_bin;
        }
        gnome_data->output = (void*) elf;
    } else
        elf = (ELFIO::elfio*) gnome_data->output;

    if (gnome_data->config_ptr == nullptr) {
        gnomes_error("Invalid configuration.");
        if (gnome_data->output != nullptr) delete ((ELFIO::elfio*) gnome_data->output);
        gnome_data->output = nullptr;
        ret = EINVAL;
        goto exit_edit_bin;
    }

    config = (struct elf_patcher_config*) gnome_data->config_ptr;

    gnomes_notice("Loaded %s inside the ELF Patcher GNOME", binary);

    for (uint32_t i = 0; i < elf->sections.size(); ++i) {
        ELFIO::section *psec = elf->sections[i];
        gnomes_info("\t[%d] %s\t%d", i, psec->get_name().c_str(), psec->get_type());

        if (psec->get_name() == ".symtab" && psec->get_type() == ELFIO::SHT_SYMTAB) {
            symtab = psec;
        } else if (psec->get_name() == ".strtab" && psec->get_type() == ELFIO::SHT_STRTAB) {
            strtab = psec;
        }
    }

    if (symtab == nullptr) {
        ret = EINVAL;
        goto exit_edit_bin;
    }

    syms = new ELFIO::symbol_section_accessor(*elf, symtab);
    if (syms == nullptr) goto exit_edit_bin;

    for (uint64_t i = 0; i < config->num_patches; ++i) {
        struct elf_binary_patch *bin = nullptr;
        struct elf_patch *patch = &(config->patches[i]);

        ELFIO::section *osec = nullptr;
        ELFIO::section *rsec = nullptr;

        std::string symbol = patch->symbol;
        std::string rela_name;

        uint64_t offset = 0;
        uint64_t index = 0;
        uint16_t section_idx = 0;

        if (!elf_find_symbol_offset(syms, symbol, &offset, &index, &section_idx)) {
            gnomes_warn("Symbol %s is not found inside the binary: %s", patch->symbol, binary);
            continue;
        }

        if (patch->patch_data_type == BinaryPatch)
            bin = &(patch->p.binary);
        else if (patch->patch_data_type == AssemblyPatch)
            bin = extract_binary(&(patch->p.assembly));

        if (bin == nullptr) continue;

        osec = elf->sections[section_idx];
        rela_name = ".rela" + osec->get_name();

        for (uint32_t j = 0; j < elf->sections.size(); ++j) {
            rsec = elf->sections[j];
            if (rsec->get_name() == rela_name &&
                rsec->get_type() == ELFIO::SHT_RELA)
                break;
            rsec = nullptr;
        }

        switch (patch->patch_type) {
        case InplacePatch:
            gnomes_info("Applying inplace patch to %s at 0x%.16lX", patch->symbol, patch->offset);
            elf_patch(
                elf, symtab, osec, rsec,
                offset,
                offset + patch->offset,
                bin
            );
            break;
        case AdditivePatch:
            gnomes_info("Applying additive patch to %s at 0x%.16lX", patch->symbol, patch->offset);
            elf_patch(
                elf, symtab, osec, rsec,
                offset,
                offset + patch->offset,
                bin,
                bin->size
            );
            break;
        case DestructivePatch:
            gnomes_info("Applying destructive patch to %s at 0x%.16lX", patch->symbol, patch->offset);
            elf_patch(
                elf, symtab, osec, rsec,
                offset,
                offset + patch->offset,
                bin,
                -(bin->size)
            );
            break;
        default:
            gnomes_warn("Invalid patch type asked for.");
            break;
        }

        for (uint64_t j = 0;
             j < bin->reloc_size &&
                 bin->reloc_data != nullptr &&
                 rsec != nullptr;
             ++j) {
            ELFIO::relocation_section_accessor rela(*elf, rsec);
            ELFIO::string_section_accessor str_section(strtab);

            std::string sym_name = bin->reloc_data[j].symbol;

            uint64_t sym_offset = 0;
            uint64_t sym_idx = 0;

            if (!elf_find_symbol_offset(syms, sym_name, &sym_offset, &sym_idx)) {
                uint32_t string_idx = 0;

                gnomes_info("Adding symbol %s to the binary %s", bin->reloc_data[j].symbol, binary);

                if (!elf_find_string_offset(&str_section, sym_name, &string_idx))
                    string_idx = str_section.add_string(sym_name);

                sym_idx = syms->add_symbol(
                    string_idx,
                    0, 0,
                    ELFIO::STB_GLOBAL, 0,
                    0, 0
                );

                gnomes_debug("Symbols section now has a %ld symbols", syms->get_symbols_num());
            }

            rela.add_entry(
                offset + patch->offset + bin->reloc_data[j].offset,
                sym_idx,
                (unsigned char) (ELFIO::STT_NOTYPE)
            );
        }

        if (patch->patch_data_type == AssemblyPatch) {
            for (uint64_t j = 0;
                 j < bin->reloc_size &&
                     bin->reloc_data != nullptr;
                 ++j)
                if (bin->reloc_data[j].symbol)
                    delete bin->reloc_data[j].symbol;
            if (bin->reloc_data) delete bin->reloc_data;
            if (bin->data) delete bin->data;
            delete bin;
        }

        gnome_data->is_valid = 1;
    }

exit_edit_bin:
    if (syms != nullptr) delete syms;

    return ret;
}

static int extract(
    struct gnome_info *gnome_data,
    void *output_buffer
)
{
    int ret = 0;
    std::lock_guard<std::mutex> extract_lock(mut);

    if (gnome_data->is_valid) {
        ELFIO::elfio *elf = (ELFIO::elfio*) gnome_data->output;
        ret = elf->save((const char*) output_buffer);
        gnomes_info("Wrote into file: %s", (const char*) output_buffer);
        gnome_data->is_valid = 0;
        if (gnome_data->output != nullptr) {
            delete ((ELFIO::elfio*) gnome_data->output);
            gnome_data->output = nullptr;
        }
    } else {
        gnomes_error("Output data is not valid yet.");
        ret = EINVAL;
    }

    return ret;
}

const struct GnomeEditorAPI gnome_elf_patcher_api = {
.init = init,
.edit_bin = edit_bin,
.extract = extract
};
