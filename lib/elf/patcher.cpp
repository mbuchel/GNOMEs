/*
 * Copyright (C) 2666680 Ontario Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 */
#include <configs/elf/patcher.h>
#include <elf/base.hpp>
#include <elf/editor.hpp>
#include <elf/patcher.h>
#include <gnomes/editor.h>
#include <gnomes/logger.h>

#include <asmtk/asmtk.h>
#include <asmjit/x86.h>

#include <mutex>
#include <set>

static std::mutex mut;

static struct elf_patch* extract_binary(
    struct elf_patch *patch
)
{
    uint64_t i;

    struct elf_patch *ret = nullptr;
    struct elf_assembly_patch *assembly = nullptr;
    struct elf_binary_patch *bin = nullptr;
    std::string instructions = "";

    asmjit::Environment env(asmjit::Arch::kX64);
    asmjit::CodeHolder code;

    code.init(env);

    asmjit::x86::Assembler a(&code);
    asmtk::AsmParser p(&a);

    asmtk::Error err;

    asmjit::CodeBuffer *buffer;

    if (patch->patch_data_type == BinaryPatch) {
        ret = patch;
        goto exit_extract_binary;
    }

    ret = new struct elf_patch();
    if (ret == nullptr)
        goto exit_extract_binary;

    ret->patch_type = NullPatch;
    ret->patch_data_type = BinaryPatch;
    ret->symbol = new char[strlen(patch->symbol) + 1];
    if (ret->symbol == nullptr)
        goto exit_extract_binary;

    strcpy(ret->symbol, patch->symbol);
    ret->patch_type = patch->patch_type;

    assembly = &(patch->p.assembly);

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

    bin = new struct elf_binary_patch();
    if (bin == nullptr) goto exit_extract_binary;

    bin->size = buffer->size();
    bin->data = new uint8_t[bin->size]();

    if (bin->data == nullptr)
        goto failed_extract_binary;

    memcpy(
        bin->data,
        buffer->data(),
        bin->size
    );

    gnomes_debug_hexdump2(
        bin->data,
        bin->size
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

    bin->reloc_size = i;
    if (bin->reloc_size)
        bin->reloc_data = new struct elf_binary_reloc[bin->reloc_size];

    gnomes_info("Total relocation entry size: %ld", bin->reloc_size);

    i = 0;
    for (const auto *label : code.labelEntries()) {
        asmjit::LabelLink *link = label->links();

        while (link != nullptr) {
            bin->reloc_data[i].offset = link->offset;
            bin->reloc_data[i].symbol = nullptr;

            if (label->hasName()) {
                const char *name = label->name();
                bin->reloc_data[i].symbol = new char[strlen(name) + 1]();

                if (bin->reloc_data[i].symbol)
                    strcpy(bin->reloc_data[i].symbol, name);
            }

            gnomes_info(
                "\tAdded %s relocation to 0x%.16lX inside the binary patch.",
                bin->reloc_data[i].symbol,
                bin->reloc_data[i].offset
            );

            ++i;
            link = link->next;
        }
    }

    goto exit_extract_binary;

failed_extract_binary:
    if (bin->data != nullptr) delete bin->data;
    if (bin->reloc_data != nullptr) {
        for (uint64_t j = 0; j < bin->reloc_size; ++j)
            if (bin->reloc_data[j].symbol != nullptr)
                delete bin->reloc_data[j].symbol;
        delete bin->reloc_data;
    }
    if (bin != nullptr) delete bin;
    if (ret != nullptr && ret->symbol != nullptr)
        delete ret->symbol;
    if (ret != nullptr) delete ret;

exit_extract_binary:
    return ret;
}

static int edit_bin(
    struct gnome_info *gnome_data,
    ELFFormat *bin
)
{
    int ret = EINVAL;
    struct elf_patcher_config *config =
        (struct elf_patcher_config*) gnome_data->config_ptr;

    gnomes_notice("Running patcher GNOME...");

    for (uint64_t i = 0; i < config->num_patches; ++i) {
        const enum SupportedPatchData og_patch_data_type =
            config->patches[i].patch_data_type;
        struct elf_binary_patch *bin_patch = nullptr;
        struct elf_patch *patch = &(config->patches[i]);

        std::string symbol = patch->symbol;

        patch = extract_binary(patch);
        if (patch == nullptr || patch->patch_type == NullPatch) {
            gnomes_warn("Invalid binary, skipping patch %ld / %ld", i + 1, config->num_patches);
            continue;
        }

        bin_patch = &(patch->p.binary);

        if (bin->elf64()) {
            std::string rel_name;
            std::string rela_name;
            std::shared_ptr<ELFSection<Elf64_Shdr>> hashtab =
                std::static_pointer_cast<ELFSection<Elf64_Shdr>>(bin->hashtab);
            std::shared_ptr<ELFSection<Elf64_Shdr>> strtab =
                std::static_pointer_cast<ELFSection<Elf64_Shdr>>(bin->strtab);
            std::shared_ptr<ELFSection<Elf64_Shdr>> symtab =
                std::static_pointer_cast<ELFSection<Elf64_Shdr>>(bin->symtab);
            std::shared_ptr<ELFSection<Elf64_Shdr>> osec = nullptr;
            std::shared_ptr<ELFSection<Elf64_Shdr>> rsec = nullptr;
            Elf64_Sym *sym = elf_find_sym<Elf64_Word, Elf64_Sym, Elf64_Shdr>(
                hashtab,
                strtab,
                symtab,
                symbol
            );

            if (sym == nullptr) {
                gnomes_warn("Symbol %s is not found.", patch->symbol);
                goto clear_patch_data;
            }

            osec = std::static_pointer_cast<ELFSection<Elf64_Shdr>>(bin->sections[sym->st_shndx]);

            gnomes_info("Found the symbol in: %s", osec->name.c_str());

            rel_name = ".rel" + osec->name;
            rela_name = ".rela" + osec->name;

            for (const auto &section : bin->sections) {
                std::shared_ptr<ELFSection<Elf64_Shdr>> s =
                    std::static_pointer_cast<ELFSection<Elf64_Shdr>>(section);
                if (section->name == rel_name && s->hdr->sh_type == SHT_REL) {
                    rsec = s;
                    break;
                }
                if (section->name == rela_name && s->hdr->sh_type == SHT_RELA) {
                    rsec = s;
                    break;
                }
            }

            if (rsec == nullptr) goto clear_patch_data;

            switch (patch->patch_type) {
            case InplacePatch:
                gnomes_info("Applying inplace patch to %s at 0x%.16lX", patch->symbol, patch->offset);
                ret = elf_patch<Elf32_Word, Elf64_Shdr, Elf64_Sym, Elf64_Rel, Elf64_Rela, 64>(
                    hashtab, strtab, symtab,
                    osec, rsec,
                    sym,
                    patch
                );
                break;
            case AdditivePatch:
                gnomes_info("Applying additive patch to %s at 0x%.16lX", patch->symbol, patch->offset);
                ret = elf_patch<Elf32_Word, Elf64_Shdr, Elf64_Sym, Elf64_Rel, Elf64_Rela, 64>(
                    hashtab, strtab, symtab,
                    osec, rsec,
                    sym,
                    patch,
                    bin_patch->size
                );
                break;
            case DestructivePatch:
                gnomes_info("Applying destructive patch to %s at 0x%.16lX", patch->symbol, patch->offset);
                ret = elf_patch<Elf32_Word, Elf64_Shdr, Elf64_Sym, Elf64_Rel, Elf64_Rela, 64>(
                    hashtab, strtab, symtab,
                    osec, rsec,
                    sym,
                    patch,
                    -(bin_patch->size)
                );
                break;
            default:
                gnomes_warn("Invalid patch type asked for skipping patch %ld / %ld", i + 1, config->num_patches);
                continue;
            }

            if (ret != 0) {
                gnomes_warn("Patch invalid value");
                free_elf_patcher_patch(patch);
                goto failed_edit_bin;
            }
        }

clear_patch_data:
        // NOTE: We set up a new patch which needs to be cleared.
        if (og_patch_data_type == AssemblyPatch)
            free_elf_patcher_patch(patch);
    }

    gnome_data->is_valid = 1;

    goto exit_edit_bin;

failed_edit_bin:
    ret = EINVAL;

exit_edit_bin:
    return ret;
}

const struct GnomeEditorAPI gnome_elf_patcher_api = {
.init = [](struct gnome_info *data, void *ptr) -> int { return (get_init_function(&mut))(data, ptr); },
.edit_bin = [](struct gnome_info *data, const char *name) -> int {
    return (get_edit_bin_function(edit_bin, &mut))(data, name);
},
.extract = [](struct gnome_info *data, void *ptr) -> int { return (get_extract_function(&mut))(data, ptr); }
};
