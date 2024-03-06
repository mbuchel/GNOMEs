/*
 * Copyright (C) 2666680 Ontario Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 */
#include <elf/base.hpp>
#include <elf/format.hpp>
#include <gnomes/logger.h>

#include <elf.h>
#include <stdint.h>

#include <algorithm>
#include <cstring>
#include <string>
#include <fstream>
#include <filesystem>
#include <map>
#include <memory>
#include <utility>
#include <vector>

template <typename D, typename H>
static void fix_dynamic_entries(
    std::shared_ptr<ELFSection<H>> dynamic,
    std::vector<std::shared_ptr<ELFSectionInterface>> sections
)
{
    for (uint64_t i = 0; dynamic != nullptr && i < dynamic->template entries<D>(); ++i) {
        D *dyn = dynamic->template get<D>(i);

        switch (dyn->d_tag) {
        case DT_STRTAB:
            for (const auto &section : sections) {
                std::shared_ptr<ELFSection<H>> s = std::static_pointer_cast<ELFSection<H>>(section);
                std::shared_ptr<const H> hdr = s->hdr;
                if (hdr->sh_type == SHT_STRTAB) {
                    if (dyn->d_un.d_ptr != hdr->sh_offset)
                        gnomes_info("Updating strtab offset: 0x%.8X = 0x%.8X", dyn->d_un.d_ptr, hdr->sh_offset);
                    dyn->d_un.d_ptr = hdr->sh_offset;
                    break;
                }
            }
            break;
        case DT_SYMTAB:
            for (const auto &section : sections) {
                std::shared_ptr<ELFSection<H>> s = std::static_pointer_cast<ELFSection<H>>(section);
                std::shared_ptr<const H> hdr = s->hdr;
                if (hdr->sh_type == SHT_DYNSYM) {
                    if (dyn->d_un.d_ptr != hdr->sh_offset)
                        gnomes_info("Updating dynsym offset: 0x%.8X = 0x%.8X", dyn->d_un.d_ptr, hdr->sh_offset);
                    dyn->d_un.d_ptr = hdr->sh_offset;
                    break;
                }
            }
            break;
        default:
            // TODO: Implement all of these.
            break;
        }
    }
}

template <typename ELF_SHDR, typename T>
static std::unique_ptr<uint8_t[]> resize_smart_ptr(
    std::shared_ptr<ELF_SHDR> hdr, std::unique_ptr<uint8_t[]> section_data, bool negative = false,
    uint64_t negative_entry = 0, uint64_t data_size = 0
)
{
    const uint64_t size_of_t = data_size == 0 ? sizeof(T) : data_size;
    const uint64_t negative_offset = negative_entry * size_of_t;
    const uint64_t new_size =
        negative ?
        hdr->sh_size - size_of_t :
        hdr->sh_size + size_of_t;

    std::unique_ptr<uint8_t[]> ret = nullptr;

    uint8_t *data = (uint8_t*) (section_data.get());
    uint8_t *tmp = nullptr;

    section_data.release();

    if ((!negative && new_size < hdr->sh_size) ||
        (negative && new_size > hdr->sh_size)) {
        gnomes_error("The new size overflowed.");
        goto failed_resize;
    }

    if (negative) {
        if (negative_offset > hdr->sh_size) {
            gnomes_error("Out of bounds negative entry.");
            goto failed_resize;
        }

        std::copy(
            data + negative_offset,
            data + (hdr->sh_size - negative_offset - size_of_t),
            data + negative_offset + size_of_t
        );
    }

    tmp = (uint8_t*) realloc(data, new_size);
    if (tmp == nullptr) {
        gnomes_error("Could not reallocate smart pointer to a new size of: 0x%.16lX", new_size);
        goto failed_resize;
    }

    data = tmp;
    hdr->sh_size = new_size;

    goto exit_resize;

failed_resize:
    if (data != nullptr) {
        delete [] data;
        data = nullptr;
    }

exit_resize:
    ret.reset(data);

    return ret;
}

template <typename ELF_SHDR>
static std::unique_ptr<uint8_t[]> resize_smart_ptr_str(
    std::shared_ptr<ELF_SHDR> hdr, std::unique_ptr<uint8_t[]> section_data, bool negative = false,
    uint64_t negative_entry = 0, uint64_t data_size = 0
)
{
    const uint64_t negative_offset = negative_entry;
    const uint64_t str_size = strlen((char*) &(section_data.get()[negative_offset])) + 1;
    const uint64_t new_size =
        negative ?
        hdr->sh_size - str_size:
        hdr->sh_size + data_size;

    std::unique_ptr<uint8_t[]> ret = nullptr;

    uint8_t *data = (uint8_t*) (section_data.get());
    uint8_t *tmp = nullptr;

    section_data.release();

    if ((!negative && new_size < hdr->sh_size) ||
        (negative && new_size > hdr->sh_size)) {
        gnomes_error("The new size overflowed.");
        goto failed_resize;
    }

    if (negative) {
        if (negative_offset > hdr->sh_size) {
            gnomes_error("Out of bounds negative entry.");
            goto failed_resize;
        }

        std::copy(
            data + negative_offset,
            data + (hdr->sh_size - negative_offset - data_size),
            data + negative_offset + data_size
        );
    }

    tmp = (uint8_t*) realloc(data, new_size);
    if (tmp == nullptr) {
        gnomes_error("Could not reallocate smart pointer to a new size of: 0x%.16lX", new_size);
        goto failed_resize;
    }

    data = tmp;
    hdr->sh_size = new_size;

    goto exit_resize;

failed_resize:
    if (data != nullptr) {
        delete [] data;
        data = nullptr;
    }

exit_resize:
    ret.reset(data);

    return ret;
}

template <typename T>
ELFSection<T>::ELFSection(
    std::string name,
    std::unique_ptr<T> hdr,
    std::unique_ptr<uint8_t[]> sect_data,
    uint64_t index
)
{
    this->name = name;
    this->section_data = std::move(sect_data);
    this->priv_hdr = std::move(hdr);
    this->hdr = std::static_pointer_cast<const T>(this->priv_hdr);
    this->idx = index;
}

template <typename T>
bool ELFSection<T>::patch(
    const uint8_t* data,
    const uint64_t patch_offset,
    const uint64_t patch_size,
    const int64_t diff
)
{
    bool ret = false;

    this->section_data = resize_smart_ptr<T, T>(
        this->priv_hdr,
        std::move(this->section_data),
        diff < 0,
        patch_offset,
        patch_size
    );

    if (this->section_data == nullptr) {
        gnomes_error("Could not resize for section: %s", this->name.c_str());
        goto exit_patch;
    }

    if (diff > 0) {
        memmove(
            this->section_data.get() + patch_offset + patch_size,
            this->section_data.get() + patch_offset,
            this->hdr->sh_size - patch_size - patch_offset
        );

        std::copy(
            data,
            data + patch_size,
            this->section_data.get() + patch_offset
        );
    } else if (diff == 0) {
        std::copy(
            data,
            data + patch_size,
            this->section_data.get() + patch_offset
        );
    }

    ret = true;

exit_patch:
    return ret;
}

template <typename ELF_SHDR>
bool ELFSection<ELF_SHDR>::append(const std::string &data)
{
    bool ret = false;
    const uint64_t og_size = this->hdr->sh_size;

    this->section_data = resize_smart_ptr_str<ELF_SHDR>(
        this->priv_hdr,
        std::move(this->section_data),
        false,
        0,
        data.size() + 1
    );

    if (this->section_data == nullptr) {
        gnomes_error("Could not resize for section: %s", this->name.c_str());
        goto exit_append;
    }

    std::copy(
        (uint8_t*) data.c_str(),
        (uint8_t*) data.c_str() + data.size() + 1,
        this->section_data.get() + og_size
    );

    ret = true;

exit_append:
    return ret;
}

template <typename ELF_SHDR> template <typename T>
bool ELFSection<ELF_SHDR>::append(const T* data)
{
    bool ret = false;
    const uint64_t og_size = this->hdr->sh_size;

    this->section_data = resize_smart_ptr<ELF_SHDR, T>(
        this->priv_hdr,
        std::move(this->section_data)
    );

    if (this->section_data == nullptr) {
        gnomes_error("Could not resize for section: %s", this->name.c_str());
        goto exit_append;
    }

    std::copy(
        (uint8_t*) data,
        (uint8_t*) data + sizeof(T),
        this->section_data.get() + og_size
    );

    ret = true;

exit_append:
    return ret;
}

template <typename ELF_SHDR>
bool ELFSection<ELF_SHDR>::insert(const std::string &data, const uint64_t entry_idx)
{
    bool ret = false;
    const uint64_t entry_offset = entry_idx;

    this->section_data = resize_smart_ptr_str<ELF_SHDR>(
        this->priv_hdr,
        std::move(this->section_data),
        false,
        0,
        data.size() + 1
    );

    if (this->section_data == nullptr) {
        gnomes_error("Could not resize for section: %s", this->name.c_str());
        goto exit_insert;
    }

    memmove(
        this->section_data.get() + entry_offset + data.size() + 1,
        this->section_data.get() + entry_offset,
        this->hdr->sh_size - (data.size() + 1) - entry_offset
    );

    std::copy(
        data.c_str(),
        data.c_str() + data.size() + 1,
        this->section_data.get() + entry_offset
    );

    ret = true;

exit_insert:
    return ret;
}

template <typename ELF_SHDR> template <typename T>
bool ELFSection<ELF_SHDR>::insert(const T* data, const uint64_t entry_idx)
{
    bool ret = false;
    const uint64_t entry_offset = entry_idx * sizeof(T);

    this->section_data = resize_smart_ptr<ELF_SHDR, T>(
        this->priv_hdr,
        std::move(this->section_data)
    );

    if (this->section_data == nullptr) {
        gnomes_error("Could not resize for section: %s", this->name.c_str());
        goto exit_insert;
    }

    memmove(
        this->section_data.get() + entry_offset + sizeof(T),
        this->section_data.get() + entry_offset,
        this->hdr->sh_size - sizeof(T) - entry_offset
    );

    std::copy(
        (uint8_t*) data,
        (uint8_t*) data + sizeof(T),
        this->section_data.get() + entry_offset
    );

    ret = true;

exit_insert:
    return ret;
}

template <typename ELF_SHDR> template <typename T>
bool ELFSection<ELF_SHDR>::remove(const uint64_t entry_idx)
{
    bool ret = false;

    this->section_data = resize_smart_ptr<ELF_SHDR, T>(
        this->priv_hdr,
        std::move(this->section_data),
        true,
        entry_idx
    );

    if (this->section_data == nullptr) {
        gnomes_error("Could not resize for section: %s", this->name.c_str());
        goto exit_remove;
    }

    ret = true;

exit_remove:
    return ret;
}

template <typename ELF_SHDR>
bool ELFSection<ELF_SHDR>::remove_str(const uint64_t entry_idx)
{
    bool ret = false;

    this->section_data = resize_smart_ptr_str<ELF_SHDR>(
        this->priv_hdr,
        std::move(this->section_data),
        true,
        entry_idx
    );

    if (this->section_data == nullptr) {
        gnomes_error("Could not resize for section: %s", this->name.c_str());
        goto exit_remove;
    }

    ret = true;

exit_remove:
    return ret;
}

template <typename ELF_SHDR>
std::string ELFSection<ELF_SHDR>::operator[](uint64_t entry_idx)
{
    if (entry_idx < this->hdr->sh_size)
        return std::string(&(((char*) this->section_data.get())[entry_idx]));
    else
        return std::string();
}

ELFFormat::ELFFormat(const std::string file_name)
{
    std::ifstream infile;
    Elf32_Ehdr *hdr = nullptr;

    std::unique_ptr<uint8_t[]> data = nullptr;

    this->is_elf64 = false;
    this->is_valid = false;
    this->len = std::filesystem::file_size(file_name);

    this->dynamic = nullptr;
    this->hashtab = nullptr;
    this->strtab = nullptr;
    this->symtab = nullptr;

    this->shstr = nullptr;
    this->program_data = nullptr;
    this->prog_data = nullptr;

    infile.open(file_name, std::ios::binary);

    if (!infile.is_open()) {
        gnomes_error("Binary %s could not be loaded.", file_name.c_str());
        goto exit_elf_format;
    }

    data = std::make_unique<uint8_t[]>(this->len);
    if (data == nullptr) {
        gnomes_error("Could not allocate memory for the binary in place.");
        goto exit_elf_format;
    }

    std::copy(
        std::istreambuf_iterator<char>(infile),
        std::istreambuf_iterator<char>(),
        data.get()
    );

    hdr = (Elf32_Ehdr*) data.get();

    if (hdr->e_ident[EI_MAG0] != ELFMAG0 ||
        hdr->e_ident[EI_MAG1] != ELFMAG1 ||
        hdr->e_ident[EI_MAG2] != ELFMAG2 ||
        hdr->e_ident[EI_MAG3] != ELFMAG3) {
        gnomes_error("Invalid binary, not a proper ELF format.");
        goto exit_elf_format;
    }

    this->is_valid = true;

    if (hdr->e_ident[EI_CLASS] == ELFCLASS64) {
        std::copy(
            data.get(),
            data.get() + sizeof(Elf64_Ehdr),
            (uint8_t*) &(this->hdr64)
        );
        this->is_elf64 = true;
    } else {
        std::copy(
            data.get(),
            data.get() + sizeof(Elf32_Ehdr),
            (uint8_t*) &(this->hdr32)
        );
    }

    // Gets the program headers.
    if (this->is_elf64) {
        if (this->hdr64.e_phnum != 0) {
            gnomes_notice("Copying %d entries of program data for ELF64 file: %s", this->hdr64.e_phnum, file_name.c_str());
            const uint64_t program_data_size = this->hdr64.e_phnum * this->hdr64.e_phentsize;
            this->program_data = std::move(std::make_unique<uint8_t[]>(program_data_size));
            std::copy(
                data.get() + this->hdr64.e_phoff,
                data.get() + this->hdr64.e_phoff + program_data_size,
                this->program_data.get()
            );
            this->prog_data = std::static_pointer_cast<const uint8_t[]>(this->program_data);
        }
    } else {
        if (this->hdr32.e_phnum != 0) {
            gnomes_notice("Copying %d entries of program data for ELF32 file: %s", this->hdr32.e_phnum, file_name.c_str());
            const uint32_t program_data_size = this->hdr32.e_phnum * this->hdr32.e_phentsize;
            this->program_data = std::move(std::make_unique<uint8_t[]>(program_data_size));
            std::copy(
                data.get() + this->hdr32.e_phoff,
                data.get() + this->hdr32.e_phoff + program_data_size,
                this->program_data.get()
            );
            this->prog_data = std::static_pointer_cast<const uint8_t[]>(this->program_data);
        }
    }

    // Gets the sections.
    if (this->is_elf64) {
        const uint64_t spot = this->hdr64.e_shoff;
        const uint64_t strndx = this->hdr64.e_shstrndx;
        const uint64_t stroff = spot + strndx * this->hdr64.e_shentsize;
        std::shared_ptr<ELFSection<Elf64_Shdr>> shstr = nullptr;
        std::unique_ptr<Elf64_Shdr> shstr_hdr = std::make_unique<Elf64_Shdr>();
        std::unique_ptr<uint8_t[]> shstr_data = nullptr;

        std::copy(
            (Elf64_Shdr*) (data.get() + stroff),
            (Elf64_Shdr*) (data.get() + stroff + this->hdr64.e_shentsize),
            shstr_hdr.get()
        );

        shstr_data = std::make_unique<uint8_t[]>(shstr_hdr->sh_size);

        std::copy(
            data.get() + shstr_hdr->sh_offset,
            data.get() + shstr_hdr->sh_offset + shstr_hdr->sh_size,
            shstr_data.get()
        );

        shstr = std::make_shared<ELFSection<Elf64_Shdr>>(
            ".shstrtab",
            std::move(shstr_hdr),
            std::move(shstr_data),
            0
        );
        this->shstr = std::static_pointer_cast<ELFSectionInterface>(shstr);

        gnomes_notice("Reading sections for ELF64 file: %s", file_name.c_str());
        for (Elf64_Half i = 0; i < this->hdr64.e_shnum; ++i) {
            const uint64_t sect_offset = spot + i * this->hdr64.e_shentsize;
            std::shared_ptr<ELFSection<Elf64_Shdr>> sect = nullptr;
            std::shared_ptr<ELFSectionInterface> nsect = nullptr;
            std::unique_ptr<Elf64_Shdr> sect_hdr = std::make_unique<Elf64_Shdr>();
            std::unique_ptr<uint8_t[]> sect_data = nullptr;

            if (i == strndx) {
                this->shstr->name = (*shstr)[shstr->hdr->sh_name];
                this->shstr->idx = i;
                this->sections.push_back(this->shstr);
                gnomes_info("\t[%.2d] %s", i, this->shstr->name.c_str());
                continue;
            }

            std::copy(
                (Elf64_Shdr*) (data.get() + sect_offset),
                (Elf64_Shdr*) (data.get() + sect_offset + this->hdr64.e_shentsize),
                sect_hdr.get()
            );

            sect_data = std::make_unique<uint8_t[]>(sect_hdr->sh_size);

            std::copy(
                data.get() + sect_hdr->sh_offset,
                data.get() + sect_hdr->sh_offset + sect_hdr->sh_size,
                sect_data.get()
            );

            sect = std::make_shared<ELFSection<Elf64_Shdr>>(
                (*shstr)[sect_hdr->sh_name],
                std::move(sect_hdr),
                std::move(sect_data),
                i
            );
            nsect = std::static_pointer_cast<ELFSectionInterface>(sect);
            switch (sect->hdr->sh_type) {
            case SHT_DYNAMIC:
                this->dynamic = nsect;
                break;
            case SHT_DYNSYM:
                this->symtab = nsect;
                break;
            case SHT_HASH:
                this->hashtab = nsect;
                break;
            case SHT_STRTAB:
                this->strtab = nsect;
                break;
            case SHT_SYMTAB:
                if (this->symtab == nullptr)
                    this->symtab = nsect;
                break;
            }
            gnomes_info("\t[%.2d] %s", i, sect->name.c_str());
            this->sections.push_back(nsect);
        }
    } else {
        const uint32_t spot = this->hdr32.e_shoff;
        const uint32_t strndx = this->hdr32.e_shstrndx;
        const uint32_t stroff = spot + strndx * this->hdr32.e_shentsize;
        std::shared_ptr<ELFSection<Elf32_Shdr>> shstr = nullptr;
        std::unique_ptr<Elf32_Shdr> shstr_hdr = std::make_unique<Elf32_Shdr>();
        std::unique_ptr<uint8_t[]> shstr_data = nullptr;

        std::copy(
            (Elf32_Shdr*) (data.get() + stroff),
            (Elf32_Shdr*) (data.get() + stroff + this->hdr64.e_shentsize),
            shstr_hdr.get()
        );

        shstr_data = std::make_unique<uint8_t[]>(shstr_hdr->sh_size);

        std::copy(
            data.get() + shstr_hdr->sh_offset,
            data.get() + shstr_hdr->sh_offset + shstr_hdr->sh_size,
            shstr_data.get()
        );

        shstr = std::make_shared<ELFSection<Elf32_Shdr>>(
            ".shstrtab",
            std::move(shstr_hdr),
            std::move(shstr_data),
            0
        );
        this->shstr = std::static_pointer_cast<ELFSectionInterface>(shstr);

        gnomes_notice("Reading segments for ELF32 file: %s", file_name.c_str());
        for (Elf32_Half i = 0; i < this->hdr32.e_shnum; ++i) {
            const uint32_t sect_offset = spot + i * this->hdr32.e_shentsize;
            std::shared_ptr<ELFSection<Elf32_Shdr>> sect = nullptr;
            std::shared_ptr<ELFSectionInterface> nsect = nullptr;
            std::unique_ptr<Elf32_Shdr> sect_hdr = std::make_unique<Elf32_Shdr>();
            std::unique_ptr<uint8_t[]> sect_data = nullptr;

            if (i == strndx) {
                this->shstr->name = (*shstr)[shstr->hdr->sh_name];
                this->shstr->idx = i;
                this->sections.push_back(this->shstr);
                gnomes_info("\t[%.2d] %s", i, this->shstr->name.c_str());
                continue;
            }

            std::copy(
                (Elf32_Shdr*) (data.get() + sect_offset),
                (Elf32_Shdr*) (data.get() + sect_offset + this->hdr64.e_shentsize),
                sect_hdr.get()
            );

            sect_data = std::make_unique<uint8_t[]>(sect_hdr->sh_size);

            std::copy(
                data.get() + sect_hdr->sh_offset,
                data.get() + sect_hdr->sh_offset + sect_hdr->sh_size,
                sect_data.get()
            );

            sect = std::make_shared<ELFSection<Elf32_Shdr>>(
                (*shstr)[sect_hdr->sh_name],
                std::move(sect_hdr),
                std::move(sect_data),
                i
            );
            nsect = std::static_pointer_cast<ELFSectionInterface>(sect);
            switch (sect->hdr->sh_type) {
            case SHT_DYNAMIC:
                this->dynamic = nsect;
                break;
            case SHT_DYNSYM:
                this->symtab = nsect;
                break;
            case SHT_HASH:
                this->hashtab = nsect;
                break;
            case SHT_STRTAB:
                this->strtab = nsect;
                break;
            case SHT_SYMTAB:
                if (this->symtab == nullptr)
                    this->symtab = nsect;
                break;
            }
            gnomes_info("\t[%.2d] %s", i, sect->name.c_str());
            this->sections.push_back(nsect);
        }
    }

exit_elf_format:
    if (infile.is_open()) infile.close();
}

bool ELFFormat::valid()
{
    return this->is_valid;
}

uint64_t ELFFormat::size()
{
    uint64_t len = 0;

    if (this->is_elf64) {
        len += sizeof(Elf64_Ehdr);
        len += this->hdr64.e_phnum * this->hdr64.e_phentsize;
    } else {
        len += sizeof(Elf32_Ehdr);
        len += this->hdr32.e_phnum * this->hdr32.e_phentsize;
    }

    if (this->hashtab.get() && this->strtab.get() && this->symtab.get()) {
        if (this->is_elf64)
            elf_fix_hash_table<Elf64_Word, Elf64_Sym, Elf64_Shdr>(
                std::static_pointer_cast<ELFSection<Elf64_Shdr>>(this->hashtab),
                std::static_pointer_cast<ELFSection<Elf64_Shdr>>(this->strtab),
                std::static_pointer_cast<ELFSection<Elf64_Shdr>>(this->symtab)
            );
        else
            elf_fix_hash_table<Elf32_Word, Elf32_Sym, Elf32_Shdr>(
                std::static_pointer_cast<ELFSection<Elf32_Shdr>>(this->hashtab),
                std::static_pointer_cast<ELFSection<Elf32_Shdr>>(this->strtab),
                std::static_pointer_cast<ELFSection<Elf32_Shdr>>(this->symtab)
            );
    }

    for (const auto &section : this->sections) {
        if (this->is_elf64) {
            std::shared_ptr<ELFSection<Elf64_Shdr>> s = std::static_pointer_cast<ELFSection<Elf64_Shdr>>(section);
            std::shared_ptr<const Elf64_Shdr> hdr = s->hdr;
            if (hdr->sh_offset == 0 && hdr->sh_size == 0) continue;
            if (len % hdr->sh_addralign) len = (len + hdr->sh_addralign - 1) & ~(hdr->sh_addralign - 1);
            if (hdr->sh_offset > len) {
                len = hdr->sh_offset;
            }
            s->set_offset(len);
            if (hdr->sh_type != SHT_NOBITS)
                len += hdr->sh_size;
        } else {
            std::shared_ptr<ELFSection<Elf32_Shdr>> s = std::static_pointer_cast<ELFSection<Elf32_Shdr>>(section);
            std::shared_ptr<const Elf32_Shdr> hdr = s->hdr;
            if (hdr->sh_offset == 0 && hdr->sh_size == 0) continue;
            if (len % hdr->sh_addralign) len = (len + hdr->sh_addralign - 1) & ~(hdr->sh_addralign - 1);
            if (hdr->sh_offset > len) {
                len = hdr->sh_offset;
            }
            s->set_offset(len);
            if (hdr->sh_type != SHT_NOBITS)
                len += hdr->sh_size;
        }
    }

    if (this->program_data != nullptr && this->is_elf64) {
        fix_dynamic_entries<Elf64_Dyn, Elf64_Shdr>(
            std::static_pointer_cast<ELFSection<Elf64_Shdr>>(this->dynamic),
            this->sections
        );
    } else if (this->program_data != nullptr) {
        fix_dynamic_entries<Elf32_Dyn, Elf32_Shdr>(
            std::static_pointer_cast<ELFSection<Elf32_Shdr>>(this->dynamic),
            this->sections
        );
    }

    if (this->is_elf64) {
        if (len % sizeof(Elf64_Xword)) len = (len + sizeof(Elf64_Xword) - 1) & ~(sizeof(Elf64_Xword) - 1);
        this->hdr64.e_shoff = len;
        len += this->hdr64.e_shnum * this->hdr64.e_shentsize;
    } else {
        if (len % sizeof(Elf32_Xword)) len = (len + sizeof(Elf32_Xword) - 1) & ~(sizeof(Elf32_Xword) - 1);
        this->hdr32.e_shoff = len;
        len += this->hdr32.e_shnum * this->hdr32.e_shentsize;
    }

    this->len = len;

    return this->len;
}

std::unique_ptr<uint8_t[]> ELFFormat::binary()
{
    std::unique_ptr<uint8_t[]> ret = std::make_unique<uint8_t[]>(this->size());

    uint64_t len = 0;
    uint64_t i = 0;

    if (ret == nullptr) return ret;

    if (this->is_elf64) {
        std::copy(
            (uint8_t*) &(this->hdr64),
            ((uint8_t*) &(this->hdr64)) + sizeof(Elf64_Ehdr),
            ret.get()
        );
        len += sizeof(Elf64_Ehdr);
        if (this->hdr64.e_phnum != 0) {
            std::copy(
                this->program_data.get(),
                this->program_data.get() + this->hdr64.e_phnum * this->hdr64.e_phentsize,
                ret.get() + len
            );
            len += this->hdr64.e_phnum * this->hdr64.e_phentsize;
        }
    } else {
        std::copy(
            (uint8_t*) &(this->hdr32),
            ((uint8_t*) &(this->hdr32)) + sizeof(Elf32_Ehdr),
            ret.get()
        );
        len += sizeof(Elf32_Ehdr);
        if (this->hdr32.e_phnum != 0) {
            std::copy(
                this->program_data.get(),
                this->program_data.get() + this->hdr32.e_phnum * this->hdr32.e_phentsize,
                ret.get() + len
            );
            len += this->hdr32.e_phnum * this->hdr32.e_phentsize;
        }
    }

    for (const auto &section : this->sections) {
        if (this->is_elf64) {
            std::shared_ptr<ELFSection<Elf64_Shdr>> s = std::static_pointer_cast<ELFSection<Elf64_Shdr>>(section);
            std::shared_ptr<const Elf64_Shdr> hdr = s->hdr;
            std::copy(
                (uint8_t*) hdr.get(),
                ((uint8_t*) hdr.get()) + sizeof(Elf64_Shdr),
                ret.get() + this->hdr64.e_shoff + (i++) * this->hdr64.e_shentsize
            );
            if (hdr->sh_offset == 0 && hdr->sh_size == 0) continue;
            if (len % hdr->sh_addralign) len = (len + hdr->sh_addralign - 1) & ~(hdr->sh_addralign - 1);
            if (hdr->sh_offset > len) {
                len = hdr->sh_offset;
            }
            if (hdr->sh_type != SHT_NOBITS) {
                std::copy(
                    s->section_data.get(),
                    s->section_data.get() + hdr->sh_size,
                    ret.get() + len
                );
                len += hdr->sh_size;
            }
        } else {
            std::shared_ptr<ELFSection<Elf32_Shdr>> s = std::static_pointer_cast<ELFSection<Elf32_Shdr>>(section);
            std::shared_ptr<const Elf32_Shdr> hdr = s->hdr;
            std::copy(
                (uint8_t*) hdr.get(),
                ((uint8_t*) hdr.get()) + sizeof(Elf32_Shdr),
                ret.get() + this->hdr32.e_shoff + (i++) * this->hdr32.e_shentsize
            );
            if (hdr->sh_offset == 0 && hdr->sh_size == 0) continue;
            if (len % hdr->sh_addralign) len = (len + hdr->sh_addralign - 1) & ~(hdr->sh_addralign - 1);
            if (hdr->sh_offset > len) {
                len = hdr->sh_offset;
            }
            if (hdr->sh_type != SHT_NOBITS) {
                std::copy(
                    s->section_data.get(),
                    s->section_data.get() + hdr->sh_size,
                    ret.get() + len
                );
                len += hdr->sh_size;
            }
        }
    }

    if (this->is_elf64) {
        if (len % sizeof(Elf64_Xword)) len = (len + sizeof(Elf64_Xword) - 1) & ~(sizeof(Elf64_Xword) - 1);
        this->hdr64.e_shoff = len;
        len += this->hdr64.e_shnum * this->hdr64.e_shentsize;
    } else {
        if (len % sizeof(Elf32_Xword)) len = (len + sizeof(Elf32_Xword) - 1) & ~(sizeof(Elf32_Xword) - 1);
        this->hdr32.e_shoff = len;
        len += this->hdr32.e_shnum * this->hdr32.e_shentsize;
    }

    return std::move(ret);
}

// Template precompilations.
#define CREATE_TEMPLATED(X, Y)                                            \
    template bool ELFSection<X>::append<Y>(const Y*);                     \
    template bool ELFSection<X>::insert<Y>(const Y*, const uint64_t);     \
    template bool ELFSection<X>::remove<Y>(const uint64_t);

CREATE_TEMPLATED(Elf32_Shdr, Elf32_Sym);
CREATE_TEMPLATED(Elf32_Shdr, Elf32_Rel);
CREATE_TEMPLATED(Elf32_Shdr, Elf32_Rela);
CREATE_TEMPLATED(Elf64_Shdr, Elf64_Sym);
CREATE_TEMPLATED(Elf64_Shdr, Elf64_Rel);
CREATE_TEMPLATED(Elf64_Shdr, Elf64_Rela);

#undef CREATE_TEMPLATED

template class ELFSection<Elf32_Shdr>;
template class ELFSection<Elf64_Shdr>;
