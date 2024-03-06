/*
 * Copyright (C) 2666680 Ontario Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 */
#ifndef ELF_FORMAT_HPP
#define ELF_FORMAT_HPP

#include <elf.h>
#include <stdint.h>

#include <algorithm>
#include <string>
#include <map>
#include <memory>
#include <utility>
#include <vector>

#ifdef __cplusplus

/*! \brief Interface for interacting with ELF sections.
 *
 * This is a mechanism to allow us to hide the ELF section abstraction and
 * handle different classes of ELF format.
 */
class ELFSectionInterface
{
public:
        virtual std::string operator[](uint64_t entry_idx) = 0;
        virtual uint64_t get_size() = 0;

        virtual bool append(const std::string &data) = 0;
        virtual bool insert(const std::string &data, const uint64_t entry_idx) = 0;
        virtual bool remove_str(const uint64_t entry_idx) = 0;

        virtual bool patch(
                const uint8_t* data,
                const uint64_t patch_offset,
                const uint64_t patch_size,
                const int64_t diff = 0
        ) = 0;

        std::string name;
        std::unique_ptr<uint8_t[]> section_data;
        uint64_t idx;
};

/*! \brief This is a class to interact with sections of an ELF format.
 *
 * NOTES:
 * -# Only supports Elf32_Shdr and Elf64_Shdr
 */
template <typename ELF_SHDR>
class ELFSection : public ELFSectionInterface
{
public:
        template <typename W, typename S, typename H>
        friend void elf_fix_hash_table(
                std::shared_ptr<ELFSection<H>>,
                std::shared_ptr<ELFSection<H>>,
                std::shared_ptr<ELFSection<H>>
        );

        ELFSection(
                std::string name,
                std::unique_ptr<ELF_SHDR> hdr,
                std::unique_ptr<uint8_t[]> sect_data,
                uint64_t index
        );

        virtual bool patch(
                const uint8_t* data,
                const uint64_t patch_offset,
                const uint64_t patch_size,
                const int64_t diff = 0
        );

        template<typename T>
        bool append(const T* data);
        virtual bool append(const std::string &data);

        template<typename T>
        bool insert(const T* data, const uint64_t entry_idx);
        virtual bool insert(const std::string &data, const uint64_t entry_idx);

        template <typename T>
        T* get(uint64_t entry_idx) {
                return &(((T*) this->section_data.get())[entry_idx]);
        }

        virtual std::string operator[](uint64_t entry_idx);

        template<typename T>
        bool remove(const uint64_t entry_idx);
        virtual bool remove_str(const uint64_t entry_idx);

        template <typename T>
        uint64_t entries() {
                return (this->hdr->sh_size / sizeof(T));
        }

        void set_offset(const uint64_t offset) {
                this->priv_hdr->sh_offset = offset;
        }

        virtual uint64_t get_size() {
                return this->hdr->sh_size;
        }

        std::shared_ptr<const ELF_SHDR> hdr;

private:
        std::shared_ptr<ELF_SHDR> priv_hdr;
};

/*! \brief This is a class to interact/modify the ELF format.
 *
 * This tool allows us to modify the ELF format extensively as well as perform various validations.
 * It also allows us more tools to modify the ELF file than other libraries (ELFIO).
 */
class ELFFormat
{
public:
        ELFFormat(const std::string file_name);

        bool valid();

        bool is_linked();

        uint64_t size();

        std::unique_ptr<uint8_t[]> binary();

        bool elf64() { return this->is_elf64; }

        template <typename T, int bits>
        const T* get_hdr() {
                if (bits != 64)
                        return ((const T*) &(this->hdr64));
                else
                        return ((const T*) &(this->hdr32));
        }

        std::shared_ptr<const uint8_t[]> prog_data;

        std::shared_ptr<ELFSectionInterface> dynamic;
        std::shared_ptr<ELFSectionInterface> hashtab;
        std::shared_ptr<ELFSectionInterface> strtab;
        std::shared_ptr<ELFSectionInterface> symtab;

        std::vector<std::shared_ptr<ELFSectionInterface>> sections;

private:
        bool is_elf64;
        bool is_valid;

        uint64_t len;

        Elf32_Ehdr hdr32;
        Elf64_Ehdr hdr64;

        std::shared_ptr<uint8_t[]> program_data;
        std::shared_ptr<ELFSectionInterface> shstr;
};

#endif

#endif
