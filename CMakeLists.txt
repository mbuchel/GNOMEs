#
# Copyright (C) 2666680 Ontario Inc.
#
# SPDX-License-Identifier: MIT
#
cmake_minimum_required(VERSION 3.9.1)

project("GNOMEs" VERSION 0.0.1)

# Generated GNOMEs.
set(
  GNOMES
  ${CMAKE_CURRENT_BINARY_DIR}/gnomes-elf-inject.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/gnomes-elf-patch.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/gnomes-elf-rename.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/gnomes-run.cpp
)

# JSON schema locations.
set(
  ELF_JSON_SCHEMAS
  ${CMAKE_CURRENT_BINARY_DIR}/g_schemas.hpp
  ${CMAKE_CURRENT_BINARY_DIR}/g_elf_schemas.hpp
)

# Install and get the vendor libraries
include(ExternalProject)
include("${CMAKE_SOURCE_DIR}/vendor/asmjit.cmake")
include("${CMAKE_SOURCE_DIR}/vendor/asmtk.cmake")
include("${CMAKE_SOURCE_DIR}/vendor/elfio.cmake")
include("${CMAKE_SOURCE_DIR}/vendor/rapidjson.cmake")

file(GLOB EXE_SRC RELATIVE ${CMAKE_SOURCE_DIR} "exe/*.*")
file(GLOB_RECURSE LIB_SRC RELATIVE ${CMAKE_SOURCE_DIR} "lib/*.*")
file(GLOB_RECURSE SCHEMAS_SRC RELATIVE ${CMAKE_SOURCE_DIR} "schemas/*")

# Custom tool to help generate schemas from schema files.
add_executable(generate_gnome_schemas ${CMAKE_SOURCE_DIR}/tools/generate_gnome_schemas.cpp)
set_property(TARGET generate_gnome_schemas PROPERTY CXX_STANDARD 20)

# Custom tool to create different GNOMEs.
add_executable(generate_gnomes ${CMAKE_SOURCE_DIR}/tools/generate_gnomes.cpp)
set_property(TARGET generate_gnomes PROPERTY CXX_STANDARD 20)

# Custom generation command.
add_custom_command(
  OUTPUT
    ${ELF_JSON_SCHEMAS}
  COMMAND
    generate_gnome_schemas ${CMAKE_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}
  DEPENDS
    generate_gnome_schemas
    ${SCHEMAS_SRC}
)
add_custom_command(
  OUTPUT
    ${GNOMES}
  COMMAND
    generate_gnomes ${CMAKE_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}
  DEPENDS
    generate_gnomes
    ${EXE_SRC}
)

# GNOMEs libraries.
add_library(
  gnomes-static
  STATIC
  ${LIB_SRC}
  ${ELF_JSON_SCHEMAS}
)
target_include_directories(
  gnomes-static
  PRIVATE
   inc
   ${ASMJIT_INCLUDE_DIR}
   ${ASMTK_INCLUDE_DIR}
   ${ELFIO_INCLUDE_DIR}
   ${RAPIDJSON_INCLUDE_DIR}
   ${CMAKE_CURRENT_BINARY_DIR}
)
add_dependencies(gnomes-static asmjit asmtk elfio rapidjson)
set_property(TARGET gnomes-static PROPERTY C_STANDARD 99)
set_property(TARGET gnomes-static PROPERTY CXX_STANDARD 17)
target_link_libraries(
  gnomes-static
  ${ASMTK_LIBRARY}
  ${ASMJIT_LIBRARY}
)

# All the GNOMEs we create
foreach (exe ${GNOMES})
    get_filename_component(exename ${exe} NAME_WE)
    list(APPEND EXES "${exename}")
    add_executable(${exename} ${exe})
    target_include_directories(
      ${exename}
      PRIVATE
        inc
        ${RAPIDJSON_INCLUDE_DIR}
    )
    target_link_libraries(
      ${exename}
      PUBLIC
        gnomes-static
    )
    set_property(TARGET ${exename} PROPERTY C_STANDARD 99)
    set_property(TARGET ${exename} PROPERTY CXX_STANDARD 17)
endforeach ()

# Installs the main functions.
install(
  TARGETS ${EXES}
)
