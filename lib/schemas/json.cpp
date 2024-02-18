/*
 * Copyright (C) 2666680 Ontario Inc.
 *
 * SPDX-License-Identifier: MIT
 *
 */
#include <rapidjson/document.h>
#include <rapidjson/schema.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/prettywriter.h>

#include <gnomes/logger.h>
#include <gnomes/schemas.h>

#include "g_schemas.hpp"

static uint8_t init()
{
    return 1;
}

static uint8_t valid(
    const char *type_cstr,
    const char *schema_cstr,
    void *node_ptr
)
{
    uint8_t ret = 0;
    std::string type_str = type_cstr;
    std::string schema_str = schema_cstr;
    std::map<std::string, std::string> higher_schemas = schemas[type_str];
    std::string json_str = higher_schemas[schema_str];
    rapidjson::Document d;
    rapidjson::Value *node = (rapidjson::Value*) node_ptr;

    rapidjson::StringBuffer buffer;
    rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(buffer);

    node->Accept(writer);

    gnomes_debug("Validating against schema: %s, %s", type_cstr, schema_cstr);
    gnomes_debug("The JSON we are validating is: %s", buffer.GetString());

    if (d.Parse(json_str.c_str()).HasParseError()) {
        gnomes_error("Invalid json string for %s, %s", type_cstr, schema_cstr);
        return 0;
    }

    rapidjson::SchemaDocument sd(d);
    rapidjson::SchemaValidator sv(sd);

    ret = node->Accept(sv);
    if (!ret) {
        rapidjson::StringBuffer sb;
        sv.GetInvalidSchemaPointer().StringifyUriFragment(sb);
        gnomes_error("Invalid schema: %s", sb.GetString());
        gnomes_error("Invalid keyword: %s", sv.GetInvalidSchemaKeyword());
        sb.Clear();
        sv.GetInvalidDocumentPointer().StringifyUriFragment(sb);
        gnomes_error("Invalid document: %s", sb.GetString());
    }

    return ret;
}

struct GnomeSchemaAPI json_schema_api = {
.inited = 0,
.init = init,
.valid = valid
};
