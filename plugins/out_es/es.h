/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef FLB_OUT_ES_H
#define FLB_OUT_ES_H

#define FLB_ES_DEFAULT_HOST       "127.0.0.1"
#define FLB_ES_DEFAULT_PORT       92000
#define FLB_ES_DEFAULT_INDEX      "fluent-bit"
#define FLB_ES_DEFAULT_TYPE       "flb_type"
#define FLB_ES_DEFAULT_PREFIX     "logstash"
#define FLB_ES_DEFAULT_TIME_FMT   "%Y.%m.%d"
#define FLB_ES_DEFAULT_TIME_KEY   "@timestamp"
#define FLB_ES_DEFAULT_TIME_KEYF  "%Y-%m-%dT%H:%M:%S"
#define FLB_ES_DEFAULT_TAG_KEY    "flb-key"
#define FLB_ES_DEFAULT_HTTP_MAX   "4096"

struct flb_elasticsearch_config {
    /* Elasticsearch index (database) and type (table) */
    char *index;
    char *type;

    /* HTTP Auth */
    char *http_user;
    char *http_passwd;

    /* AWS Auth */
#ifdef FLB_HAVE_SIGNV4
    int has_aws_auth;
    char *aws_region;
#endif

    /* HTTP Client Setup */
    size_t buffer_size;

    /*
     * If enabled, replace field name dots with underscore, required for
     * Elasticsearch 2.0-2.3.
     */
    int replace_dots;

    int trace_output;
    int trace_error;

    /*
     * Logstash compatibility options
     * ==============================
     */

    /* enabled/disabled */
    int logstash_format;
    int generate_id;
    int current_time_index;

    /* prefix */
    flb_sds_t logstash_prefix;

    /* prefix key */
    flb_sds_t logstash_prefix_key;

    /* date format */
    flb_sds_t logstash_dateformat;

    /* time key */
    flb_sds_t time_key;

    /* time key format */
    flb_sds_t time_key_format;

    /* include_tag_key */
    int include_tag_key;
    flb_sds_t tag_key;

    /* Elasticsearch HTTP API */
    char uri[256];

    /* Link to list flb_elasticsearch->configs */
    struct mk_list _head;
};

struct flb_elasticsearch {
    /* if HA mode is enabled */
    int ha_mode;              /* High Availability mode enabled ? */
    char *ha_upstream;        /* Upstream configuration file      */
    struct flb_upstream_ha *ha;

    /* Upstream handler and config context for single mode (no HA) */
    struct flb_upstream *u;
    struct mk_list configs;
    struct flb_output_instance *ins;
};

#endif
