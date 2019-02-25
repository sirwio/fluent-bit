/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_metrics.h>
#include <fluent-bit/flb_storage.h>
#include <fluent-bit/stream_processor/flb_sp.h>
#include <fluent-bit/stream_processor/flb_sp_stream.h>

/* Function defined in plugins/in_stream_processor/sp.c */
int in_stream_processor_add_chunk(char *buf_data, size_t buf_size,
                                  struct flb_input_instance *in);

/* Check if a given stream name already exists */
static int sp_stream_name_exists(char *name, struct flb_config *config)
{
    struct mk_list *head;
    struct flb_input_instance *in;

    mk_list_foreach(head, &config->inputs) {
        in = mk_list_entry(head, struct flb_input_instance, _head);
        if (strcmp(in->name, name) == 0) {
            return FLB_TRUE;
        }

        if (in->alias) {
            if (strcmp(in->alias, name) == 0) {
                return FLB_TRUE;
            }
        }
    }

    return FLB_FALSE;
}

int flb_sp_stream_create(char *name, struct flb_sp_task *task,
                         struct flb_sp *sp)
{
    int ret;
    struct flb_input_instance *in;
    struct flb_sp_stream *stream;

    /* The name must be different than an input plugin instance name or alias */
    ret = sp_stream_name_exists(name, sp->config);
    if (ret == FLB_TRUE) {
        flb_error("[sp] stream name '%s' already exists", name);
        return -1;
    }

    /* Create stream context for 'stream processor' */
    stream = flb_malloc(sizeof(struct flb_sp_stream));
    if (!stream) {
        flb_errno();
        return -1;
    }
    stream->name = flb_sds_create(name);
    if (!stream->name) {
        return -1;
    }

    /*
     * Register an input plugin instance using 'in_stream_processor', that one
     * is used as the parent plugin to ingest data back into Fluent Bit
     * data pipeline.
     */
    in = flb_input_new(sp->config, "stream_processor", NULL, FLB_FALSE);
    if (!in) {
        flb_error("[sp] cannot create instance of in_stream_processor");
        flb_free(stream);
        return -1;
    }

    /* Set an alias, otherwise the stream will be called stream_processor.N */
    ret = flb_input_set_property(in, "alias", name);
    if (ret == -1) {
        flb_warn("[sp] cannot set stream name, using fallback name %s",
                 in->name);
    }

    /* Initialize instance */
    ret = flb_input_instance_init(in, sp->config);
    if (ret == -1) {
        flb_error("[sp] cannot initialize instance of in_stream_processor");
        flb_input_instance_exit(in, sp->config);
        flb_input_instance_free(in);
    }
    stream->in = in;

    /* Initialize plugin collector (event callback) */
    flb_input_collector_start(0, in);

#ifdef FLB_HAVE_METRICS
    /* Override Metrics title */
    ret = flb_metrics_title(name, in->metrics);
    if (ret == -1) {
        flb_warn("[sp] cannot set metrics title, using fallback name %s",
                 in->name);
    }
#endif

    /* Storage context */
    ret = flb_storage_input_create(sp->config->cio, in);
    if (ret == -1) {
        flb_error("[sp] cannot initialize storage for stream '%s'",
                  name);
        flb_sp_stream_destroy(stream, sp);
        return -1;
    }

    task->stream = stream;
    return 0;
}

int flb_sp_stream_append_data(char *buf_data, size_t buf_size,
                              struct flb_sp_stream *stream)
{
    return in_stream_processor_add_chunk(buf_data, buf_size, stream->in);
}

void flb_sp_stream_destroy(struct flb_sp_stream *stream, struct flb_sp *sp)
{
    flb_sds_destroy(stream->name);
    flb_input_instance_exit(stream->in, sp->config);
    flb_input_instance_free(stream->in);
    flb_free(stream);
}
