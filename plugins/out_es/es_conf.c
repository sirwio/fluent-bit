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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_upstream_ha.h>
#include <fluent-bit/flb_signv4.h>
#include <fluent-bit/flb_aws_credentials.h>

#include "es.h"
#include "es_conf.h"

int es_config_simple(struct flb_elasticsearch *ctx,
                     struct flb_output_instance *ins,
                     struct flb_config *config)
{

    int io_flags = 0;
    ssize_t ret;
    const char *tmp;
    const char *path;
#ifdef FLB_HAVE_AWS
    char *aws_role_arn = NULL;
    char *aws_external_id = NULL;
    char *aws_session_name = NULL;
#endif
    struct flb_uri *uri = ins->host.uri;
    struct flb_uri_field *f_index = NULL;
    struct flb_uri_field *f_type = NULL;
    struct flb_elasticsearch_config *ec = NULL;
    struct flb_upstream *upstream;

    /* Allocate context */
    ec = flb_calloc(1, sizeof(struct flb_elasticsearch_config));
    if (!ec) {
        flb_errno();
        return -1;
    }
    /* TODO - Check if line below shall be there */
    /* ctx->ins = ins; */

    if (uri) {
        if (uri->count >= 2) {
            f_index = flb_uri_get(uri, 0);
            f_type  = flb_uri_get(uri, 1);
        }
    }

    /* Set default network configuration */
    flb_output_net_default("127.0.0.1", 9200, ins);

    /* Populate context with config map defaults and incoming properties */
    ret = flb_output_config_map_set(ins, (void *) ec);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "configuration error");
        flb_es_conf_destroy(ec);
        return -1;
    }

    /* use TLS ? */
    if (ins->use_tls == FLB_TRUE) {
        io_flags = FLB_IO_TLS;
    }
    else {
        io_flags = FLB_IO_TCP;
    }

    if (ins->host.ipv6 == FLB_TRUE) {
        io_flags |= FLB_IO_IPV6;
    }

    /* Prepare an upstream handler */
    upstream = flb_upstream_create(config,
                                   ins->host.name,
                                   ins->host.port,
                                   io_flags,
                                   &ins->tls);
    if (!upstream) {
        flb_plg_error(ctx->ins, "cannot create Upstream context");
        flb_es_conf_destroy(ec);
        return -1;
    }
    ctx->u = upstream;

    /* Set instance flags into upstream */
    flb_output_upstream_set(ctx->u, ins);

    /* Set manual Index and Type */
    if (f_index) {
        ec->index = flb_strdup(f_index->value); /* FIXME */
    }

    if (f_type) {
        ec->type = flb_strdup(f_type->value); /* FIXME */
    }

    /* HTTP Payload (response) maximum buffer size (0 == unlimited) */
    if (ec->buffer_size == -1) {
        ec->buffer_size = 0;
    }

    /* Elasticsearch: Path */
    path = flb_output_get_property("path", ins);
    if (!path) {
        path = "";
    }

    /* Elasticsearch: Pipeline */
    tmp = flb_output_get_property("pipeline", ins);
    if (tmp) {
        snprintf(ec->uri, sizeof(ec->uri) - 1, "%s/_bulk/?pipeline=%s", path, tmp);
    }
    else {
        snprintf(ec->uri, sizeof(ec->uri) - 1, "%s/_bulk", path);
    }

#ifdef FLB_HAVE_AWS
    /* AWS Auth */
    ec->has_aws_auth = FLB_FALSE;
    tmp = flb_output_get_property("aws_auth", ins);
    if (tmp) {
        if (strncasecmp(tmp, "On", 2) == 0) {
            ec->has_aws_auth = FLB_TRUE;
            flb_debug("[out_es] Enabled AWS Auth");

            /* AWS provider needs a separate TLS instance */
            ec->aws_tls.context = flb_tls_context_new(FLB_TRUE,
                                                      ins->tls_debug,
                                                      ins->tls_vhost,
                                                      ins->tls_ca_path,
                                                      ins->tls_ca_file,
                                                      ins->tls_crt_file,
                                                      ins->tls_key_file,
                                                      ins->tls_key_passwd);
            if (!ec->aws_tls.context) {
                flb_errno();
                flb_es_conf_destroy(ec);
                return -1;
            }

            tmp = flb_output_get_property("aws_region", ins);
            if (!tmp) {
                flb_error("[out_es] aws_auth enabled but aws_region not set");
                flb_es_conf_destroy(ec);
                return -1;
            }
            ec->aws_region = (char *) tmp;

            ec->aws_provider = flb_standard_chain_provider_create(config,
                                                                   &ec->aws_tls,
                                                                   ec->aws_region,
                                                                   NULL,
                                                                   flb_aws_client_generator());
            if (!ec->aws_provider) {
                flb_error("[out_es] Failed to create AWS Credential Provider");
                flb_es_conf_destroy(ec);
                return -1;
            }

            tmp = flb_output_get_property("aws_role_arn", ins);
            if (tmp) {
                /* Use the STS Provider */
                ec->base_aws_provider = ec->aws_provider;
                aws_role_arn = (char *) tmp;
                aws_external_id = NULL;
                tmp = flb_output_get_property("aws_external_id", ins);
                if (tmp) {
                    aws_external_id = (char *) tmp;
                }

                aws_session_name = flb_sts_session_name();
                if (!aws_session_name) {
                    flb_error("[out_es] Failed to create aws iam role "
                              "session name");
                    flb_es_conf_destroy(ec);
                    return -1;
                }

                /* STS provider needs yet another separate TLS instance */
                ec->aws_sts_tls.context = flb_tls_context_new(FLB_TRUE,
                                                              ins->tls_debug,
                                                              ins->tls_vhost,
                                                              ins->tls_ca_path,
                                                              ins->tls_ca_file,
                                                              ins->tls_crt_file,
                                                              ins->tls_key_file,
                                                              ins->tls_key_passwd);
                   if(ec->aws_sts_tls.context) {
                    flb_errno();
                    flb_es_conf_destroy(ec);
                    return -1;
                }

                ec->aws_provider = flb_sts_provider_create(config,
                                                            &ec->aws_sts_tls,
                                                            ec->
                                                            base_aws_provider,
                                                            aws_external_id,
                                                            aws_role_arn,
                                                            aws_session_name,
                                                            ec->aws_region,
                                                            NULL,
                                                            flb_aws_client_generator());
                /* Session name can be freed once provider is created */
                flb_free(aws_session_name);
                if (!ec->aws_provider) {
                    flb_error("[out_es] Failed to create AWS STS Credential "
                              "Provider");
                    flb_es_conf_destroy(ec);
                    return -1;
                }

            }

            /* initialize credentials in sync mode */
            ec->aws_provider->provider_vtable->sync(ec->aws_provider);
            ec->aws_provider->provider_vtable->init(ec->aws_provider);
            /* set back to async */
            ec->aws_provider->provider_vtable->async(ec->aws_provider);
        }
    }
#endif


  /* Initialize and validate es_config context */
  ret = flb_es_conf_init(ec, ctx);
  if (ret == -1) {
      if (ec) {
          flb_es_conf_destroy(ec);
      }
      return -1;
  }

    return 0;
}

/* Configure in HA mode */
int es_config_ha(const char *upstream_file,
                 struct flb_elasticsearch *ctx,
                 struct flb_config *config)
{
    ssize_t ret = 0;
    const char *tmp;
    const char *path;
    struct mk_list *head;
    struct flb_uri_field *f_index = NULL;
    struct flb_uri_field *f_type = NULL;
    struct flb_upstream_node *node;
    struct flb_elasticsearch_config *ec = NULL;

    ctx->ha_mode = FLB_TRUE;
    ctx->ha = flb_upstream_ha_from_file(upstream_file, config);
    if (!ctx->ha) {
        flb_error("[out_es] cannot load Upstream file");
        return -1;
    }

    /* Iterate nodes and create a forward_config context */
    mk_list_foreach(head, &ctx->ha->nodes) {
        node = mk_list_entry(head, struct flb_upstream_node, _head);

        /* Allocate context */
        ec = flb_calloc(1, sizeof(struct flb_elasticsearch_config));
        if (!ec) {
            flb_errno();
            flb_error("[out_es] failed config allocation");
            continue;
        }

        /* Set default values */
        ret = flb_output_config_map_set(ctx->ins, ec);
        if (ret == -1) {
            flb_free(ec);
            return -1;
        }

        /* Elasticsearch: Path */
        path = flb_upstream_node_get_property("path", node);
        if (!path) {
            path = "";
        }

        /* Elasticsearch: Pipeline */
        tmp = flb_upstream_node_get_property("pipeline", node);
        if (tmp) {
            snprintf(ec->uri, sizeof(ec->uri) - 1, "%s/_bulk/?pipeline=%s", path, tmp);
        }
        else {
            snprintf(ec->uri, sizeof(ec->uri) - 1, "%s/_bulk", path);
        }

        /* Initialize and validate es_config context */
        ret = flb_es_conf_init(ec, ctx);
        if (ret == -1) {
            if (ec) {
                flb_es_conf_destroy(ec);
            }
            return -1;
        }

        /* Set our elasticsearch_config context into the node */
        flb_upstream_node_set_data(ec, node);
    }

    return 0;
}

int flb_es_conf_init(struct flb_elasticsearch_config *ec,
                     struct flb_elasticsearch *ctx)
{
  mk_list_add(&ec->_head, &ctx->configs);
  return 0;
}

int flb_es_conf_destroy(struct flb_elasticsearch_config *ec)
{
    if (!ec) {
        return 0;
    }

#ifdef FLB_HAVE_AWS
    if (ec->base_aws_provider) {
        flb_aws_provider_destroy(ec->base_aws_provider);
    }

    if (ec->aws_provider) {
        flb_aws_provider_destroy(ec->aws_provider);
    }

    if (ec->aws_tls.context) {
        flb_tls_context_destroy(ec->aws_tls.context);
    }

    if (ec->aws_sts_tls.context) {
        flb_tls_context_destroy(ec->aws_sts_tls.context);
    }
#endif

    flb_free(ec);

    return 0;
}

