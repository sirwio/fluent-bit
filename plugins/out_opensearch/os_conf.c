/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_upstream_ha.h>
#include <fluent-bit/flb_signv4.h>
#include <fluent-bit/flb_aws_credentials.h>

#include "opensearch.h"
#include "os_conf.h"

int os_config_simple(struct flb_opensearch *ctx,
                     struct flb_output_instance *ins,
                     struct flb_config *config)
{
    int len;
    int io_flags = 0;
    ssize_t ret;
    char *buf;
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
    struct flb_opensearch_config *oc = NULL;
    struct flb_upstream *upstream;

    /* Allocate context */
    oc = flb_calloc(1, sizeof(struct flb_opensearch_config));
    if (!oc) {
        flb_errno();
        return -1;
    }

    /* only used if the config has been set from the command line */
    if (uri) {
        if (uri->count >= 2) {
            f_index = flb_uri_get(uri, 0);
            f_type  = flb_uri_get(uri, 1);
        }
    }

    /* Set default network configuration */
    flb_output_net_default("127.0.0.1", 9200, ins);

    /* Populate context with config map defaults and incoming properties */
    ret = flb_output_config_map_set(ins, (void *) oc);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "configuration error");
        flb_os_conf_destroy(oc);
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
                                   ins->tls);
    if (!upstream) {
        flb_plg_error(ctx->ins, "cannot create Upstream context");
        flb_os_conf_destroy(oc);
        return -1;
    }
    ctx->u = upstream;

    /* Set instance flags into upstream */
    flb_output_upstream_set(ctx->u, ins);

    /* Set manual Index and Type */
    if (f_index) {
        oc->index = flb_strdup(f_index->value);
    }
    else {
        /* Check if the index has been set in the configuration */
        if (oc->index) {
            /* do we have a record accessor pattern ? */
            if (strchr(oc->index, '$')) {
                oc->ra_index = flb_ra_create(oc->index, FLB_TRUE);
                if (!oc->ra_index) {
                    flb_plg_error(ctx->ins, "invalid record accessor pattern set for 'index' property");
                    flb_os_conf_destroy(oc);
                    return -1;
                }
            }
        }
    }

    if (f_type) {
        oc->type = flb_strdup(f_type->value); /* FIXME */
    }

    /* HTTP Payload (response) maximum buffer size (0 == unlimited) */
    if (oc->buffer_size == -1) {
        oc->buffer_size = 0;
    }

    /* Path */
    path = flb_output_get_property("path", ins);
    if (!path) {
        path = "";
    }

    /* Pipeline */
    tmp = flb_output_get_property("pipeline", ins);
    if (tmp) {
        snprintf(oc->uri, sizeof(oc->uri) - 1, "%s/_bulk/?pipeline=%s", path, tmp);
    }
    else {
        snprintf(oc->uri, sizeof(oc->uri) - 1, "%s/_bulk", path);
    }


    if (oc->id_key) {
        oc->ra_id_key = flb_ra_create(oc->id_key, FLB_FALSE);
        if (oc->ra_id_key == NULL) {
            flb_plg_error(ins, "could not create record accessor for Id Key");
        }
        if (oc->generate_id == FLB_TRUE) {
            flb_plg_warn(ins, "Generate_ID is ignored when ID_key is set");
            oc->generate_id = FLB_FALSE;
        }
    }

    if (oc->write_operation) {
        if (strcasecmp(oc->write_operation, FLB_OS_WRITE_OP_INDEX) == 0) {
            oc->action = FLB_OS_WRITE_OP_INDEX;
        }
        else if (strcasecmp(oc->write_operation, FLB_OS_WRITE_OP_CREATE) == 0) {
            oc->action = FLB_OS_WRITE_OP_CREATE;
        }
        else if (strcasecmp(oc->write_operation, FLB_OS_WRITE_OP_UPDATE) == 0
            || strcasecmp(oc->write_operation, FLB_OS_WRITE_OP_UPSERT) == 0) {
            oc->action = FLB_OS_WRITE_OP_UPDATE;
        }
        else {
            flb_plg_error(ins,
                          "wrong Write_Operation (should be one of index, "
                          "create, update, upsert)");
            flb_os_conf_destroy(oc);
            return -1;
        }

        if (strcasecmp(oc->action, FLB_OS_WRITE_OP_UPDATE) == 0
            && !oc->ra_id_key && oc->generate_id == FLB_FALSE) {
            flb_plg_error(ins,
                          "id_key or generate_id must be set when Write_Operation "
                          "update or upsert");
            flb_os_conf_destroy(oc);
            return -1;
        }
    }

    if (oc->logstash_prefix_key) {
        if (oc->logstash_prefix_key[0] != '$') {
            len = flb_sds_len(oc->logstash_prefix_key);
            buf = flb_malloc(len + 2);
            if (!buf) {
                flb_errno();
                flb_os_conf_destroy(oc);
                return -1;
            }
            buf[0] = '$';
            memcpy(buf + 1, oc->logstash_prefix_key, len);
            buf[len + 1] = '\0';

            oc->ra_prefix_key = flb_ra_create(buf, FLB_TRUE);
            flb_free(buf);
        }
        else {
            oc->ra_prefix_key = flb_ra_create(oc->logstash_prefix_key, FLB_TRUE);
        }

        if (!oc->ra_prefix_key) {
            flb_plg_error(ins, "invalid logstash_prefix_key pattern '%s'", tmp);
            flb_os_conf_destroy(oc);
            return -1;
        }
    }

#ifdef FLB_HAVE_AWS
    /* AWS Auth */
    oc->has_aws_auth = FLB_FALSE;
    tmp = flb_output_get_property("aws_auth", ins);
    if (tmp) {
        if (strncasecmp(tmp, "On", 2) == 0) {
            oc->has_aws_auth = FLB_TRUE;
            flb_debug("[out_es] Enabled AWS Auth");

            /* AWS provider needs a separate TLS instance */
            oc->aws_tls = flb_tls_create(FLB_TLS_CLIENT_MODE,
                                         FLB_TRUE,
                                         ins->tls_debug,
                                         ins->tls_vhost,
                                         ins->tls_ca_path,
                                         ins->tls_ca_file,
                                         ins->tls_crt_file,
                                         ins->tls_key_file,
                                         ins->tls_key_passwd);
            if (!oc->aws_tls) {
                flb_errno();
                flb_os_conf_destroy(oc);
                return -1;
            }

            tmp = flb_output_get_property("aws_region", ins);
            if (!tmp) {
                flb_error("[out_es] aws_auth enabled but aws_region not set");
                flb_os_conf_destroy(oc);
                return -1;
            }
            oc->aws_region = (char *) tmp;

            tmp = flb_output_get_property("aws_sts_endpoint", ins);
            if (tmp) {
                oc->aws_sts_endpoint = (char *) tmp;
            }

            oc->aws_provider = flb_standard_chain_provider_create(config,
                                                                  oc->aws_tls,
                                                                  oc->aws_region,
                                                                  oc->aws_sts_endpoint,
                                                                  NULL,
                                                                  flb_aws_client_generator());
            if (!oc->aws_provider) {
                flb_error("[out_es] Failed to create AWS Credential Provider");
                flb_os_conf_destroy(oc);
                return -1;
            }

            tmp = flb_output_get_property("aws_role_arn", ins);
            if (tmp) {
                /* Use the STS Provider */
                oc->base_aws_provider = oc->aws_provider;
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
                    flb_os_conf_destroy(oc);
                    return -1;
                }

                /* STS provider needs yet another separate TLS instance */
                oc->aws_sts_tls = flb_tls_create(FLB_TLS_CLIENT_MODE,
                                                 FLB_TRUE,
                                                 ins->tls_debug,
                                                 ins->tls_vhost,
                                                 ins->tls_ca_path,
                                                 ins->tls_ca_file,
                                                 ins->tls_crt_file,
                                                 ins->tls_key_file,
                                                 ins->tls_key_passwd);
                if (!oc->aws_sts_tls) {
                    flb_errno();
                    flb_os_conf_destroy(oc);
                    return -1;
                }

                oc->aws_provider = flb_sts_provider_create(config,
                                                           oc->aws_sts_tls,
                                                           oc->
                                                           base_aws_provider,
                                                           aws_external_id,
                                                           aws_role_arn,
                                                           aws_session_name,
                                                           oc->aws_region,
                                                           oc->aws_sts_endpoint,
                                                           NULL,
                                                           flb_aws_client_generator());
                /* Session name can be freed once provider is created */
                flb_free(aws_session_name);
                if (!oc->aws_provider) {
                    flb_error("[out_es] Failed to create AWS STS Credential "
                              "Provider");
                    flb_os_conf_destroy(oc);
                    return -1;
                }

            }

            /* initialize credentials in sync mode */
            oc->aws_provider->provider_vtable->sync(oc->aws_provider);
            oc->aws_provider->provider_vtable->init(oc->aws_provider);
            /* set back to async */
            oc->aws_provider->provider_vtable->async(oc->aws_provider);
            oc->aws_provider->provider_vtable->upstream_set(oc->aws_provider, ctx->ins);
        }
    }
#endif

  /* Initialize and validate os_config context */
  ret = flb_os_conf_init(oc, ctx);
  if (ret == -1) {
      if (oc) {
          flb_os_conf_destroy(oc);
      }
      return -1;
  }

    return 0;
}

/* Configure in HA mode */
int os_config_ha(const char *upstream_file,
                 struct flb_opensearch *ctx,
                 struct flb_config *config)
{
    ssize_t ret = 0;
    const char *tmp;
    const char *path;
    struct mk_list *head;
    struct flb_uri *uri = ctx->ins->host.uri;
    struct flb_uri_field *f_index = NULL;
    struct flb_uri_field *f_type = NULL;
    struct flb_upstream_node *node;
    struct flb_opensearch_config *oc = NULL;

    ctx->ha_mode = FLB_TRUE;
    ctx->ha = flb_upstream_ha_from_file(upstream_file, config);
    if (!ctx->ha) {
        flb_plg_error(ctx->ins, "cannot load Upstream file");
        return -1;
    }

    if (uri) {
        if (uri->count >= 2) {
            f_index = flb_uri_get(uri, 0);
            f_type  = flb_uri_get(uri, 1);
        }
    }

    /* Iterate nodes and create a flb_opensearch_config context */
    mk_list_foreach(head, &ctx->ha->nodes) {
        node = mk_list_entry(head, struct flb_upstream_node, _head);

        /* Allocate context */
        oc = flb_calloc(1, sizeof(struct flb_opensearch_config));
        if (!oc) {
            flb_errno();
            flb_plg_error(ctx->ins, "failed config allocation");
            continue;
        }

        /* Set manual Index and Type */
        if (f_index) {
            oc->index = flb_strdup(f_index->value); /* FIXME */
        }

        if (f_type) {
            oc->type = flb_strdup(f_type->value); /* FIXME */
        }

        /* Set default values */
        ret = flb_output_config_map_set(ctx->ins, oc);
        if (ret == -1) {
            flb_free(oc);
            return -1;
        }

        /* Opensearch: Path */
        path = flb_upstream_node_get_property("path", node);
        if (!path) {
            path = "";
        }

        /* Opensearch: Pipeline */
        tmp = flb_upstream_node_get_property("pipeline", node);
        if (tmp) {
            snprintf(oc->uri, sizeof(oc->uri) - 1, "%s/_bulk/?pipeline=%s", path, tmp);
        }
        else {
            snprintf(oc->uri, sizeof(oc->uri) - 1, "%s/_bulk", path);
        }

        if (oc->write_operation) {
          if (strcasecmp(oc->write_operation, FLB_OS_WRITE_OP_INDEX) == 0) {
              oc->action = flb_strdup(FLB_OS_WRITE_OP_INDEX);
          }
          else if (strcasecmp(oc->write_operation, FLB_OS_WRITE_OP_CREATE) == 0) {
              oc->action = flb_strdup(FLB_OS_WRITE_OP_CREATE);
          }
          else if (strcasecmp(oc->write_operation, FLB_OS_WRITE_OP_UPDATE) == 0
              || strcasecmp(oc->write_operation, FLB_OS_WRITE_OP_UPSERT) == 0) {
              oc->action = flb_strdup(FLB_OS_WRITE_OP_UPDATE);
          }
          else {
              flb_plg_error(ctx->ins, "wrong Write_Operation (should be one of index, create, update, upsert)");
              flb_os_conf_destroy(oc);
              return -1;
          }
          if (strcasecmp(oc->action, FLB_OS_WRITE_OP_UPDATE) == 0
              && !oc->ra_id_key && oc->generate_id == FLB_FALSE) {
              flb_plg_error(ctx->ins, "Id_Key or Generate_Id must be set when Write_Operation update or upsert");
              flb_os_conf_destroy(oc);
              return -1;
          }
        }

        /* Initialize and validate os_config context */
        ret = flb_os_conf_init(oc, ctx);
        if (ret == -1) {
            if (oc) {
                flb_os_conf_destroy(oc);
            }
            return -1;
        }

        /* Set our opensearch_config context into the node */
        flb_upstream_node_set_data(oc, node);
    }

    flb_output_upstream_ha_set(ctx->ha, ctx->ins);

    return 0;
}

int flb_os_conf_init(struct flb_opensearch_config *oc,
                     struct flb_opensearch *ctx)
{
    mk_list_add(&oc->_head, &ctx->configs);
    return 0;
}

int flb_os_conf_destroy(struct flb_opensearch_config *oc)
{
    if (!oc) {
        return 0;
    }

    if (oc->ra_id_key) {
        flb_ra_destroy(oc->ra_id_key);
        oc->ra_id_key = NULL;
    }

#ifdef FLB_HAVE_AWS
    if (oc->base_aws_provider) {
        flb_aws_provider_destroy(oc->base_aws_provider);
    }

    if (oc->aws_provider) {
        flb_aws_provider_destroy(oc->aws_provider);
    }

    if (oc->aws_tls) {
        flb_tls_destroy(oc->aws_tls);
    }

    if (oc->aws_sts_tls) {
        flb_tls_destroy(oc->aws_sts_tls);
    }
#endif

    if (oc->ra_prefix_key) {
        flb_ra_destroy(oc->ra_prefix_key);
    }

    if (oc->ra_index) {
        flb_ra_destroy(oc->ra_index);
    }

    flb_free(oc);

    return 0;
}
