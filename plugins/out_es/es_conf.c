/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
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
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_upstream_ha.h>
#include <fluent-bit/flb_signv4.h>
#include <fluent-bit/flb_aws_credentials.h>
#include <mbedtls/base64.h>

#include "es.h"
#include "es_conf.h"

/*
 * extract_cloud_host extracts the public hostname
 * of a deployment from a Cloud ID string.
 *
 * The Cloud ID string has the format "<deployment_name>:<base64_info>".
 * Once decoded, the "base64_info" string has the format "<deployment_region>$<elasticsearch_hostname>$<kibana_hostname>"
 * and the function returns "<elasticsearch_hostname>.<deployment_region>" token.
 */
static flb_sds_t extract_cloud_host(struct flb_elasticsearch *ctx,
                                    const char *cloud_id)
{

    char *colon;
    char *region;
    char *host;
    char buf[256] = {0};
    char cloud_host_buf[256] = {0};
    const char dollar[2] = "$";
    size_t len;
    int ret;

    /* keep only part after first ":" */
    colon = strchr(cloud_id, ':');
    if (colon == NULL) {
        return NULL;
    }
    colon++;

    /* decode base64 */
    ret = mbedtls_base64_decode((unsigned char *)buf, sizeof(buf), &len, (unsigned char *)colon, strlen(colon));
    if (ret) {
        flb_plg_error(ctx->ins, "cannot decode cloud_id");
        return NULL;
    }
    region = strtok(buf, dollar);
    if (region == NULL) {
        return NULL;
    }
    host = strtok(NULL, dollar);
    if (host == NULL) {
        return NULL;
    }
    strcpy(cloud_host_buf, host);
    strcat(cloud_host_buf, ".");
    strcat(cloud_host_buf, region);
    return flb_sds_create(cloud_host_buf);
}

/*
 * set_cloud_credentials gets a cloud_auth
 * and sets the context's cloud_user and cloud_passwd.
 * Example:
 *   cloud_auth = elastic:ZXVyb3BxxxxxxZTA1Ng
 *   ---->
 *   cloud_user = elastic
 *   cloud_passwd = ZXVyb3BxxxxxxZTA1Ng
 */
static void set_cloud_credentials(struct flb_elasticsearch_config *ec,
                                  const char *cloud_auth)
{
    /* extract strings */
    int items = 0;
    struct mk_list *toks;
    struct mk_list *head;
    struct flb_split_entry *entry;
    toks = flb_utils_split((const char *)cloud_auth, ':', -1);
    mk_list_foreach(head, toks) {
        items++;
        entry = mk_list_entry(head, struct flb_split_entry, _head);
        if (items == 1) {
          ec->cloud_user = flb_strdup(entry->value);
        }
        if (items == 2) {
          ec->cloud_passwd = flb_strdup(entry->value);
        }
    }
    flb_utils_split_free(toks);
}

int es_config_simple(struct flb_elasticsearch *ctx,
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
    char *cloud_host = NULL;
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

    if (uri) {
        if (uri->count >= 2) {
            f_index = flb_uri_get(uri, 0);
            f_type  = flb_uri_get(uri, 1);
        }
    }

    /* handle cloud_id */
    tmp = flb_output_get_property("cloud_id", ins);
    if (tmp) {
        cloud_host = extract_cloud_host(ctx, tmp);
        if (cloud_host == NULL) {
            flb_plg_error(ctx->ins, "cannot extract cloud_host");
            flb_es_conf_destroy(ec);
            return -1;
        }
        ins->host.name = cloud_host;
        ins->host.port = 443;
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

    /* handle cloud_auth */
    tmp = flb_output_get_property("cloud_auth", ins);
    if (tmp) {
        set_cloud_credentials(ec, tmp);
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


    if (ec->id_key) {
        ec->ra_id_key = flb_ra_create(ec->id_key, FLB_FALSE);
        if (ec->ra_id_key == NULL) {
            flb_plg_error(ins, "could not create record accessor for Id Key");
        }
        if (ec->generate_id == FLB_TRUE) {
            flb_plg_warn(ins, "Generate_ID is ignored when ID_key is set");
            ec->generate_id = FLB_FALSE;
        }
    }

    if (ec->logstash_prefix_key) {
        if (ec->logstash_prefix_key[0] != '$') {
            len = flb_sds_len(ec->logstash_prefix_key);
            buf = flb_malloc(len + 2);
            if (!buf) {
                flb_errno();
                flb_es_conf_destroy(ec);
                return -1;
            }
            buf[0] = '$';
            memcpy(buf + 1, ec->logstash_prefix_key, len);
            buf[len + 1] = '\0';

            ec->ra_prefix_key = flb_ra_create(buf, FLB_TRUE);
            flb_free(buf);
        }
        else {
            ec->ra_prefix_key = flb_ra_create(ec->logstash_prefix_key, FLB_TRUE);
        }

        if (!ec->ra_prefix_key) {
            flb_plg_error(ins, "invalid logstash_prefix_key pattern '%s'", tmp);
            flb_es_conf_destroy(ec);
            return -1;
        }
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
            ec->aws_tls = flb_tls_create(FLB_TRUE,
                                          ins->tls_debug,
                                          ins->tls_vhost,
                                          ins->tls_ca_path,
                                          ins->tls_ca_file,
                                          ins->tls_crt_file,
                                          ins->tls_key_file,
                                          ins->tls_key_passwd);
            if (!ec->aws_tls) {
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

            tmp = flb_output_get_property("aws_sts_endpoint", ins);
            if (tmp) {
                ec->aws_sts_endpoint = (char *) tmp;
            }

            ec->aws_provider = flb_standard_chain_provider_create(config,
                                                                  ec->aws_tls,
                                                                  ec->aws_region,
                                                                  ec->aws_sts_endpoint,
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
                ec->aws_sts_tls = flb_tls_create(FLB_TRUE,
                                                 ins->tls_debug,
                                                 ins->tls_vhost,
                                                 ins->tls_ca_path,
                                                 ins->tls_ca_file,
                                                 ins->tls_crt_file,
                                                 ins->tls_key_file,
                                                 ins->tls_key_passwd);
                if (!ec->aws_sts_tls) {
                    flb_errno();
                    flb_es_conf_destroy(ec);
                    return -1;
                }

                ec->aws_provider = flb_sts_provider_create(config,
                                                            ec->aws_sts_tls,
                                                            ec->
                                                            base_aws_provider,
                                                            aws_external_id,
                                                            aws_role_arn,
                                                            aws_session_name,
                                                            ec->aws_region,
                                                            ec->aws_sts_endpoint,
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
            /* SIRVIO NEED TO CHECK CALL BELOW */
            ec->aws_provider->provider_vtable->upstream_set(ec->aws_provider, ctx->ins);
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
    struct flb_uri *uri = ctx->ins->host.uri;
    struct flb_uri_field *f_index = NULL;
    struct flb_uri_field *f_type = NULL;
    struct flb_upstream_node *node;
    struct flb_elasticsearch_config *ec = NULL;

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

    /* Iterate nodes and create a forward_config context */
    mk_list_foreach(head, &ctx->ha->nodes) {
        node = mk_list_entry(head, struct flb_upstream_node, _head);

        /* Allocate context */
        ec = flb_calloc(1, sizeof(struct flb_elasticsearch_config));
        if (!ec) {
            flb_errno();
            flb_plg_error(ctx->ins, "failed config allocation");
            continue;
        }

        /* Set manual Index and Type */
        if (f_index) {
            ec->index = flb_strdup(f_index->value); /* FIXME */
        }

        if (f_type) {
            ec->type = flb_strdup(f_type->value); /* FIXME */
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
    if (ec->ra_id_key) {
        flb_ra_destroy(ec->ra_id_key);
        ec->ra_id_key = NULL;
    }

#ifdef FLB_HAVE_AWS
    if (ec->base_aws_provider) {
        flb_aws_provider_destroy(ec->base_aws_provider);
    }

    if (ec->aws_provider) {
        flb_aws_provider_destroy(ec->aws_provider);
    }

    if (ec->aws_tls) {
        flb_tls_destroy(ec->aws_tls);
    }

    if (ec->aws_sts_tls) {
        flb_tls_destroy(ec->aws_sts_tls);
    }
#endif

    if (ec->ra_prefix_key) {
        flb_ra_destroy(ec->ra_prefix_key);
    }

    flb_free(ec->cloud_passwd);
    flb_free(ec->cloud_user);
    flb_free(ec);

    return 0;
}

