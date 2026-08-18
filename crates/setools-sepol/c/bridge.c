/* SPDX-License-Identifier: LGPL-2.1-only */

#define _POSIX_C_SOURCE 200809L

#include "bridge.h"

#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include <selinux/selinux.h>
#include <sepol/debug.h>
#include <sepol/handle.h>
#include <sepol/policydb.h>
#include <sepol/policydb/conditional.h>
#include <sepol/policydb/policydb.h>

struct st_te_rule_entry {
    avtab_ptr_t node;
    uint32_t conditional;
    uint32_t conditional_block;
};

struct st_policy {
    sepol_policydb_t *policydb;
    struct st_te_rule_entry *te_rules;
    uint32_t te_rule_count;
    cond_node_t **conditionals;
    uint32_t conditional_count;
};

struct st_load_context {
    char *diagnostic;
};

static char *st_vformat(const char *format, va_list arguments)
{
    va_list copy;
    int length;
    char *message;

    va_copy(copy, arguments);
    length = vsnprintf(NULL, 0, format, copy);
    va_end(copy);
    if (length < 0) {
        return NULL;
    }

    message = malloc((size_t)length + 1U);
    if (message == NULL) {
        return NULL;
    }

    if (vsnprintf(message, (size_t)length + 1U, format, arguments) < 0) {
        free(message);
        return NULL;
    }

    return message;
}

static void st_error_set(st_error *error, st_status code,
                         const char *format, ...)
{
    va_list arguments;

    if (error == NULL) {
        return;
    }

    error->code = (int32_t)code;
    va_start(arguments, format);
    error->message = st_vformat(format, arguments);
    va_end(arguments);
}

static void st_sepol_message(void *opaque, sepol_handle_t *handle,
                             const char *format, ...)
{
    struct st_load_context *context = opaque;
    va_list arguments;

    if (context == NULL || context->diagnostic != NULL ||
        sepol_msg_get_level(handle) != SEPOL_MSG_ERR) {
        return;
    }

    va_start(arguments, format);
    context->diagnostic = st_vformat(format, arguments);
    va_end(arguments);
}

static st_string_view st_string(const char *value)
{
    st_string_view view;

    view.data = value;
    view.length = value != NULL ? strlen(value) : 0U;
    return view;
}

static int st_index_te_rules(st_policy *policy, st_error *error)
{
    const avtab_t *table = &policy->policydb->p.te_avtab;
    cond_node_t *conditional;
    cond_av_list_t *conditional_rule;
    avtab_ptr_t node;
    uint32_t bucket;
    uint32_t index = 0U;
    uint32_t conditional_index = 0U;
    uint64_t rule_count = table->nel;

    for (conditional = policy->policydb->p.cond_list;
         conditional != NULL; conditional = conditional->next) {
        policy->conditional_count++;
        for (conditional_rule = conditional->true_list;
             conditional_rule != NULL; conditional_rule = conditional_rule->next) {
            rule_count++;
        }
        for (conditional_rule = conditional->false_list;
             conditional_rule != NULL; conditional_rule = conditional_rule->next) {
            rule_count++;
        }
    }
    if (rule_count > UINT32_MAX) {
        st_error_set(error, ST_STATUS_INVALID_METADATA,
                     "policy contains too many TE rules");
        return ST_STATUS_INVALID_METADATA;
    }

    policy->te_rule_count = (uint32_t)rule_count;
    if (policy->conditional_count != 0U) {
        policy->conditionals = calloc(policy->conditional_count,
                                      sizeof(*policy->conditionals));
        if (policy->conditionals == NULL) {
            st_error_set(error, ST_STATUS_OUT_OF_MEMORY,
                         "could not allocate conditional index");
            return ST_STATUS_OUT_OF_MEMORY;
        }
    }
    if (policy->te_rule_count == 0U) {
        return ST_STATUS_OK;
    }

    policy->te_rules = calloc(policy->te_rule_count, sizeof(*policy->te_rules));
    if (policy->te_rules == NULL) {
        st_error_set(error, ST_STATUS_OUT_OF_MEMORY,
                     "could not allocate TE rule index");
        return ST_STATUS_OUT_OF_MEMORY;
    }

    for (bucket = 0U; bucket < table->nslot; bucket++) {
        for (node = table->htable[bucket]; node != NULL; node = node->next) {
            if (index >= policy->te_rule_count) {
                st_error_set(error, ST_STATUS_INVALID_METADATA,
                             "libsepol TE rule count changed while indexing");
                return ST_STATUS_INVALID_METADATA;
            }
            policy->te_rules[index].node = node;
            policy->te_rules[index].conditional = UINT32_MAX;
            index++;
        }
    }

    for (conditional = policy->policydb->p.cond_list;
         conditional != NULL; conditional = conditional->next) {
        policy->conditionals[conditional_index] = conditional;
        for (conditional_rule = conditional->true_list;
             conditional_rule != NULL; conditional_rule = conditional_rule->next) {
            policy->te_rules[index].node = conditional_rule->node;
            policy->te_rules[index].conditional = conditional_index;
            policy->te_rules[index].conditional_block = 1U;
            index++;
        }
        for (conditional_rule = conditional->false_list;
             conditional_rule != NULL; conditional_rule = conditional_rule->next) {
            policy->te_rules[index].node = conditional_rule->node;
            policy->te_rules[index].conditional = conditional_index;
            policy->te_rules[index].conditional_block = 0U;
            index++;
        }
        conditional_index++;
    }

    if (index != policy->te_rule_count) {
        st_error_set(error, ST_STATUS_INVALID_METADATA,
                     "libsepol TE rule table contains %u entries, expected %u",
                     index, policy->te_rule_count);
        return ST_STATUS_INVALID_METADATA;
    }

    return ST_STATUS_OK;
}

static const char *st_permission_name(const symtab_t *permissions,
                                      uint32_t value)
{
    hashtab_ptr_t node;
    uint32_t bucket;

    if (permissions == NULL || permissions->table == NULL) {
        return NULL;
    }

    for (bucket = 0U; bucket < permissions->table->size; bucket++) {
        for (node = permissions->table->htable[bucket]; node != NULL;
             node = node->next) {
            const perm_datum_t *datum = node->datum;
            if (datum != NULL && datum->s.value == value) {
                return node->key;
            }
        }
    }

    return NULL;
}

uint32_t st_bridge_abi_version(void)
{
    return ST_BRIDGE_ABI_VERSION;
}

int32_t st_running_policy_info_get(st_running_policy_info *info)
{
    const char *current_policy_path;
    const char *binary_policy_path;

    if (info == NULL) {
        return ST_STATUS_INVALID_ARGUMENT;
    }

    current_policy_path = selinux_current_policy_path();
    binary_policy_path = selinux_binary_policy_path();
    info->selinuxfs_exists = selinuxfs_exists() != 0;
    info->minimum_version = (uint32_t)sepol_policy_kern_vers_min();
    info->maximum_version = (uint32_t)sepol_policy_kern_vers_max();
    info->current_policy_path = st_string(current_policy_path);
    info->binary_policy_path = st_string(binary_policy_path);
    return ST_STATUS_OK;
}

int32_t st_local_log_timestamp(char *buffer, size_t capacity)
{
    struct timeval now;
    struct tm local;
    size_t length;
    int written;

    if (buffer == NULL || capacity == 0U) {
        return ST_STATUS_INVALID_ARGUMENT;
    }
    if (gettimeofday(&now, NULL) != 0 || localtime_r(&now.tv_sec, &local) == NULL) {
        return ST_STATUS_INVALID_METADATA;
    }
    length = strftime(buffer, capacity, "%Y-%m-%d %H:%M:%S", &local);
    if (length == 0U || length >= capacity) {
        return ST_STATUS_INVALID_ARGUMENT;
    }
    written = snprintf(buffer + length, capacity - length, ",%03ld",
                       now.tv_usec / 1000L);
    if (written != 4 || (size_t)written >= capacity - length) {
        return ST_STATUS_INVALID_ARGUMENT;
    }
    return ST_STATUS_OK;
}

int32_t st_process_use_default_sigpipe(void)
{
    return signal(SIGPIPE, SIG_DFL) == SIG_ERR ? -1 : 0;
}

st_policy *st_policy_load(const char *path, st_error *error)
{
    st_policy *policy = NULL;
    sepol_policy_file_t *policy_file = NULL;
    sepol_handle_t *handle = NULL;
    FILE *input = NULL;
    struct st_load_context context = { .diagnostic = NULL };
    int saved_errno;

    if (error != NULL) {
        error->code = ST_STATUS_OK;
        error->message = NULL;
    }

    if (path == NULL || path[0] == '\0') {
        st_error_set(error, ST_STATUS_INVALID_ARGUMENT,
                     "policy path must not be empty");
        return NULL;
    }

    policy = calloc(1U, sizeof(*policy));
    if (policy == NULL) {
        st_error_set(error, ST_STATUS_OUT_OF_MEMORY,
                     "could not allocate policy handle");
        goto fail;
    }

    handle = sepol_handle_create();
    if (handle == NULL || sepol_policydb_create(&policy->policydb) < 0 ||
        sepol_policy_file_create(&policy_file) < 0) {
        st_error_set(error, ST_STATUS_OUT_OF_MEMORY,
                     "libsepol policy allocation failed");
        goto fail;
    }

    sepol_msg_set_callback(handle, st_sepol_message, &context);

    input = fopen(path, "rb");
    if (input == NULL) {
        saved_errno = errno;
        st_error_set(error, ST_STATUS_OPEN_FAILED,
                     "could not open binary policy: %s", strerror(saved_errno));
        goto fail;
    }

    sepol_policy_file_set_handle(policy_file, handle);
    sepol_policy_file_set_fp(policy_file, input);
    if (sepol_policydb_read(policy->policydb, policy_file) < 0) {
        st_error_set(error, ST_STATUS_POLICY_READ_FAILED, "%s",
                     context.diagnostic != NULL
                         ? context.diagnostic
                         : "libsepol rejected the binary policy");
        goto fail;
    }

    if (st_index_te_rules(policy, error) != ST_STATUS_OK) {
        goto fail;
    }

    fclose(input);
    sepol_policy_file_free(policy_file);
    sepol_handle_destroy(handle);
    free(context.diagnostic);
    return policy;

fail:
    if (input != NULL) {
        fclose(input);
    }
    sepol_policy_file_free(policy_file);
    sepol_handle_destroy(handle);
    if (policy != NULL) {
        free(policy->te_rules);
        free(policy->conditionals);
        sepol_policydb_free(policy->policydb);
        free(policy);
    }
    free(context.diagnostic);
    return NULL;
}

void st_policy_free(st_policy *policy)
{
    if (policy == NULL) {
        return;
    }

    free(policy->te_rules);
    free(policy->conditionals);
    sepol_policydb_free(policy->policydb);
    free(policy);
}

int32_t st_policy_metadata_get(const st_policy *policy,
                               st_policy_metadata *metadata,
                               st_error *error)
{
    const struct policydb *policydb;

    if (error != NULL) {
        error->code = ST_STATUS_OK;
        error->message = NULL;
    }

    if (policy == NULL || policy->policydb == NULL || metadata == NULL) {
        st_error_set(error, ST_STATUS_INVALID_ARGUMENT,
                     "policy and metadata pointers must not be null");
        return ST_STATUS_INVALID_ARGUMENT;
    }

    policydb = &policy->policydb->p;
    metadata->version = policydb->policyvers;
    metadata->mls = policydb->mls != 0 ? 1U : 0U;
    metadata->target_platform = (uint32_t)policydb->target_platform;
    metadata->handle_unknown = policydb->handle_unknown;
    return ST_STATUS_OK;
}

uint32_t st_policy_type_count(const st_policy *policy)
{
    if (policy == NULL || policy->policydb == NULL) {
        return 0U;
    }
    return policy->policydb->p.p_types.nprim;
}

int32_t st_policy_type_get(const st_policy *policy, uint32_t index,
                           st_type_view *type, st_error *error)
{
    const policydb_t *policydb;
    const type_datum_t *datum;
    const char *name;

    if (error != NULL) {
        error->code = ST_STATUS_OK;
        error->message = NULL;
    }
    if (policy == NULL || policy->policydb == NULL || type == NULL) {
        st_error_set(error, ST_STATUS_INVALID_ARGUMENT,
                     "policy and type pointers must not be null");
        return ST_STATUS_INVALID_ARGUMENT;
    }

    policydb = &policy->policydb->p;
    if (index >= policydb->p_types.nprim ||
        policydb->type_val_to_struct[index] == NULL) {
        st_error_set(error, ST_STATUS_INVALID_METADATA,
                     "type index %u is not present", index);
        return ST_STATUS_INVALID_METADATA;
    }

    datum = policydb->type_val_to_struct[index];
    if (datum->flavor != TYPE_TYPE && datum->flavor != TYPE_ATTRIB) {
        st_error_set(error, ST_STATUS_INVALID_METADATA,
                     "type index %u has unsupported flavor %u", index,
                     datum->flavor);
        return ST_STATUS_INVALID_METADATA;
    }

    name = policydb->p_type_val_to_name[index];
    if (datum->flavor == TYPE_TYPE && name == NULL) {
        st_error_set(error, ST_STATUS_INVALID_METADATA,
                     "type index %u has no primary name", index);
        return ST_STATUS_INVALID_METADATA;
    }

    type->kind = datum->flavor == TYPE_ATTRIB ? ST_TYPE_ATTRIBUTE : ST_TYPE;
    type->name = st_string(name);
    return ST_STATUS_OK;
}

static int st_type_is_alias(const type_datum_t *datum)
{
    return (datum->primary == 0U && datum->flavor == TYPE_TYPE) ||
           datum->flavor == TYPE_ALIAS;
}

uint32_t st_policy_type_alias_count(const st_policy *policy, uint32_t type)
{
    const hashtab_t table = policy != NULL && policy->policydb != NULL
                                ? policy->policydb->p.p_types.table
                                : NULL;
    hashtab_ptr_t node;
    uint32_t bucket;
    uint32_t count = 0U;

    if (table == NULL) {
        return 0U;
    }
    for (bucket = 0U; bucket < table->size; bucket++) {
        for (node = table->htable[bucket]; node != NULL; node = node->next) {
            const type_datum_t *datum = node->datum;
            if (datum != NULL && st_type_is_alias(datum) &&
                datum->s.value == type + 1U) {
                count++;
            }
        }
    }
    return count;
}

int32_t st_policy_type_alias_get(const st_policy *policy, uint32_t type,
                                 uint32_t index, st_string_view *name,
                                 st_error *error)
{
    const hashtab_t table = policy != NULL && policy->policydb != NULL
                                ? policy->policydb->p.p_types.table
                                : NULL;
    hashtab_ptr_t node;
    uint32_t bucket;
    uint32_t current = 0U;

    if (error != NULL) {
        error->code = ST_STATUS_OK;
        error->message = NULL;
    }
    if (policy == NULL || policy->policydb == NULL || name == NULL) {
        st_error_set(error, ST_STATUS_INVALID_ARGUMENT,
                     "policy and type alias pointers must not be null");
        return ST_STATUS_INVALID_ARGUMENT;
    }
    if (table != NULL) {
        for (bucket = 0U; bucket < table->size; bucket++) {
            for (node = table->htable[bucket]; node != NULL; node = node->next) {
                const type_datum_t *datum = node->datum;
                if (datum != NULL && st_type_is_alias(datum) &&
                    datum->s.value == type + 1U && current++ == index) {
                    *name = st_string(node->key);
                    return ST_STATUS_OK;
                }
            }
        }
    }
    st_error_set(error, ST_STATUS_INVALID_METADATA,
                 "type %u alias index %u is not present", type, index);
    return ST_STATUS_INVALID_METADATA;
}

int32_t st_policy_attribute_members_get(const st_policy *policy,
                                        uint32_t attribute,
                                        uint32_t *members,
                                        size_t capacity,
                                        size_t *count,
                                        st_error *error)
{
    const policydb_t *policydb;
    const ebitmap_t *membership;
    ebitmap_node_t *node;
    unsigned int bit;
    size_t required;
    size_t written = 0U;

    if (error != NULL) {
        error->code = ST_STATUS_OK;
        error->message = NULL;
    }
    if (policy == NULL || policy->policydb == NULL || count == NULL) {
        st_error_set(error, ST_STATUS_INVALID_ARGUMENT,
                     "policy and count pointers must not be null");
        return ST_STATUS_INVALID_ARGUMENT;
    }

    policydb = &policy->policydb->p;
    if (attribute >= policydb->p_types.nprim ||
        policydb->type_val_to_struct[attribute] == NULL ||
        policydb->type_val_to_struct[attribute]->flavor != TYPE_ATTRIB ||
        policydb->attr_type_map == NULL) {
        st_error_set(error, ST_STATUS_INVALID_METADATA,
                     "type index %u is not an attribute", attribute);
        return ST_STATUS_INVALID_METADATA;
    }

    membership = &policydb->attr_type_map[attribute];
    required = 0U;
    ebitmap_for_each_positive_bit(membership, node, bit) {
        required++;
    }
    *count = required;
    if (members == NULL) {
        return ST_STATUS_OK;
    }
    if (capacity < required) {
        st_error_set(error, ST_STATUS_INVALID_ARGUMENT,
                     "attribute member buffer has capacity %zu, needs %zu",
                     capacity, required);
        return ST_STATUS_INVALID_ARGUMENT;
    }

    ebitmap_for_each_positive_bit(membership, node, bit) {
        if (bit >= policydb->p_types.nprim ||
            policydb->type_val_to_struct[bit] == NULL ||
            policydb->type_val_to_struct[bit]->flavor != TYPE_TYPE) {
            st_error_set(error, ST_STATUS_INVALID_METADATA,
                         "attribute %u contains invalid type index %u",
                         attribute, bit);
            return ST_STATUS_INVALID_METADATA;
        }
        members[written++] = bit;
    }

    if (written != required) {
        st_error_set(error, ST_STATUS_INVALID_METADATA,
                     "attribute %u member count changed while copying",
                     attribute);
        return ST_STATUS_INVALID_METADATA;
    }
    return ST_STATUS_OK;
}

uint32_t st_policy_class_count(const st_policy *policy)
{
    if (policy == NULL || policy->policydb == NULL) {
        return 0U;
    }
    return policy->policydb->p.p_classes.nprim;
}

int32_t st_policy_class_get(const st_policy *policy, uint32_t index,
                            st_class_view *target_class, st_error *error)
{
    const policydb_t *policydb;
    const class_datum_t *datum;
    const char *name;

    if (error != NULL) {
        error->code = ST_STATUS_OK;
        error->message = NULL;
    }
    if (policy == NULL || policy->policydb == NULL || target_class == NULL) {
        st_error_set(error, ST_STATUS_INVALID_ARGUMENT,
                     "policy and class pointers must not be null");
        return ST_STATUS_INVALID_ARGUMENT;
    }

    policydb = &policy->policydb->p;
    if (index >= policydb->p_classes.nprim ||
        policydb->class_val_to_struct[index] == NULL) {
        st_error_set(error, ST_STATUS_INVALID_METADATA,
                     "class index %u is not present", index);
        return ST_STATUS_INVALID_METADATA;
    }

    datum = policydb->class_val_to_struct[index];
    name = policydb->p_class_val_to_name[index];
    if (name == NULL) {
        st_error_set(error, ST_STATUS_INVALID_METADATA,
                     "class index %u has no name", index);
        return ST_STATUS_INVALID_METADATA;
    }

    target_class->name = st_string(name);
    target_class->permission_count = datum->permissions.nprim;
    return ST_STATUS_OK;
}

int32_t st_policy_permission_get(const st_policy *policy,
                                 uint32_t target_class,
                                 uint32_t permission,
                                 st_string_view *name,
                                 st_error *error)
{
    const policydb_t *policydb;
    const class_datum_t *class_datum;
    const char *permission_name;

    if (error != NULL) {
        error->code = ST_STATUS_OK;
        error->message = NULL;
    }
    if (policy == NULL || policy->policydb == NULL || name == NULL) {
        st_error_set(error, ST_STATUS_INVALID_ARGUMENT,
                     "policy and permission pointers must not be null");
        return ST_STATUS_INVALID_ARGUMENT;
    }

    policydb = &policy->policydb->p;
    if (target_class >= policydb->p_classes.nprim ||
        policydb->class_val_to_struct[target_class] == NULL) {
        st_error_set(error, ST_STATUS_INVALID_METADATA,
                     "class index %u is not present", target_class);
        return ST_STATUS_INVALID_METADATA;
    }

    class_datum = policydb->class_val_to_struct[target_class];
    if (permission >= class_datum->permissions.nprim) {
        st_error_set(error, ST_STATUS_INVALID_METADATA,
                     "permission index %u is out of range for class %u",
                     permission, target_class);
        return ST_STATUS_INVALID_METADATA;
    }

    permission_name = st_permission_name(&class_datum->permissions,
                                         permission + 1U);
    if (permission_name == NULL && class_datum->comdatum != NULL) {
        permission_name = st_permission_name(&class_datum->comdatum->permissions,
                                             permission + 1U);
    }
    if (permission_name == NULL) {
        st_error_set(error, ST_STATUS_INVALID_METADATA,
                     "permission index %u has no name for class %u",
                     permission, target_class);
        return ST_STATUS_INVALID_METADATA;
    }

    *name = st_string(permission_name);
    return ST_STATUS_OK;
}

uint32_t st_policy_te_rule_count(const st_policy *policy)
{
    return policy != NULL ? policy->te_rule_count : 0U;
}

int32_t st_policy_te_rule_get(const st_policy *policy, uint32_t index,
                              st_te_rule_view *rule, st_error *error)
{
    const struct st_te_rule_entry *entry =
        policy != NULL && index < policy->te_rule_count
            ? &policy->te_rules[index]
            : NULL;
    const avtab_ptr_t node = entry != NULL ? entry->node : NULL;
    const avtab_key_t *key;
    const avtab_datum_t *datum;

    if (error != NULL) {
        error->code = ST_STATUS_OK;
        error->message = NULL;
    }
    if (policy == NULL || policy->policydb == NULL || rule == NULL) {
        st_error_set(error, ST_STATUS_INVALID_ARGUMENT,
                     "policy and rule pointers must not be null");
        return ST_STATUS_INVALID_ARGUMENT;
    }
    if (node == NULL) {
        st_error_set(error, ST_STATUS_INVALID_METADATA,
                     "TE rule index %u is not present", index);
        return ST_STATUS_INVALID_METADATA;
    }

    key = &node->key;
    datum = &node->datum;
    if (key->source_type == 0U || key->target_type == 0U ||
        key->target_class == 0U) {
        st_error_set(error, ST_STATUS_INVALID_METADATA,
                     "TE rule index %u contains a zero symbol value", index);
        return ST_STATUS_INVALID_METADATA;
    }

    memset(rule, 0, sizeof(*rule));
    rule->kind = key->specified & ~AVTAB_ENABLED;
    rule->source = key->source_type - 1U;
    rule->target = key->target_type - 1U;
    rule->target_class = key->target_class - 1U;
    rule->default_type = UINT32_MAX;
    rule->conditional = entry->conditional;
    rule->conditional_block = entry->conditional_block;

    if ((rule->kind & AVTAB_AV) != 0U) {
        rule->permissions = rule->kind == AVTAB_AUDITDENY
                                ? ~datum->data
                                : datum->data;
    } else if ((rule->kind & AVTAB_TYPE) != 0U) {
        if (datum->data == 0U) {
            st_error_set(error, ST_STATUS_INVALID_METADATA,
                         "TE rule index %u has a zero default type", index);
            return ST_STATUS_INVALID_METADATA;
        }
        rule->default_type = datum->data - 1U;
    } else if ((rule->kind & AVTAB_XPERMS) != 0U) {
        if (datum->xperms == NULL) {
            st_error_set(error, ST_STATUS_INVALID_METADATA,
                         "TE rule index %u has no extended permissions", index);
            return ST_STATUS_INVALID_METADATA;
        }
        rule->xperm_kind = datum->xperms->specified;
        rule->xperm_driver = datum->xperms->driver;
        memcpy(rule->xperms, datum->xperms->perms, sizeof(rule->xperms));
    } else {
        st_error_set(error, ST_STATUS_INVALID_METADATA,
                     "TE rule index %u has unsupported kind %#x", index,
                     rule->kind);
        return ST_STATUS_INVALID_METADATA;
    }

    return ST_STATUS_OK;
}

uint32_t st_policy_boolean_count(const st_policy *policy)
{
    if (policy == NULL || policy->policydb == NULL) {
        return 0U;
    }
    return policy->policydb->p.p_bools.nprim;
}

int32_t st_policy_boolean_get(const st_policy *policy, uint32_t index,
                              st_boolean_view *boolean, st_error *error)
{
    const policydb_t *policydb;
    const cond_bool_datum_t *datum;
    const char *name;

    if (error != NULL) {
        error->code = ST_STATUS_OK;
        error->message = NULL;
    }
    if (policy == NULL || policy->policydb == NULL || boolean == NULL) {
        st_error_set(error, ST_STATUS_INVALID_ARGUMENT,
                     "policy and Boolean pointers must not be null");
        return ST_STATUS_INVALID_ARGUMENT;
    }

    policydb = &policy->policydb->p;
    if (index >= policydb->p_bools.nprim ||
        policydb->bool_val_to_struct[index] == NULL) {
        st_error_set(error, ST_STATUS_INVALID_METADATA,
                     "Boolean index %u is not present", index);
        return ST_STATUS_INVALID_METADATA;
    }
    datum = policydb->bool_val_to_struct[index];
    name = policydb->p_bool_val_to_name[index];
    if (name == NULL) {
        st_error_set(error, ST_STATUS_INVALID_METADATA,
                     "Boolean index %u has no name", index);
        return ST_STATUS_INVALID_METADATA;
    }

    boolean->name = st_string(name);
    boolean->state = datum->state != 0 ? 1U : 0U;
    return ST_STATUS_OK;
}

uint32_t st_policy_conditional_count(const st_policy *policy)
{
    return policy != NULL ? policy->conditional_count : 0U;
}

uint32_t st_policy_conditional_token_count(const st_policy *policy,
                                           uint32_t conditional)
{
    const cond_expr_t *token;
    uint32_t count = 0U;

    if (policy == NULL || conditional >= policy->conditional_count) {
        return 0U;
    }
    for (token = policy->conditionals[conditional]->expr;
         token != NULL; token = token->next) {
        count++;
    }
    return count;
}

int32_t st_policy_conditional_token_get(const st_policy *policy,
                                        uint32_t conditional,
                                        uint32_t index,
                                        st_conditional_token_view *token,
                                        st_error *error)
{
    const cond_expr_t *expression;
    uint32_t current = 0U;

    if (error != NULL) {
        error->code = ST_STATUS_OK;
        error->message = NULL;
    }
    if (policy == NULL || policy->policydb == NULL || token == NULL) {
        st_error_set(error, ST_STATUS_INVALID_ARGUMENT,
                     "policy and conditional token pointers must not be null");
        return ST_STATUS_INVALID_ARGUMENT;
    }
    if (conditional >= policy->conditional_count) {
        st_error_set(error, ST_STATUS_INVALID_METADATA,
                     "conditional index %u is not present", conditional);
        return ST_STATUS_INVALID_METADATA;
    }

    expression = policy->conditionals[conditional]->expr;
    while (expression != NULL && current < index) {
        expression = expression->next;
        current++;
    }
    if (expression == NULL || expression->expr_type < COND_BOOL ||
        expression->expr_type > COND_NEQ) {
        st_error_set(error, ST_STATUS_INVALID_METADATA,
                     "conditional %u token %u is not present", conditional,
                     index);
        return ST_STATUS_INVALID_METADATA;
    }

    token->kind = expression->expr_type;
    token->boolean = UINT32_MAX;
    if (expression->expr_type == COND_BOOL) {
        if (expression->boolean == 0U ||
            expression->boolean > policy->policydb->p.p_bools.nprim) {
            st_error_set(error, ST_STATUS_INVALID_METADATA,
                         "conditional %u token %u has invalid Boolean value %u",
                         conditional, index, expression->boolean);
            return ST_STATUS_INVALID_METADATA;
        }
        token->boolean = expression->boolean - 1U;
    }
    return ST_STATUS_OK;
}

uint32_t st_policy_role_count(const st_policy *policy)
{
    if (policy == NULL || policy->policydb == NULL) {
        return 0U;
    }
    return policy->policydb->p.p_roles.nprim;
}

int32_t st_policy_role_get(const st_policy *policy, uint32_t index,
                           st_role_view *role, st_error *error)
{
    const policydb_t *policydb;
    const char *name;

    if (error != NULL) {
        error->code = ST_STATUS_OK;
        error->message = NULL;
    }
    if (policy == NULL || policy->policydb == NULL || role == NULL) {
        st_error_set(error, ST_STATUS_INVALID_ARGUMENT,
                     "policy and role pointers must not be null");
        return ST_STATUS_INVALID_ARGUMENT;
    }
    policydb = &policy->policydb->p;
    if (index >= policydb->p_roles.nprim ||
        policydb->role_val_to_struct[index] == NULL) {
        st_error_set(error, ST_STATUS_INVALID_METADATA,
                     "role index %u is not present", index);
        return ST_STATUS_INVALID_METADATA;
    }
    name = policydb->p_role_val_to_name[index];
    if (name == NULL) {
        st_error_set(error, ST_STATUS_INVALID_METADATA,
                     "role index %u has no name", index);
        return ST_STATUS_INVALID_METADATA;
    }
    role->name = st_string(name);
    return ST_STATUS_OK;
}

static int32_t st_bitmap_copy(const ebitmap_t *bitmap, uint32_t limit,
                              uint32_t *values, size_t capacity,
                              size_t *count, const char *description,
                              st_error *error)
{
    ebitmap_node_t *node;
    unsigned int bit;
    size_t required = 0U;
    size_t written = 0U;

    ebitmap_for_each_positive_bit(bitmap, node, bit) {
        if (bit >= limit) {
            st_error_set(error, ST_STATUS_INVALID_METADATA,
                         "%s contains out-of-range index %u", description,
                         bit);
            return ST_STATUS_INVALID_METADATA;
        }
        required++;
    }
    *count = required;
    if (values == NULL) {
        return ST_STATUS_OK;
    }
    if (capacity < required) {
        st_error_set(error, ST_STATUS_INVALID_ARGUMENT,
                     "%s buffer has capacity %zu, needs %zu", description,
                     capacity, required);
        return ST_STATUS_INVALID_ARGUMENT;
    }
    ebitmap_for_each_positive_bit(bitmap, node, bit) {
        values[written++] = bit;
    }
    return ST_STATUS_OK;
}

int32_t st_policy_role_members_get(const st_policy *policy, uint32_t role,
                                   uint32_t *members, size_t capacity,
                                   size_t *count, st_error *error)
{
    const policydb_t *policydb;

    if (error != NULL) {
        error->code = ST_STATUS_OK;
        error->message = NULL;
    }
    if (policy == NULL || policy->policydb == NULL || count == NULL) {
        st_error_set(error, ST_STATUS_INVALID_ARGUMENT,
                     "policy and count pointers must not be null");
        return ST_STATUS_INVALID_ARGUMENT;
    }
    policydb = &policy->policydb->p;
    if (role >= policydb->p_roles.nprim ||
        policydb->role_val_to_struct[role] == NULL) {
        st_error_set(error, ST_STATUS_INVALID_METADATA,
                     "role index %u is not present", role);
        return ST_STATUS_INVALID_METADATA;
    }
    return st_bitmap_copy(&policydb->role_val_to_struct[role]->roles,
                          policydb->p_roles.nprim, members, capacity, count,
                          "role membership", error);
}

uint32_t st_policy_rbac_rule_count(const st_policy *policy)
{
    const role_allow_t *allow;
    const role_trans_t *transition;
    uint32_t count = 0U;

    if (policy == NULL || policy->policydb == NULL) {
        return 0U;
    }
    for (allow = policy->policydb->p.role_allow; allow != NULL;
         allow = allow->next) {
        count++;
    }
    for (transition = policy->policydb->p.role_tr; transition != NULL;
         transition = transition->next) {
        count++;
    }
    return count;
}

int32_t st_policy_rbac_rule_get(const st_policy *policy, uint32_t index,
                                st_rbac_rule_view *rule, st_error *error)
{
    const role_allow_t *allow;
    const role_trans_t *transition;
    uint32_t current = 0U;

    if (error != NULL) {
        error->code = ST_STATUS_OK;
        error->message = NULL;
    }
    if (policy == NULL || policy->policydb == NULL || rule == NULL) {
        st_error_set(error, ST_STATUS_INVALID_ARGUMENT,
                     "policy and RBAC rule pointers must not be null");
        return ST_STATUS_INVALID_ARGUMENT;
    }
    memset(rule, 0, sizeof(*rule));
    rule->target_class = UINT32_MAX;
    rule->default_role = UINT32_MAX;
    for (allow = policy->policydb->p.role_allow; allow != NULL;
         allow = allow->next, current++) {
        if (current == index) {
            if (allow->role == 0U || allow->new_role == 0U) {
                break;
            }
            rule->kind = 1U;
            rule->source = allow->role - 1U;
            rule->target = allow->new_role - 1U;
            return ST_STATUS_OK;
        }
    }
    for (transition = policy->policydb->p.role_tr; transition != NULL;
         transition = transition->next, current++) {
        if (current == index) {
            if (transition->role == 0U || transition->type == 0U ||
                transition->tclass == 0U || transition->new_role == 0U) {
                break;
            }
            rule->kind = 2U;
            rule->source = transition->role - 1U;
            rule->target = transition->type - 1U;
            rule->target_class = transition->tclass - 1U;
            rule->default_role = transition->new_role - 1U;
            return ST_STATUS_OK;
        }
    }
    st_error_set(error, ST_STATUS_INVALID_METADATA,
                 "RBAC rule index %u is not present", index);
    return ST_STATUS_INVALID_METADATA;
}

uint32_t st_policy_filename_rule_count(const st_policy *policy)
{
    const hashtab_t table = policy != NULL && policy->policydb != NULL
                                ? policy->policydb->p.filename_trans
                                : NULL;
    const filename_trans_datum_t *datum;
    hashtab_ptr_t node;
    ebitmap_node_t *bitmap_node;
    unsigned int bit;
    uint32_t bucket;
    uint32_t count = 0U;

    if (table == NULL) {
        return 0U;
    }
    for (bucket = 0U; bucket < table->size; bucket++) {
        for (node = table->htable[bucket]; node != NULL; node = node->next) {
            for (datum = node->datum; datum != NULL; datum = datum->next) {
                ebitmap_for_each_positive_bit(&datum->stypes, bitmap_node, bit) {
                    count++;
                }
            }
        }
    }
    return count;
}

int32_t st_policy_filename_rule_get(const st_policy *policy, uint32_t index,
                                    st_filename_rule_view *rule,
                                    st_error *error)
{
    const hashtab_t table = policy != NULL && policy->policydb != NULL
                                ? policy->policydb->p.filename_trans
                                : NULL;
    const filename_trans_key_t *key;
    const filename_trans_datum_t *datum;
    hashtab_ptr_t node;
    ebitmap_node_t *bitmap_node;
    unsigned int bit;
    uint32_t bucket;
    uint32_t current = 0U;

    if (error != NULL) {
        error->code = ST_STATUS_OK;
        error->message = NULL;
    }
    if (policy == NULL || policy->policydb == NULL || rule == NULL) {
        st_error_set(error, ST_STATUS_INVALID_ARGUMENT,
                     "policy and filename rule pointers must not be null");
        return ST_STATUS_INVALID_ARGUMENT;
    }
    if (table != NULL) {
        for (bucket = 0U; bucket < table->size; bucket++) {
            for (node = table->htable[bucket]; node != NULL; node = node->next) {
                key = (const filename_trans_key_t *)node->key;
                for (datum = node->datum; datum != NULL; datum = datum->next) {
                    ebitmap_for_each_positive_bit(&datum->stypes, bitmap_node, bit) {
                        if (current++ != index) {
                            continue;
                        }
                        if (key == NULL || key->ttype == 0U ||
                            key->tclass == 0U || key->name == NULL ||
                            datum->otype == 0U) {
                            break;
                        }
                        rule->source = bit;
                        rule->target = key->ttype - 1U;
                        rule->target_class = key->tclass - 1U;
                        rule->default_type = datum->otype - 1U;
                        rule->filename = st_string(key->name);
                        return ST_STATUS_OK;
                    }
                }
            }
        }
    }
    st_error_set(error, ST_STATUS_INVALID_METADATA,
                 "filename transition index %u is not present", index);
    return ST_STATUS_INVALID_METADATA;
}

uint32_t st_policy_sensitivity_count(const st_policy *policy)
{
    const policydb_t *policydb;
    uint32_t count = 0U;

    if (policy == NULL || policy->policydb == NULL) {
        return 0U;
    }
    policydb = &policy->policydb->p;
    while (count < policydb->p_levels.nprim &&
           policydb->p_sens_val_to_name[count] != NULL) {
        count++;
    }
    return count;
}

int32_t st_policy_sensitivity_get(const st_policy *policy, uint32_t index,
                                  st_string_view *name, st_error *error)
{
    const policydb_t *policydb;

    if (error != NULL) {
        error->code = ST_STATUS_OK;
        error->message = NULL;
    }
    if (policy == NULL || policy->policydb == NULL || name == NULL) {
        st_error_set(error, ST_STATUS_INVALID_ARGUMENT,
                     "policy and sensitivity pointers must not be null");
        return ST_STATUS_INVALID_ARGUMENT;
    }
    policydb = &policy->policydb->p;
    if (index >= policydb->p_levels.nprim ||
        policydb->p_sens_val_to_name[index] == NULL) {
        st_error_set(error, ST_STATUS_INVALID_METADATA,
                     "sensitivity index %u is not present", index);
        return ST_STATUS_INVALID_METADATA;
    }
    *name = st_string(policydb->p_sens_val_to_name[index]);
    return ST_STATUS_OK;
}

uint32_t st_policy_sensitivity_alias_count(const st_policy *policy,
                                           uint32_t sensitivity)
{
    const hashtab_t table = policy != NULL && policy->policydb != NULL
                                ? policy->policydb->p.p_levels.table
                                : NULL;
    hashtab_ptr_t node;
    uint32_t bucket;
    uint32_t count = 0U;

    if (table == NULL) {
        return 0U;
    }
    for (bucket = 0U; bucket < table->size; bucket++) {
        for (node = table->htable[bucket]; node != NULL; node = node->next) {
            const level_datum_t *datum = node->datum;
            if (datum != NULL && datum->isalias && datum->level != NULL &&
                datum->level->sens == sensitivity + 1U) {
                count++;
            }
        }
    }
    return count;
}

int32_t st_policy_sensitivity_alias_get(const st_policy *policy,
                                        uint32_t sensitivity, uint32_t index,
                                        st_string_view *name, st_error *error)
{
    const hashtab_t table = policy != NULL && policy->policydb != NULL
                                ? policy->policydb->p.p_levels.table
                                : NULL;
    hashtab_ptr_t node;
    uint32_t bucket;
    uint32_t current = 0U;

    if (error != NULL) {
        error->code = ST_STATUS_OK;
        error->message = NULL;
    }
    if (policy == NULL || policy->policydb == NULL || name == NULL) {
        st_error_set(error, ST_STATUS_INVALID_ARGUMENT,
                     "policy and sensitivity alias pointers must not be null");
        return ST_STATUS_INVALID_ARGUMENT;
    }
    if (table != NULL) {
        for (bucket = 0U; bucket < table->size; bucket++) {
            for (node = table->htable[bucket]; node != NULL; node = node->next) {
                const level_datum_t *datum = node->datum;
                if (datum != NULL && datum->isalias && datum->level != NULL &&
                    datum->level->sens == sensitivity + 1U && current++ == index) {
                    *name = st_string(node->key);
                    return ST_STATUS_OK;
                }
            }
        }
    }
    st_error_set(error, ST_STATUS_INVALID_METADATA,
                 "sensitivity %u alias index %u is not present", sensitivity,
                 index);
    return ST_STATUS_INVALID_METADATA;
}

uint32_t st_policy_category_count(const st_policy *policy)
{
    const policydb_t *policydb;
    uint32_t count = 0U;

    if (policy == NULL || policy->policydb == NULL) {
        return 0U;
    }
    policydb = &policy->policydb->p;
    while (count < policydb->p_cats.nprim &&
           policydb->p_cat_val_to_name[count] != NULL) {
        count++;
    }
    return count;
}

int32_t st_policy_category_get(const st_policy *policy, uint32_t index,
                               st_string_view *name, st_error *error)
{
    const policydb_t *policydb;

    if (error != NULL) {
        error->code = ST_STATUS_OK;
        error->message = NULL;
    }
    if (policy == NULL || policy->policydb == NULL || name == NULL) {
        st_error_set(error, ST_STATUS_INVALID_ARGUMENT,
                     "policy and category pointers must not be null");
        return ST_STATUS_INVALID_ARGUMENT;
    }
    policydb = &policy->policydb->p;
    if (index >= policydb->p_cats.nprim ||
        policydb->p_cat_val_to_name[index] == NULL) {
        st_error_set(error, ST_STATUS_INVALID_METADATA,
                     "category index %u is not present", index);
        return ST_STATUS_INVALID_METADATA;
    }
    *name = st_string(policydb->p_cat_val_to_name[index]);
    return ST_STATUS_OK;
}

uint32_t st_policy_category_alias_count(const st_policy *policy,
                                        uint32_t category)
{
    const hashtab_t table = policy != NULL && policy->policydb != NULL
                                ? policy->policydb->p.p_cats.table
                                : NULL;
    hashtab_ptr_t node;
    uint32_t bucket;
    uint32_t count = 0U;

    if (table == NULL) {
        return 0U;
    }
    for (bucket = 0U; bucket < table->size; bucket++) {
        for (node = table->htable[bucket]; node != NULL; node = node->next) {
            const cat_datum_t *datum = node->datum;
            if (datum != NULL && datum->isalias &&
                datum->s.value == category + 1U) {
                count++;
            }
        }
    }
    return count;
}

int32_t st_policy_category_alias_get(const st_policy *policy,
                                     uint32_t category, uint32_t index,
                                     st_string_view *name, st_error *error)
{
    const hashtab_t table = policy != NULL && policy->policydb != NULL
                                ? policy->policydb->p.p_cats.table
                                : NULL;
    hashtab_ptr_t node;
    uint32_t bucket;
    uint32_t current = 0U;

    if (error != NULL) {
        error->code = ST_STATUS_OK;
        error->message = NULL;
    }
    if (policy == NULL || policy->policydb == NULL || name == NULL) {
        st_error_set(error, ST_STATUS_INVALID_ARGUMENT,
                     "policy and category alias pointers must not be null");
        return ST_STATUS_INVALID_ARGUMENT;
    }
    if (table != NULL) {
        for (bucket = 0U; bucket < table->size; bucket++) {
            for (node = table->htable[bucket]; node != NULL; node = node->next) {
                const cat_datum_t *datum = node->datum;
                if (datum != NULL && datum->isalias &&
                    datum->s.value == category + 1U && current++ == index) {
                    *name = st_string(node->key);
                    return ST_STATUS_OK;
                }
            }
        }
    }
    st_error_set(error, ST_STATUS_INVALID_METADATA,
                 "category %u alias index %u is not present", category, index);
    return ST_STATUS_INVALID_METADATA;
}

uint32_t st_policy_mls_rule_count(const st_policy *policy)
{
    const hashtab_t table = policy != NULL && policy->policydb != NULL
                                ? policy->policydb->p.range_tr
                                : NULL;
    return table != NULL ? table->nel : 0U;
}

static int32_t st_mls_rule_find(const st_policy *policy, uint32_t index,
                                const range_trans_t **key,
                                const mls_range_t **range,
                                st_error *error)
{
    const hashtab_t table = policy->policydb->p.range_tr;
    hashtab_ptr_t node;
    uint32_t bucket;
    uint32_t current = 0U;

    if (table != NULL) {
        for (bucket = 0U; bucket < table->size; bucket++) {
            for (node = table->htable[bucket]; node != NULL; node = node->next) {
                if (current++ == index) {
                    *key = (const range_trans_t *)node->key;
                    *range = (const mls_range_t *)node->datum;
                    return ST_STATUS_OK;
                }
            }
        }
    }
    st_error_set(error, ST_STATUS_INVALID_METADATA,
                 "MLS rule index %u is not present", index);
    return ST_STATUS_INVALID_METADATA;
}

int32_t st_policy_mls_rule_get(const st_policy *policy, uint32_t index,
                               st_mls_rule_view *rule, st_error *error)
{
    const range_trans_t *key;
    const mls_range_t *range;
    int32_t status;

    if (error != NULL) {
        error->code = ST_STATUS_OK;
        error->message = NULL;
    }
    if (policy == NULL || policy->policydb == NULL || rule == NULL) {
        st_error_set(error, ST_STATUS_INVALID_ARGUMENT,
                     "policy and MLS rule pointers must not be null");
        return ST_STATUS_INVALID_ARGUMENT;
    }
    status = st_mls_rule_find(policy, index, &key, &range, error);
    if (status != ST_STATUS_OK) {
        return status;
    }
    if (key == NULL || range == NULL || key->source_type == 0U ||
        key->target_type == 0U || key->target_class == 0U ||
        range->level[0].sens == 0U || range->level[1].sens == 0U) {
        st_error_set(error, ST_STATUS_INVALID_METADATA,
                     "MLS rule index %u contains a zero symbol value", index);
        return ST_STATUS_INVALID_METADATA;
    }
    rule->source = key->source_type - 1U;
    rule->target = key->target_type - 1U;
    rule->target_class = key->target_class - 1U;
    rule->low_sensitivity = range->level[0].sens - 1U;
    rule->high_sensitivity = range->level[1].sens - 1U;
    return ST_STATUS_OK;
}

int32_t st_policy_mls_rule_categories_get(const st_policy *policy,
                                          uint32_t index, uint32_t high,
                                          uint32_t *categories,
                                          size_t capacity, size_t *count,
                                          st_error *error)
{
    const range_trans_t *key;
    const mls_range_t *range;
    int32_t status;

    if (error != NULL) {
        error->code = ST_STATUS_OK;
        error->message = NULL;
    }
    if (policy == NULL || policy->policydb == NULL || count == NULL || high > 1U) {
        st_error_set(error, ST_STATUS_INVALID_ARGUMENT,
                     "invalid MLS category copy arguments");
        return ST_STATUS_INVALID_ARGUMENT;
    }
    status = st_mls_rule_find(policy, index, &key, &range, error);
    if (status != ST_STATUS_OK) {
        return status;
    }
    (void)key;
    return st_bitmap_copy(&range->level[high].cat,
                          st_policy_category_count(policy), categories,
                          capacity, count, "MLS category set", error);
}

void st_error_clear(st_error *error)
{
    if (error == NULL) {
        return;
    }

    free(error->message);
    error->message = NULL;
    error->code = ST_STATUS_OK;
}
