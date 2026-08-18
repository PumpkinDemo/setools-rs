/* SPDX-License-Identifier: LGPL-2.1-only */

#ifndef SETOOLS_SEPOL_BRIDGE_H
#define SETOOLS_SEPOL_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ST_BRIDGE_ABI_VERSION 4U

typedef struct st_policy st_policy;

typedef enum st_status {
    ST_STATUS_OK = 0,
    ST_STATUS_INVALID_ARGUMENT = 1,
    ST_STATUS_OUT_OF_MEMORY = 2,
    ST_STATUS_OPEN_FAILED = 3,
    ST_STATUS_POLICY_READ_FAILED = 4,
    ST_STATUS_INVALID_METADATA = 5
} st_status;

typedef struct st_error {
    int32_t code;
    char *message;
} st_error;

typedef struct st_policy_metadata {
    uint32_t version;
    uint32_t mls;
    uint32_t target_platform;
    uint32_t handle_unknown;
} st_policy_metadata;

typedef struct st_string_view {
    const char *data;
    size_t length;
} st_string_view;

typedef struct st_running_policy_info {
    uint32_t selinuxfs_exists;
    uint32_t minimum_version;
    uint32_t maximum_version;
    st_string_view current_policy_path;
    st_string_view binary_policy_path;
} st_running_policy_info;

typedef enum st_type_kind {
    ST_TYPE = 0,
    ST_TYPE_ATTRIBUTE = 1
} st_type_kind;

typedef struct st_type_view {
    uint32_t kind;
    st_string_view name;
    uint32_t permissive;
    uint32_t bound;
} st_type_view;

typedef struct st_class_view {
    st_string_view name;
    st_string_view common;
    uint32_t permission_count;
    uint32_t local_permission_count;
    uint32_t default_user;
    uint32_t default_role;
    uint32_t default_type;
    uint32_t default_range;
} st_class_view;

typedef struct st_te_rule_view {
    uint32_t kind;
    uint32_t source;
    uint32_t target;
    uint32_t target_class;
    uint32_t permissions;
    uint32_t default_type;
    uint32_t xperm_kind;
    uint32_t xperm_driver;
    uint32_t xperms[8];
    uint32_t conditional;
    uint32_t conditional_block;
} st_te_rule_view;

typedef struct st_boolean_view {
    st_string_view name;
    uint32_t state;
} st_boolean_view;

typedef struct st_conditional_token_view {
    uint32_t kind;
    uint32_t boolean;
} st_conditional_token_view;

typedef struct st_role_view {
    st_string_view name;
} st_role_view;

typedef struct st_rbac_rule_view {
    uint32_t kind;
    uint32_t source;
    uint32_t target;
    uint32_t target_class;
    uint32_t default_role;
} st_rbac_rule_view;

typedef struct st_filename_rule_view {
    uint32_t source;
    uint32_t target;
    uint32_t target_class;
    uint32_t default_type;
    st_string_view filename;
} st_filename_rule_view;

typedef struct st_mls_rule_view {
    uint32_t source;
    uint32_t target;
    uint32_t target_class;
    uint32_t low_sensitivity;
    uint32_t high_sensitivity;
} st_mls_rule_view;

typedef struct st_common_view {
    st_string_view name;
    uint32_t permission_count;
} st_common_view;

typedef struct st_user_view {
    st_string_view name;
    uint32_t low_sensitivity;
    uint32_t high_sensitivity;
    uint32_t default_sensitivity;
} st_user_view;

typedef struct st_constraint_view {
    uint32_t target_class;
    uint32_t permissions;
    uint32_t validate_transition;
    uint32_t mls;
    uint32_t expression_count;
} st_constraint_view;

typedef struct st_constraint_expression_view {
    uint32_t expression_type;
    uint32_t attribute;
    uint32_t operator;
    uint32_t names_kind;
    uint32_t names_count;
} st_constraint_expression_view;

typedef struct st_context_view {
    uint32_t user;
    uint32_t role;
    uint32_t type;
    uint32_t low_sensitivity;
    uint32_t high_sensitivity;
} st_context_view;

typedef enum st_labeling_kind {
    ST_LABEL_INITIAL_SID = 0,
    ST_LABEL_FS_USE = 1,
    ST_LABEL_GENFSCON = 2,
    ST_LABEL_PORTCON = 3,
    ST_LABEL_NETIFCON = 4,
    ST_LABEL_NODECON = 5,
    ST_LABEL_IBPKEYCON = 6,
    ST_LABEL_IBENDPORTCON = 7,
    ST_LABEL_DEVICETREECON = 8,
    ST_LABEL_IOMEMCON = 9,
    ST_LABEL_IOPORTCON = 10,
    ST_LABEL_PCIDEVICECON = 11,
    ST_LABEL_PIRQCON = 12
} st_labeling_kind;

typedef struct st_labeling_view {
    uint32_t subtype;
    st_string_view name;
    st_string_view secondary;
    uint64_t low;
    uint64_t high;
    uint8_t address[16];
    uint8_t mask[16];
    st_context_view contexts[2];
} st_labeling_view;

uint32_t st_bridge_abi_version(void);

int32_t st_process_use_default_sigpipe(void);

int32_t st_running_policy_info_get(st_running_policy_info *info);

int32_t st_local_log_timestamp(char *buffer, size_t capacity);

st_policy *st_policy_load(const char *path, st_error *error);

void st_policy_free(st_policy *policy);

int32_t st_policy_metadata_get(const st_policy *policy,
                               st_policy_metadata *metadata,
                               st_error *error);

uint32_t st_policy_type_count(const st_policy *policy);

int32_t st_policy_type_get(const st_policy *policy, uint32_t index,
                           st_type_view *type, st_error *error);

uint32_t st_policy_type_alias_count(const st_policy *policy, uint32_t type);

int32_t st_policy_type_alias_get(const st_policy *policy, uint32_t type,
                                 uint32_t index, st_string_view *name,
                                 st_error *error);

int32_t st_policy_attribute_members_get(const st_policy *policy,
                                        uint32_t attribute,
                                        uint32_t *members,
                                        size_t capacity,
                                        size_t *count,
                                        st_error *error);

uint32_t st_policy_class_count(const st_policy *policy);

int32_t st_policy_class_get(const st_policy *policy, uint32_t index,
                            st_class_view *target_class, st_error *error);

int32_t st_policy_permission_get(const st_policy *policy,
                                 uint32_t target_class,
                                 uint32_t permission,
                                 st_string_view *name,
                                 st_error *error);

int32_t st_policy_class_local_permission_get(const st_policy *policy,
                                             uint32_t target_class,
                                             uint32_t index,
                                             st_string_view *name,
                                             st_error *error);

uint32_t st_policy_te_rule_count(const st_policy *policy);

int32_t st_policy_te_rule_get(const st_policy *policy, uint32_t index,
                              st_te_rule_view *rule, st_error *error);

uint32_t st_policy_boolean_count(const st_policy *policy);

int32_t st_policy_boolean_get(const st_policy *policy, uint32_t index,
                              st_boolean_view *boolean, st_error *error);

uint32_t st_policy_conditional_count(const st_policy *policy);

uint32_t st_policy_conditional_token_count(const st_policy *policy,
                                           uint32_t conditional);

int32_t st_policy_conditional_token_get(const st_policy *policy,
                                        uint32_t conditional,
                                        uint32_t index,
                                        st_conditional_token_view *token,
                                        st_error *error);

uint32_t st_policy_role_count(const st_policy *policy);

int32_t st_policy_role_get(const st_policy *policy, uint32_t index,
                           st_role_view *role, st_error *error);

int32_t st_policy_role_members_get(const st_policy *policy, uint32_t role,
                                   uint32_t *members, size_t capacity,
                                   size_t *count, st_error *error);

int32_t st_policy_role_types_get(const st_policy *policy, uint32_t role,
                                 uint32_t *types, size_t capacity,
                                 size_t *count, st_error *error);

uint32_t st_policy_rbac_rule_count(const st_policy *policy);

int32_t st_policy_rbac_rule_get(const st_policy *policy, uint32_t index,
                                st_rbac_rule_view *rule, st_error *error);

uint32_t st_policy_filename_rule_count(const st_policy *policy);

int32_t st_policy_filename_rule_get(const st_policy *policy, uint32_t index,
                                    st_filename_rule_view *rule,
                                    st_error *error);

uint32_t st_policy_sensitivity_count(const st_policy *policy);

int32_t st_policy_sensitivity_get(const st_policy *policy, uint32_t index,
                                  st_string_view *name, st_error *error);

uint32_t st_policy_sensitivity_alias_count(const st_policy *policy,
                                           uint32_t sensitivity);

int32_t st_policy_sensitivity_alias_get(const st_policy *policy,
                                        uint32_t sensitivity, uint32_t index,
                                        st_string_view *name, st_error *error);

uint32_t st_policy_category_count(const st_policy *policy);

int32_t st_policy_category_get(const st_policy *policy, uint32_t index,
                               st_string_view *name, st_error *error);

uint32_t st_policy_category_alias_count(const st_policy *policy,
                                        uint32_t category);

int32_t st_policy_category_alias_get(const st_policy *policy,
                                     uint32_t category, uint32_t index,
                                     st_string_view *name, st_error *error);

uint32_t st_policy_mls_rule_count(const st_policy *policy);

int32_t st_policy_mls_rule_get(const st_policy *policy, uint32_t index,
                               st_mls_rule_view *rule, st_error *error);

int32_t st_policy_mls_rule_categories_get(const st_policy *policy,
                                          uint32_t index, uint32_t high,
                                          uint32_t *categories,
                                          size_t capacity, size_t *count,
                                          st_error *error);

uint32_t st_policy_common_count(const st_policy *policy);

int32_t st_policy_common_get(const st_policy *policy, uint32_t index,
                             st_common_view *common, st_error *error);

int32_t st_policy_common_permission_get(const st_policy *policy,
                                        uint32_t common, uint32_t index,
                                        st_string_view *name,
                                        st_error *error);

uint32_t st_policy_user_count(const st_policy *policy);

int32_t st_policy_user_get(const st_policy *policy, uint32_t index,
                           st_user_view *user, st_error *error);

int32_t st_policy_user_roles_get(const st_policy *policy, uint32_t user,
                                 uint32_t *roles, size_t capacity,
                                 size_t *count, st_error *error);

int32_t st_policy_user_categories_get(const st_policy *policy, uint32_t user,
                                      uint32_t level, uint32_t *categories,
                                      size_t capacity, size_t *count,
                                      st_error *error);

uint32_t st_policy_constraint_count(const st_policy *policy);

int32_t st_policy_constraint_get(const st_policy *policy, uint32_t index,
                                 st_constraint_view *constraint,
                                 st_error *error);

int32_t st_policy_constraint_expression_get(
    const st_policy *policy, uint32_t constraint, uint32_t index,
    st_constraint_expression_view *expression, st_error *error);

int32_t st_policy_constraint_expression_names_get(
    const st_policy *policy, uint32_t constraint, uint32_t expression,
    uint32_t *names, size_t capacity, size_t *count, st_error *error);

uint32_t st_policy_capability_count(const st_policy *policy);

int32_t st_policy_capability_get(const st_policy *policy, uint32_t index,
                                 st_string_view *name, st_error *error);

uint32_t st_policy_labeling_count(const st_policy *policy, uint32_t kind);

int32_t st_policy_labeling_get(const st_policy *policy, uint32_t kind,
                               uint32_t index, st_labeling_view *labeling,
                               st_error *error);

int32_t st_policy_labeling_context_categories_get(
    const st_policy *policy, uint32_t kind, uint32_t index,
    uint32_t context_index, uint32_t high, uint32_t *categories,
    size_t capacity, size_t *count, st_error *error);

void st_error_clear(st_error *error);

#ifdef __cplusplus
}
#endif

#endif
