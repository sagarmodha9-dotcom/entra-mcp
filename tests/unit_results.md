# Layers A, B, W and T: protocol, server-authorization, write-path and bounded-latency tests (MOCKED Graph, no tenant)

These tests never contact Microsoft. Graph is an HTTP mock that records every request and fails the suite on anything but GET. They prove what the SERVER does; they prove nothing about the tenant. Live tenant evidence is in `tests/live_results.md` and `EVIDENCE.md`, produced by `tests/live_m1.py`.

Run: 2026-10-23 01:25 UTC  Python 3.12.15  
Result: **109 passed, 0 failed, 109 tests**

| layer | test | result |
|---|---|---|
| A protocol | `test_a1_handshake_lists_exactly_seven_tools` | passed |
| A protocol | `test_a2_schema_rejections_make_no_graph_call[get_user-args0-extra]` | passed |
| A protocol | `test_a2_schema_rejections_make_no_graph_call[get_user-args1-upn]` | passed |
| A protocol | `test_a2_schema_rejections_make_no_graph_call[get_sign_in_logs-args2-days]` | passed |
| A protocol | `test_a2_schema_rejections_make_no_graph_call[get_sign_in_logs-args3-top]` | passed |
| A protocol | `test_a2_schema_rejections_make_no_graph_call[get_sign_in_logs-args4-days]` | passed |
| A protocol | `test_a2_schema_rejections_make_no_graph_call[list_devices-args5-top]` | passed |
| A protocol | `test_a2_schema_rejections_make_no_graph_call[get_device-args6-device_id]` | passed |
| A protocol | `test_a2_schema_rejections_make_no_graph_call[get_device-args7-path]` | passed |
| A protocol | `test_a2_schema_rejections_make_no_graph_call[nonexistent_tool-args8-no such tool]` | passed |
| A protocol | `test_a3_every_tool_hits_only_its_allowlisted_urls` | passed |
| A protocol | `test_a3_unknown_template_and_bad_placeholders_refused` | passed |
| A protocol | `test_a4_no_generic_parameter_in_any_tool_and_in_source` | passed |
| A protocol | `test_a5_transport_fails_on_any_non_get` | passed |
| A protocol | `test_a6_each_graph_error_maps_to_a_clear_tool_error[401-graph_401]` | passed |
| A protocol | `test_a6_each_graph_error_maps_to_a_clear_tool_error[403-graph_403]` | passed |
| A protocol | `test_a6_each_graph_error_maps_to_a_clear_tool_error[404-not_found]` | passed |
| A protocol | `test_a6_each_graph_error_maps_to_a_clear_tool_error[429-graph_429]` | passed |
| A protocol | `test_a6_each_graph_error_maps_to_a_clear_tool_error[503-graph_503]` | passed |
| A protocol | `test_a6_retry_then_success` | passed |
| A protocol | `test_a7_every_call_including_refusals_writes_one_line_with_documented_fields` | passed |
| A protocol | `test_a6_timeout_is_retried_then_surfaced_without_crashing` | passed |
| A protocol | `test_a6_unexpected_exception_becomes_a_tool_error` | passed |
| A protocol | `test_a6_sign_in_logs_have_a_20s_budget_and_one_retry` | passed |
| A protocol | `test_a7_tap_visible_in_auth_methods_without_its_code` | passed |
| B server authorization | `test_b1_deny_listed_admin_refused_with_zero_graph_calls` | passed |
| B server authorization | `test_b1_role_holder_refused_before_the_tool_request` | passed |
| B server authorization | `test_b1_guard_fails_closed_when_a_lookup_errors` | passed |
| B server authorization | `test_b1_role_assignment_and_role_assignable_group_refuse` | passed |
| B server authorization | `test_b2_injected_department_is_returned_as_data_and_causes_no_second_request` | passed |
| B server authorization | `test_b2_injected_device_name_in_sign_in_log_is_quoted_not_acted_on` | passed |
| B server authorization | `test_b3_hostile_upns_rejected_by_schema_before_url_builder[alice.test/../admin@contoso-test.onmicrosoft.com]` | passed |
| B server authorization | `test_b3_hostile_upns_rejected_by_schema_before_url_builder[alice.test@contoso-test.onmicrosoft.com/memberOf]` | passed |
| B server authorization | `test_b3_hostile_upns_rejected_by_schema_before_url_builder[alice.test$@contoso-test.onmicrosoft.com]` | passed |
| B server authorization | `test_b3_hostile_upns_rejected_by_schema_before_url_builder[alice.test%40contoso-test.onmicrosoft.com]` | passed |
| B server authorization | `test_b3_hostile_upns_rejected_by_schema_before_url_builder[alice test@contoso-test.onmicrosoft.com]` | passed |
| B server authorization | `test_b3_hostile_upns_rejected_by_schema_before_url_builder[alice.test@contoso-test.onmicrosoft.com']` | passed |
| B server authorization | `test_b3_hostile_upns_rejected_by_schema_before_url_builder[alice.test@contoso-test.onmicrosoft.com or 1 eq 1]` | passed |
| B server authorization | `test_b3_hostile_upns_rejected_by_schema_before_url_builder[alice.test@contoso.com]` | passed |
| B server authorization | `test_b3_hostile_upns_rejected_by_schema_before_url_builder[x' or userId ne '@contoso-test.onmicrosoft.com]` | passed |
| B server authorization | `test_b3_hostile_upns_rejected_by_schema_before_url_builder[alice.test@contoso-test.onmicrosoft.com?$select=*]` | passed |
| B server authorization | `test_b3_hostile_upns_rejected_by_schema_before_url_builder[alice.test@contoso-test.onmicrosoft.com#]` | passed |
| B server authorization | `test_b3_hostile_upns_rejected_by_schema_before_url_builder[.alice@contoso-test.onmicrosoft.com]` | passed |
| B server authorization | `test_b3_hostile_upns_rejected_by_schema_before_url_builder[a..b@contoso-test.onmicrosoft.com]` | passed |
| B server authorization | `test_b3_hostile_upns_rejected_by_schema_before_url_builder[]` | passed |
| B server authorization | `test_b3_type_confusion_rejected` | passed |
| B server authorization | `test_b4_sign_in_filter_is_built_from_typed_fields_only` | passed |
| B server authorization | `test_b5_token_roles_contain_no_write_scope_and_match_the_five_reads` | passed |
| B server authorization | `test_b6_secret_and_tokens_never_reach_logs_errors_or_results` | passed |
| B server authorization | `test_b6_repo_contains_no_secret_shaped_string` | passed |
| T bounded latency (fake clock) | `test_t1_no_request_timeout_outlives_the_deadline` | passed |
| T bounded latency (fake clock) | `test_t2_deadline_caps_retry_loops_and_names_it` | passed |
| T bounded latency (fake clock) | `test_t3_last_sign_in_degrades_to_unavailable_not_error` | passed |
| T bounded latency (fake clock) | `test_t4_slow_but_answering_endpoint_still_succeeds` | passed |
| T bounded latency (fake clock) | `test_t5_sign_in_log_keeps_its_20s_budget_inside_the_deadline` | passed |
| T bounded latency (fake clock) | `test_t6_every_read_tool_is_bounded_when_graph_never_answers[get_last_sign_in]` | passed |
| T bounded latency (fake clock) | `test_t6_every_read_tool_is_bounded_when_graph_never_answers[get_sign_in_logs]` | passed |
| T bounded latency (fake clock) | `test_t6_every_read_tool_is_bounded_when_graph_never_answers[get_user]` | passed |
| T bounded latency (fake clock) | `test_t6_every_read_tool_is_bounded_when_graph_never_answers[list_auth_methods]` | passed |
| T bounded latency (fake clock) | `test_t6_every_read_tool_is_bounded_when_graph_never_answers[list_devices]` | passed |
| T bounded latency (fake clock) | `test_t6_every_read_tool_is_bounded_when_graph_never_answers[list_user_groups]` | passed |
| T bounded latency (fake clock) | `test_t7_requests_transport_is_wall_clock_bounded_even_when_the_stall_is_outside_the_socket` | passed |
| W write path (approvals) | `test_w1_every_write_tool_only_proposes[disable_account-args0]` | passed |
| W write path (approvals) | `test_w1_every_write_tool_only_proposes[enable_account-args1]` | passed |
| W write path (approvals) | `test_w1_every_write_tool_only_proposes[reset_password-args2]` | passed |
| W write path (approvals) | `test_w1_every_write_tool_only_proposes[create_temporary_access_pass-args3]` | passed |
| W write path (approvals) | `test_w1_every_write_tool_only_proposes[revoke_sessions-args4]` | passed |
| W write path (approvals) | `test_w1_every_write_tool_only_proposes[add_to_group-args5]` | passed |
| W write path (approvals) | `test_w1_every_write_tool_only_proposes[remove_from_group-args6]` | passed |
| W write path (approvals) | `test_w1_every_write_tool_only_proposes[sync_device-args7]` | passed |
| W write path (approvals) | `test_w1_every_write_tool_only_proposes[reboot_device-args8]` | passed |
| W write path (approvals) | `test_w2_approve_tool_without_human_approval_is_refused` | passed |
| W write path (approvals) | `test_w3_human_approval_then_execution_exact_request_single_use` | passed |
| W write path (approvals) | `test_w3_each_tool_sends_exactly_its_one_template[enable_account-args0-PATCH-/users/c0454a86-0000-4000-8000-000000000002-body0]` | passed |
| W write path (approvals) | `test_w3_each_tool_sends_exactly_its_one_template[revoke_sessions-args1-POST-/users/c0454a86-0000-4000-8000-000000000002/revokeSignInSessions-None]` | passed |
| W write path (approvals) | `test_w3_each_tool_sends_exactly_its_one_template[reset_password-args2-POST-/users/de3907dd-0000-4000-8000-000000000004/authentication/methods/28c10230-6103-485e-b985-444c416c4c52/resetPassword-PASSWORD]` | passed |
| W write path (approvals) | `test_w3_each_tool_sends_exactly_its_one_template[create_temporary_access_pass-args3-POST-/users/de3907dd-0000-4000-8000-000000000004/authentication/temporaryAccessPassMethods-body3]` | passed |
| W write path (approvals) | `test_w3_each_tool_sends_exactly_its_one_template[add_to_group-args4-POST-/groups/aaaaaaaa-1111-4222-8333-444444444444/members/$ref-body4]` | passed |
| W write path (approvals) | `test_w3_each_tool_sends_exactly_its_one_template[remove_from_group-args5-DELETE-/groups/aaaaaaaa-1111-4222-8333-444444444444/members/c0454a86-0000-4000-8000-000000000002/$ref-None]` | passed |
| W write path (approvals) | `test_w3_each_tool_sends_exactly_its_one_template[sync_device-args6-POST-/deviceManagement/managedDevices/11111111-2222-4333-8444-555555555555/syncDevice-None]` | passed |
| W write path (approvals) | `test_w3_each_tool_sends_exactly_its_one_template[reboot_device-args7-POST-/deviceManagement/managedDevices/11111111-2222-4333-8444-555555555555/rebootNow-None]` | passed |
| W write path (approvals) | `test_w4_expired_proposal_cannot_be_approved_or_executed` | passed |
| W write path (approvals) | `test_w5_deny_listed_and_role_holding_targets_never_get_a_proposal` | passed |
| W write path (approvals) | `test_w5_role_change_between_approval_and_execution_is_caught` | passed |
| W write path (approvals) | `test_w6_device_not_in_test_list_refused_and_no_wipe_or_retire_anywhere` | passed |
| W write path (approvals) | `test_w7_read_client_cannot_send_a_write_template` | passed |
| W write path (approvals) | `test_w7_execution_with_app_only_token_is_refused` | passed |
| W write path (approvals) | `test_w8_generated_password_and_tap_never_reach_audit_or_approval_store` | passed |
| W write path (approvals) | `test_w9_role_assignable_and_m365_groups_refused_name_resolves_to_id` | passed |
| W write path (approvals) | `test_w10_hostile_write_arguments_rejected_with_zero_graph_calls[disable_account-args0]` | passed |
| W write path (approvals) | `test_w10_hostile_write_arguments_rejected_with_zero_graph_calls[disable_account-args1]` | passed |
| W write path (approvals) | `test_w10_hostile_write_arguments_rejected_with_zero_graph_calls[disable_account-args2]` | passed |
| W write path (approvals) | `test_w10_hostile_write_arguments_rejected_with_zero_graph_calls[disable_account-args3]` | passed |
| W write path (approvals) | `test_w10_hostile_write_arguments_rejected_with_zero_graph_calls[add_to_group-args4]` | passed |
| W write path (approvals) | `test_w10_hostile_write_arguments_rejected_with_zero_graph_calls[add_to_group-args5]` | passed |
| W write path (approvals) | `test_w10_hostile_write_arguments_rejected_with_zero_graph_calls[create_temporary_access_pass-args6]` | passed |
| W write path (approvals) | `test_w10_hostile_write_arguments_rejected_with_zero_graph_calls[create_temporary_access_pass-args7]` | passed |
| W write path (approvals) | `test_w10_hostile_write_arguments_rejected_with_zero_graph_calls[approve-args8]` | passed |
| W write path (approvals) | `test_w10_hostile_write_arguments_rejected_with_zero_graph_calls[approve-args9]` | passed |
| W write path (approvals) | `test_w10_hostile_write_arguments_rejected_with_zero_graph_calls[reboot_device-args10]` | passed |
| W write path (approvals) | `test_w10_hostile_write_arguments_rejected_with_zero_graph_calls[sync_device-args11]` | passed |
| W write path (approvals) | `test_w11_each_write_tool_maps_to_exactly_one_non_get_template` | passed |
| W write path (approvals) | `test_w12_concurrent_approve_calls_execute_exactly_once` | passed |
| W write path (approvals) | `test_w12_two_processes_sharing_the_store_cannot_both_claim` | passed |
| W write path (approvals) | `test_w12_replay_after_execution_and_cli_reapprove_are_refused` | passed |
| W write path (approvals) | `test_w12_tampered_proposal_is_refused_and_denied` | passed |
| W write path (approvals) | `test_w12_graph_error_marks_failed_and_never_retries` | passed |
| W write path (approvals) | `test_w12_timeout_is_uncertain_not_executed_and_not_retried` | passed |
| W write path (approvals) | `test_w12_executed_audit_line_is_self_contained` | passed |
