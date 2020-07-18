# Cookbook:: cb-cis-level1-win2016-member
# Recipe:: section_2
#
# Copyright:: 2019, The Authors, All Rights Reserved.

# class ::Chef::Resource
#   include ::Windows2016Hardening::Helpers
# end

# # xccdf_org.cisecurity.benchmarks_rule_2.2.1_L1_Ensure_Access_Credential_Manager_as_a_trusted_caller_is_set_to_No_One
# dsc_resource 'Limit access to credential Manager as a trusted caller' do
#   module_name 'SecurityPolicyDsc'
#   property :policy, 'Access_Credential_Manager_as_a_trusted_caller'
#   property :identity, ['']
#   property :force, true
#   resource :UserRightsAssignment
# end

# # xccdf_org.cisecurity.benchmarks_rule_2.2.3_L1_Ensure_Access_this_computer_from_the_network__is_set_to_Administrators_Authenticated_Users_MS_only
# dsc_resource 'Limit access to this computer from the network' do
#   module_name 'SecurityPolicyDsc'
#   property :policy, 'Access_this_computer_from_the_network'
#   property :identity, valid_users_groups(['Authenticated Users', 'Administrators'])
#   property :force, true
#   resource :UserRightsAssignment
# end

# # xccdf_org.cisecurity.benchmarks_rule_2.2.4_L1_Ensure_Act_as_part_of_the_operating_system_is_set_to_No_One
# dsc_resource 'Limit users who can act as part of the operating system' do
#   module_name 'SecurityPolicyDsc'
#   property :policy, 'Act_as_part_of_the_operating_system'
#   property :identity, valid_users_groups([''])
#   property :force, true
#   resource :UserRightsAssignment
# end

# # xccdf_org.cisecurity.benchmarks_rule_2.2.6_L1_Ensure_Adjust_memory_quotas_for_a_process_is_set_to_Administrators_LOCAL_SERVICE_NETWORK_SERVICE
# dsc_resource 'Limit who can adjust memory quotas for a process' do
#   module_name 'SecurityPolicyDsc'
#   property :policy, 'Adjust_memory_quotas_for_a_process'
#   property :identity, valid_users_groups(['Administrators', 'LOCAL SERVICE', 'NETWORK SERVICE'])
#   property :force, true
#   resource :UserRightsAssignment
# end

# # xccdf_org.cisecurity.benchmarks_rule_2.2.7_L1_Ensure_Allow_log_on_locally_is_set_to_Administrators
# dsc_resource 'Limit who can Allow_log_on_locally' do
#   module_name 'SecurityPolicyDsc'
#   property :policy, 'Allow_log_on_locally'
#   property :identity, valid_users_groups(['Administrators'])
#   property :force, true
#   resource :UserRightsAssignment
# end

# # xccdf_org.cisecurity.benchmarks_rule_2.2.9_L1_Ensure_Allow_log_on_through_Remote_Desktop_Services_is_set_to_Administrators_Remote_Desktop_Users_MS_only
# dsc_resource 'Limit who can log on through remote desktop services' do
#   module_name 'SecurityPolicyDsc'
#   property :policy, 'Allow_log_on_through_Remote_Desktop_Services'
#   property :identity, valid_users_groups(['Administrators'])
#   property :force, true
#   resource :UserRightsAssignment
# end

# # xccdf_org.cisecurity.benchmarks_rule_2.2.10_L1_Ensure_Back_up_files_and_directories_is_set_to_Administrators
# dsc_resource 'Limit who can backup files and directories' do
#   module_name 'SecurityPolicyDsc'
#   property :policy, 'Back_up_files_and_directories'
#   property :identity, valid_users_groups(['Administrators'])
#   property :force, true
#   resource :UserRightsAssignment
# end

# # xccdf_org.cisecurity.benchmarks_rule_2.2.11_L1_Ensure_Change_the_system_time_is_set_to_Administrators_LOCAL_SERVICE
# dsc_resource 'Limit who can change the system time' do
#   module_name 'SecurityPolicyDsc'
#   property :policy, 'Change_the_system_time'
#   property :identity, valid_users_groups(['Administrators', 'LOCAL SERVICE'])
#   property :force, true
#   resource :UserRightsAssignment
# end

# # xccdf_org.cisecurity.benchmarks_rule_2.2.12_L1_Ensure_Change_the_time_zone_is_set_to_Administrators_LOCAL_SERVICE
# dsc_resource 'Limit who can change the time zone' do
#   module_name 'SecurityPolicyDsc'
#   property :policy, 'Change_the_time_zone'
#   property :identity, valid_users_groups(['Administrators', 'LOCAL SERVICE'])
#   property :force, true
#   resource :UserRightsAssignment
# end

# # xccdf_org.cisecurity.benchmarks_rule_2.2.13_L1_Ensure_Create_a_pagefile_is_set_to_Administrators
# dsc_resource 'Limit who can create a pagefile' do
#   module_name 'SecurityPolicyDsc'
#   property :policy, 'Create_a_pagefile'
#   property :identity, valid_users_groups(['Administrators'])
#   property :force, true
#   resource :UserRightsAssignment
# end

# # xccdf_org.cisecurity.benchmarks_rule_2.2.14_L1_Ensure_Create_a_token_object_is_set_to_No_One
# dsc_resource 'Limit Create_a_token_object' do
#   module_name 'SecurityPolicyDsc'
#   property :policy, 'Create_a_token_object'
#   property :identity, valid_users_groups([''])
#   property :force, true
#   resource :UserRightsAssignment
# end

# # xccdf_org.cisecurity.benchmarks_rule_2.2.15_L1_Ensure_Create_global_objects_is_set_to_Administrators_LOCAL_SERVICE_NETWORK_SERVICE_SERVICE
# dsc_resource 'Limit who can create a token object' do
#   module_name 'SecurityPolicyDsc'
#   property :policy, 'Create_global_objects'
#   property :identity, valid_users_groups(['Administrators', 'LOCAL SERVICE', 'NETWORK SERVICE', 'SERVICE'])
#   property :force, true
#   resource :UserRightsAssignment
# end

# # xccdf_org.cisecurity.benchmarks_rule_2.2.16_L1_Ensure_Create_permanent_shared_objects_is_set_to_No_One
# dsc_resource 'Limit who can create permanent shared objects' do
#   module_name 'SecurityPolicyDsc'
#   property :policy, 'Create_permanent_shared_objects'
#   property :identity, ['']
#   property :force, true
#   resource :UserRightsAssignment
# end

# # xccdf_org.cisecurity.benchmarks_rule_2.2.18_L1_Ensure_Create_symbolic_links_is_set_to_Administrators_NT_VIRTUAL_MACHINEVirtual_Machines_MS_only
# dsc_resource 'Create symbolic links' do
#   module_name 'SecurityPolicyDsc'
#   property :policy, 'Create_symbolic_links'
#   property :identity, valid_users_groups(['Administrators'])
#   property :force, true
#   resource :UserRightsAssignment
# end

# # xccdf_org.cisecurity.benchmarks_rule_2.2.19_L1_Ensure_Debug_programs_is_set_to_Administrators
# dsc_resource 'Limit who can debug programs' do
#   module_name 'SecurityPolicyDsc'
#   property :policy, 'Debug_programs'
#   property :identity, valid_users_groups(%w(Administrators))
#   property :force, true
#   resource :UserRightsAssignment
# end

# # xccdf_org.cisecurity.benchmarks_rule_2.2.21_L1_Ensure_Deny_access_to_this_computer_from_the_network_is_set_to_Guests_Local_account_and_member_of_Administrators_group_MS_only
# dsc_resource 'Deny access to this computer from the network' do
#   module_name 'SecurityPolicyDsc'
#   property :policy, 'Deny_access_to_this_computer_from_the_network'
#   property :identity, valid_users_groups(['Guests', 'Administrators'])
#   property :force, true
#   resource :UserRightsAssignment
# end

# # xccdf_org.cisecurity.benchmarks_rule_2.2.22_L1_Ensure_Deny_log_on_as_a_batch_job_to_include_Guests
# dsc_resource 'Deny log on as a batch job' do
#   module_name 'SecurityPolicyDsc'
#   property :policy, 'Deny_log_on_as_a_batch_job'
#   property :identity, valid_users_groups(['Guests'])
#   property :force, true
#   resource :UserRightsAssignment
# end

# # xccdf_org.cisecurity.benchmarks_rule_2.2.23_L1_Ensure_Deny_log_on_as_a_service_to_include_Guests
# dsc_resource 'Deny log on as a service' do
#   module_name 'SecurityPolicyDsc'
#   property :policy, 'Deny_log_on_as_a_service'
#   property :identity, valid_users_groups(['Guests'])
#   property :force, true
#   resource :UserRightsAssignment
# end

# # xccdf_org.cisecurity.benchmarks_rule_2.2.24_L1_Ensure_Deny_log_on_locally_to_include_Guests
# dsc_resource 'Deny log on locally' do
#   module_name 'SecurityPolicyDsc'
#   property :policy, 'Deny_log_on_locally'
#   property :identity, valid_users_groups(['Guests'])
#   property :force, true
#   resource :UserRightsAssignment
# end

# # xccdf_org.cisecurity.benchmarks_rule_2.2.26_L1_Ensure_Deny_log_on_through_Remote_Desktop_Services_is_set_to_Guests_Local_account_MS_only
# dsc_resource 'Deny log on through Remote Desktop Services' do
#   module_name 'SecurityPolicyDsc'
#   property :policy, 'Deny_log_on_through_Remote_Desktop_Services'
#   property :identity, valid_users_groups(['Guests', 'Local account'])
#   property :force, true
#   resource :UserRightsAssignment
# end

# # xccdf_org.cisecurity.benchmarks_rule_2.2.28_L1_Ensure_Enable_computer_and_user_accounts_to_be_trusted_for_delegation_is_set_to_No_One_MS_only
# dsc_resource 'Enable computer and user accounts to be trusted for delegation' do
#   module_name 'SecurityPolicyDsc'
#   property :policy, 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
#   property :identity, ['']
#   property :force, true
#   resource :UserRightsAssignment
# end

# # xccdf_org.cisecurity.benchmarks_rule_2.2.29_L1_Ensure_Force_shutdown_from_a_remote_system_is_set_to_Administrators
# dsc_resource 'Limit who can force shutdown from a remote system' do
#   module_name 'SecurityPolicyDsc'
#   property :policy, 'Force_shutdown_from_a_remote_system'
#   property :identity, valid_users_groups(%w(Administrators))
#   property :force, true
#   resource :UserRightsAssignment
# end

# # xccdf_org.cisecurity.benchmarks_rule_2.2.30_L1_Ensure_Generate_security_audits_is_set_to_LOCAL_SERVICE_NETWORK_SERVICE
# dsc_resource 'Limit who can generate security audits' do
#   module_name 'SecurityPolicyDsc'
#   property :policy, 'Generate_security_audits'
#   property :identity, valid_users_groups(['LOCAL SERVICE', 'NETWORK SERVICE'])
#   property :force, true
#   resource :UserRightsAssignment
# end

# # xccdf_org.cisecurity.benchmarks_rule_2.2.32_L1_Ensure_Impersonate_a_client_after_authentication_is_set_to_Administrators_LOCAL_SERVICE_NETWORK_SERVICE_SERVICE_and_when_the_Web_Server_IIS_Role_with_Web_Services_Role_Service_is_installed_IIS_IUSRS_MS_only
# dsc_resource 'Limit who can impersonate a client after authentication' do
#   module_name 'SecurityPolicyDsc'
#   property :policy, 'Impersonate_a_client_after_authentication'
#   property :identity, valid_users_groups(['Administrators', 'SERVICE', 'LOCAL SERVICE', 'NETWORK SERVICE'])
#   property :force, true
#   resource :UserRightsAssignment
# end

# # xccdf_org.cisecurity.benchmarks_rule_2.2.33_L1_Ensure_Increase_scheduling_priority_is_set_to_Administrators
# dsc_resource 'Limit who can increase scheduling priority' do
#   module_name 'SecurityPolicyDsc'
#   property :policy, 'Increase_scheduling_priority'
#   property :identity, valid_users_groups(['Administrators'])
#   property :force, true
#   resource :UserRightsAssignment
# end

# # xccdf_org.cisecurity.benchmarks_rule_2.2.34_L1_Ensure_Load_and_unload_device_drivers_is_set_to_Administrators
# dsc_resource 'Limit who can load and unload device drivers' do
#   module_name 'SecurityPolicyDsc'
#   property :policy, 'Load_and_unload_device_drivers'
#   property :identity, valid_users_groups(['Administrators'])
#   property :force, true
#   resource :UserRightsAssignment
# end

# # xccdf_org.cisecurity.benchmarks_rule_2.2.35_L1_Ensure_Lock_pages_in_memory_is_set_to_No_One
# dsc_resource 'Limit who can lock pages in memory' do
#   module_name 'SecurityPolicyDsc'
#   property :policy, 'Lock_pages_in_memory'
#   property :identity, ['']
#   property :force, true
#   resource :UserRightsAssignment
# end

# # xccdf_org.cisecurity.benchmarks_rule_2.2.38_L1_Ensure_Manage_auditing_and_security_log_is_set_to_Administrators_MS_only
# dsc_resource 'Limit who can manage auditing and security log' do
#   module_name 'SecurityPolicyDsc'
#   property :policy, 'Manage_auditing_and_security_log'
#   property :identity, valid_users_groups(['Administrators'])
#   property :force, true
#   resource :UserRightsAssignment
# end

# # xccdf_org.cisecurity.benchmarks_rule_2.2.39_L1_Ensure_Modify_an_object_label_is_set_to_No_One
# dsc_resource 'Limit who can modify an object label' do
#   module_name 'SecurityPolicyDsc'
#   property :policy, 'Modify_an_object_label'
#   property :identity, ['']
#   property :force, true
#   resource :UserRightsAssignment
# end

# # xccdf_org.cisecurity.benchmarks_rule_2.2.40_L1_Ensure_Modify_firmware_environment_values_is_set_to_Administrators
# dsc_resource 'Limit who can modify firmware environment values' do
#   module_name 'SecurityPolicyDsc'
#   property :policy, 'Modify_firmware_environment_values'
#   property :identity, valid_users_groups(['Administrators'])
#   property :force, true
#   resource :UserRightsAssignment
# end

# # xccdf_org.cisecurity.benchmarks_rule_2.2.41_L1_Ensure_Perform_volume_maintenance_tasks_is_set_to_Administrators
# dsc_resource 'Limit who can perform volume maintenance tasks' do
#   module_name 'SecurityPolicyDsc'
#   property :policy, 'Perform_volume_maintenance_tasks'
#   property :identity, valid_users_groups(['Administrators'])
#   property :force, true
#   resource :UserRightsAssignment
# end

# # xccdf_org.cisecurity.benchmarks_rule_2.2.42_L1_Ensure_Profile_single_process_is_set_to_Administrators
# dsc_resource 'Limit who can profile single process' do
#   module_name 'SecurityPolicyDsc'
#   property :policy, 'Profile_single_process'
#   property :identity, valid_users_groups(['Administrators'])
#   property :force, true
#   resource :UserRightsAssignment
# end

# # xccdf_org.cisecurity.benchmarks_rule_2.2.43_L1_Ensure_Profile_system_performance_is_set_to_Administrators_NT_SERVICEWdiServiceHost
# dsc_script 'Limit who can profile system performance' do
#   imports 'SecurityPolicyDsc'
#   code <<-EOH
#        UserRightsAssignment AssignShutdownPrivilegesToAdmins
#         {
#             Policy   = "Profile_system_performance"
#             Identity = "Administrators", "NT SERVICE\\WdiServiceHost"
#             Force    = $true
#         }
# EOH
# end

# # xccdf_org.cisecurity.benchmarks_rule_2.2.44_L1_Ensure_Replace_a_process_level_token_is_set_to_LOCAL_SERVICE_NETWORK_SERVICE
# dsc_resource 'Limit who can replace a process level token' do
#   module_name 'SecurityPolicyDsc'
#   property :policy, 'Replace_a_process_level_token'
#   property :identity, valid_users_groups(['LOCAL SERVICE', 'NETWORK SERVICE'])
#   property :force, true
#   resource :UserRightsAssignment
# end

# # xccdf_org.cisecurity.benchmarks_rule_2.2.45_L1_Ensure_Restore_files_and_directories_is_set_to_Administrators
# dsc_resource 'Limit who can Restore_files_and_directories' do
#   module_name 'SecurityPolicyDsc'
#   property :policy, 'Restore_files_and_directories'
#   property :identity, valid_users_groups(['Administrators'])
#   property :force, true
#   resource :UserRightsAssignment
# end

# # xccdf_org.cisecurity.benchmarks_rule_2.2.46_L1_Ensure_Shut_down_the_system_is_set_to_Administrators
# dsc_resource 'Limit who can shut down the system' do
#   module_name 'SecurityPolicyDsc'
#   property :policy, 'Shut_down_the_system'
#   property :identity, valid_users_groups(['Administrators'])
#   property :force, true
#   resource :UserRightsAssignment
# end

# # xccdf_org.cisecurity.benchmarks_rule_2.2.48_L1_Ensure_Take_ownership_of_files_or_other_objects_is_set_to_Administrators
# dsc_resource 'Limit who can take ownership of files or other objects' do
#   module_name 'SecurityPolicyDsc'
#   property :policy, 'Take_ownership_of_files_or_other_objects'
#   property :identity, valid_users_groups(['Administrators'])
#   property :force, true
#   resource :UserRightsAssignment
# end

# xccdf_org.cisecurity.benchmarks_rule_2.3.1.2_L1_Ensure_Accounts_Block_Microsoft_accounts_is_set_to_Users_cant_add_or_log_on_with_Microsoft_accounts
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{ name: 'NoConnectedUser', type: :dword, data: 3 }]
  action :create
  recursive true
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.2.1_L1_Ensure_Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa' do
  values [{ name: 'SCENoApplyLegacyAuditPolicy', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.2.2_L1_Ensure_Audit_Shut_down_system_immediately_if_unable_to_log_security_audits_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\LSA' do
  values [{ name: 'CrashOnAuditFail', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.4.1_L1_Ensure_Devices_Allowed_to_format_and_eject_removable_media_is_set_to_Administrators
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' do
  values [{ name: 'AllocateDASD', type: :string, data: '0' }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.4.2_L1_Ensure_Devices_Prevent_users_from_installing_printer_drivers_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Print\\Providers\\LanMan Print Services\\Servers' do
  values [{ name: 'AddPrinterDrivers', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.6.1_L1_Ensure_Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters' do
  values [{ name: 'RequireSignOrSeal', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.6.2_L1_Ensure_Domain_member_Digitally_encrypt_secure_channel_data_when_possible_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters' do
  values [{ name: 'SealSecureChannel', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.6.3_L1_Ensure_Domain_member_Digitally_sign_secure_channel_data_when_possible_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters' do
  values [{ name: 'SignSecureChannel', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.6.4_L1_Ensure_Domain_member_Disable_machine_account_password_changes_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters' do
  values [{ name: 'DisablePasswordChange', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.6.5_L1_Ensure_Domain_member_Maximum_machine_account_password_age_is_set_to_30_or_fewer_days_but_not_0
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters' do
  values [{ name: 'MaximumPasswordAge', type: :dword, data: 30 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.6.6_L1_Ensure_Domain_member_Require_strong_Windows_2000_or_later_session_key_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters' do
  values [{ name: 'RequireStrongKey', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.7.1_L1_Ensure_Interactive_logon_Do_not_display_last_user_name_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{ name: 'DontDisplayLastUserName', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.7.2_L1_Ensure_Interactive_logon_Do_not_require_CTRLALTDEL_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{ name: 'DisableCAD', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.7.3_L1_Ensure_Interactive_logon_Machine_inactivity_limit_is_set_to_900_or_fewer_seconds_but_not_0
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{ name: 'InactivityTimeoutSecs', type: :dword, data: 900 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.7.4_L1_Configure_Interactive_logon_Message_text_for_users_attempting_to_log_on
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{ name: 'LegalNoticeText', type: :string, data: 'WARNING : Only for testing purpose.' }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.7.5_L1_Configure_Interactive_logon_Message_title_for_users_attempting_to_log_on
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{ name: 'LegalNoticeCaption', type: :string, data: 'PJ Infrastructure As Code' }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.7.7_L1_Ensure_Interactive_logon_Prompt_user_to_change_password_before_expiration_is_set_to_between_5_and_14_days
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' do
  values [{ name: 'PasswordExpiryWarning', type: :dword, data: 7 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.7.8_L1_Ensure_Interactive_logon_Require_Domain_Controller_Authentication_to_unlock_workstation_is_set_to_Enabled_MS_only
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' do
  values [{ name: 'ForceUnlockLogon', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.7.9_L1_Ensure_Interactive_logon_Smart_card_removal_behavior_is_set_to_Lock_Workstation_or_higher
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' do
  values [{ name: 'ScRemoveOption', type: :string, data: 1 }]
  action :create
  recursive true
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.8.1_L1_Ensure_Microsoft_network_client_Digitally_sign_communications_always_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters' do
  values [{ name: 'RequireSecuritySignature', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.8.2_L1_Ensure_Microsoft_network_client_Digitally_sign_communications_if_server_agrees_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters' do
  values [{ name: 'EnableSecuritySignature', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.8.3_L1_Ensure_Microsoft_network_client_Send_unencrypted_password_to_third-party_SMB_servers_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters' do
  values [{ name: 'EnablePlainTextPassword', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.9.1_L1_Ensure_Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session_is_set_to_15_or_fewer_minutes_but_not_0
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters' do
  values [{ name: 'AutoDisconnect', type: :dword, data: 15 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.9.2_L1_Ensure_Microsoft_network_server_Digitally_sign_communications_always_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters' do
  values [{ name: 'RequireSecuritySignature', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.9.3_L1_Ensure_Microsoft_network_server_Digitally_sign_communications_if_client_agrees_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters' do
  values [{ name: 'EnableSecuritySignature', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.9.4_L1_Ensure_Microsoft_network_server_Disconnect_clients_when_logon_hours_expire_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters' do
  values [{ name: 'EnableForcedLogOff', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.9.5_L1_Ensure_Microsoft_network_server_Server_SPN_target_name_validation_level_is_set_to_Accept_if_provided_by_client_or_higher_MS_only
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters' do
  values [{ name: 'SMBServerNameHardeningLevel', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.10.1_L1_Ensure_Network_access_Allow_anonymous_SIDName_translation_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters' do
  values [{ name: 'LSAAnonymousNameLookup', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.10.2_L1_Ensure_Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_is_set_to_Enabled_MS_only
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa' do
  values [{ name: 'RestrictAnonymousSAM', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.10.3_L1_Ensure_Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares_is_set_to_Enabled_MS_only
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa' do
  values [{ name: 'RestrictAnonymous', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.10.5_L1_Ensure_Network_access_Let_Everyone_permissions_apply_to_anonymous_users_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa' do
  values [{ name: 'EveryoneIncludesAnonymous', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.10.7_L1_Configure_Network_access_Named_Pipes_that_can_be_accessed_anonymously_MS_only
execute 'registry_key[2.3.10.7]' do
  command 'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v NullSessionPipes /t REG_MULTI_SZ /f'
  not_if { ::File.exist?('C:\cis-level1-harden\NullSessionPipes.lock') }
  notifies :create, 'file[C:\cis-level1-harden\NullSessionPipes.lock]', :immediately
end

file 'C:\cis-level1-harden\NullSessionPipes.lock' do
  action :nothing
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.10.8_L1_Configure_Network_access_Remotely_accessible_registry_paths
execute 'registry_key[2.3.10.7]' do
  command 'reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths" /v Machine /t REG_MULTI_SZ /f'
  not_if { ::File.exist?('C:\cis-level1-harden\AllowedExactPaths.Machine.lock') }
  notifies :create, 'file[C:\cis-level1-harden\AllowedExactPaths.Machine.lock]', :immediately
end

file 'C:\cis-level1-harden\AllowedExactPaths.Machine.lock' do
  action :nothing
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.10.9_L1_Configure_Network_access_Remotely_accessible_registry_paths_and_sub-paths
execute 'registry_key[2.3.10.7]' do
  command 'reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths" /v Machine /t REG_MULTI_SZ /f'
  not_if { ::File.exist?('C:\cis-level1-harden\AllowedPaths.Machine.lock') }
  notifies :create, 'file[C:\cis-level1-harden\AllowedPaths.Machine.lock]', :immediately
end

file 'C:\cis-level1-harden\AllowedPaths.Machine.lock' do
  action :nothing
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.10.9_L1_Configure_Network_access_Remotely_accessible_registry_paths_and_sub-paths
# registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters' do
#   values [{ name: "NullSessionPipes", type: :multi_string, data:
#   'System\\CurrentControlSet\\Control\\Print\\Printers',
#   'System\\CurrentControlSet\\Services\\Eventlog',
#   'Software\\Microsoft\\OLAP Server',
#   'Software\\Microsoft\\Windows NT\\CurrentVersion\\Print',
#   'Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows',
#   'System\\CurrentControlSet\\Control\\ContentIndex',
#   'System\\CurrentControlSet\\Control\\Terminal Server',
#   'System\\CurrentControlSet\\Control\\Terminal Server\\UserConfig',
#   'System\\CurrentControlSet\\Control\\Terminal Server\\DefaultUserConfiguration',
#   'Software\\Microsoft\\Windows NT\\CurrentVersion\\Perflib',
#   'System\\CurrentControlSet\\Services\\SysmonLog',
#   'System\\CurrentControlSet\\Services\\CertSvc',
#   'System\\CurrentControlSet\\Services\\WINS' }]
#   action :create
# end

# xccdf_org.cisecurity.benchmarks_rule_2.3.10.11_L1_Ensure_Network_access_Restrict_clients_allowed_to_make_remote_calls_to_SAM_is_set_to_Administrators_Remote_Access_Allow_MS_only
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa' do
  values [{ name: 'restrictremotesam', type: :string, data: 'O:BAG:BAD:(A;;RC;;;BA)' }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.10.12_L1_Ensure_Network_access_Shares_that_can_be_accessed_anonymously_is_set_to_None
execute 'registry_key[2.3.10.7]' do
  command 'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v NullSessionShares /t REG_MULTI_SZ /f'
  not_if { ::File.exist?('C:\cis-level1-harden\NullSessionShares.lock') }
  notifies :create, 'file[C:\cis-level1-harden\NullSessionShares.lock]', :immediately
end

file 'C:\cis-level1-harden\NullSessionShares.lock' do
  action :nothing
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.11.1_L1_Ensure_Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa' do
  values [{ name: 'UseMachineId', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.11.2_L1_Ensure_Network_security_Allow_LocalSystem_NULL_session_fallback_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0' do
  values [{ name: 'AllowNullSessionFallback', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.11.3_L1_Ensure_Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\pku2u' do
  values [{ name: 'AllowOnlineID', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.11.4_L1_Ensure_Network_security_Configure_encryption_types_allowed_for_Kerberos_is_set_to_AES128_HMAC_SHA1_AES256_HMAC_SHA1_Future_encryption_types
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters' do
  values [{ name: 'SupportedEncryptionTypes', type: :dword, data: 2147483644 }]
  action :create
  recursive true
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.11.5_L1_Ensure_Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa' do
  values [{ name: 'NoLMHash', type: :dword, data: 1 }]
  action :create
end

# # xccdf_org.cisecurity.benchmarks_rule_2.3.11.6_L1_Ensure_Network_security_Force_logoff_when_logon_hours_expire_is_set_to_Enabled
# registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa' do
#   values [{ name: "NoLMHash", type: :dword, data: 1 }]
#   action :create
# end

# xccdf_org.cisecurity.benchmarks_rule_2.3.11.7_L1_Ensure_Network_security_LAN_Manager_authentication_level_is_set_to_Send_NTLMv2_response_only._Refuse_LM__NTLM
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa' do
  values [{ name: 'LmCompatibilityLevel', type: :dword, data: 5 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.11.8_L1_Ensure_Network_security_LDAP_client_signing_requirements_is_set_to_Negotiate_signing_or_higher
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LDAP' do
  values [{ name: 'LDAPClientIntegrity', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.11.9_L1_Ensure_Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients_is_set_to_Require_NTLMv2_session_security_Require_128-bit_encryption
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0' do
  values [{ name: 'NTLMMinClientSec', type: :dword, data: 537395200 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.11.10_L1_Ensure_Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers_is_set_to_Require_NTLMv2_session_security_Require_128-bit_encryption
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0' do
  values [{ name: 'NTLMMinServerSec', type: :dword, data: 537395200 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.13.1_L1_Ensure_Shutdown_Allow_system_to_be_shut_down_without_having_to_log_on_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{ name: 'ShutdownWithoutLogon', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.15.1_L1_Ensure_System_objects_Require_case_insensitivity_for_non-Windows_subsystems_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\Kernel' do
  values [{ name: 'ObCaseInsensitive', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.15.2_L1_Ensure_System_objects_Strengthen_default_permissions_of_internal_system_objects_e.g._Symbolic_Links_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager' do
  values [{ name: 'ProtectionMode', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.17.1_L1_Ensure_User_Account_Control_Admin_Approval_Mode_for_the_Built-in_Administrator_account_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{ name: 'FilterAdministratorToken', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.17.2_L1_Ensure_User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{ name: 'EnableUIADesktopToggle', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.17.3_L1_Ensure_User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode_is_set_to_Prompt_for_consent_on_the_secure_desktop
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{ name: 'ConsentPromptBehaviorAdmin', type: :dword, data: 2 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.17.4_L1_Ensure_User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users_is_set_to_Automatically_deny_elevation_requests
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{ name: 'ConsentPromptBehaviorUser', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.17.5_L1_Ensure_User_Account_Control_Detect_application_installations_and_prompt_for_elevation_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{ name: 'EnableInstallerDetection', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.17.6_L1_Ensure_User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{ name: 'EnableSecureUIAPaths', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.17.7_L1_Ensure_User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{ name: 'EnableLUA', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.17.8_L1_Ensure_User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{ name: 'PromptOnSecureDesktop', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.17.9_L1_Ensure_User_Account_Control_Virtualize_file_and_registry_write_failures_to_per-user_locations_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{ name: 'EnableVirtualization', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.1.3_L1_Ensure_Accounts_Guest_account_status_is_set_to_Disabled_MS_only
powershell_script 'Disable guest account' do
  code 'net user guest /active:no'
  action :run
  only_if "(net user guest | Select-String -Pattern 'Account active.*Yes') -ne $null"
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.1.4_L1_Ensure_Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa' do
  values [{ name: 'LimitBlankPasswordUse', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.1.5_L1_Configure_Accounts_Rename_administrator_account
powershell_script 'Rename Administrator Account' do
  code <<-EOH
  Rename-LocalUser -Name "Administrator" -NewName "local-admin"
  EOH
  only_if '((Get-LocalUser -Name "Administrator").Name -eq "administrator")'
end

# xccdf_org.cisecurity.benchmarks_rule_2.3.1.6_L1_Configure_Accounts_Rename_guest_account
powershell_script 'Rename Guest Account' do
  code <<-EOH
  Rename-LocalUser -Name "Guest" -NewName "Guuest"
  EOH
  only_if '((Get-LocalUser -Name "Guest").Name -eq "Guest")'
end
