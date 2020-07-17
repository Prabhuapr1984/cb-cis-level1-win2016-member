# Cookbook:: cb-cis-level1-win2016-member
# Recipe:: section_18
#
# Copyright:: 2019, The Authors, All Rights Reserved.

# xccdf_org.cisecurity.benchmarks_rule_18.1.1.1_L1_Ensure_Prevent_enabling_lock_screen_camera_is_set_to_Enabled
# xccdf_org.cisecurity.benchmarks_rule_18.1.1.2_L1_Ensure_Prevent_enabling_lock_screen_slide_show_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Personalization' do
  values [{ name: 'NoLockScreenCamera', type: :dword, data: 1 }, { name: 'NoLockScreenSlideshow', type: :dword, data: 1 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.1.2.2_L1_Ensure_Allow_input_personalization_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\InputPersonalization' do
  values [{ name: 'AllowInputPersonalization', type: :dword, data: 0 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.1.2.2_L1_Ensure_Allow_input_personalization_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\InputPersonalization' do
  values [{ name: 'AllowInputPersonalization', type: :dword, data: 0 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.2.1_L1_Ensure_LAPS_AdmPwd_GPO_Extension__CSE_is_installed_MS_only
windows_package 'LAPS_AdmPwd_GPO_Extension' do
  source 'https://download.microsoft.com/download/C/7/A/C7AAD914-A8A6-4904-88A1-29E657445D03/LAPS.x64.msi'
  installer_type :custom
  options '/quiet'
end

# xccdf_org.cisecurity.benchmarks_rule_18.2.2_L1_Ensure_Do_not_allow_password_expiration_time_longer_than_required_by_policy_is_set_to_Enabled_MS_only
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd' do
  values [{ name: 'PwdExpirationProtectionEnabled', type: :dword, data: 1 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.2.3_L1_Ensure_Enable_Local_Admin_Password_Management_is_set_to_Enabled_MS_only
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd' do
  values [{ name: 'AdmPwdEnabled', type: :dword, data: 1 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.2.4_L1_Ensure_Password_Settings_Password_Complexity_is_set_to_Enabled_Large_letters__small_letters__numbers__special_characters_MS_only
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd' do
  values [{ name: 'PasswordComplexity', type: :dword, data: 4 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.2.5_L1_Ensure_Password_Settings_Password_Length_is_set_to_Enabled_15_or_more_MS_only
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd' do
  values [{ name: 'PasswordLength', type: :dword, data: 15 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.2.6_L1_Ensure_Password_Settings_Password_Age_Days_is_set_to_Enabled_30_or_fewer_MS_only
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd' do
  values [{ name: 'PasswordAgeDays', type: :dword, data: 30 }]
  recursive true
  action :create
end

# 18.3.1 (L1) Ensure 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled' (MS only) (Scored)
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{ name: 'LocalAccountTokenFilterPolicy', type: :dword, data: 0 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.3.2_L1_Ensure_Configure_SMB_v1_client_driver_is_set_to_Enabled_Disable_driver
registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\mrxsmb10' do
  values [{ name: 'Start', type: :string, data: 4 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.3.3_L1_Ensure_Configure_SMB_v1_server_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' do
  values [{ name: 'SMB1', type: :string, data: 0 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.3.4_L1_Ensure_Enable_Structured_Exception_Handling_Overwrite_Protection_SEHOP_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel' do
  values [{ name: 'DisableExceptionChainValidation', type: :string, data: 0 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.3.5_L1_Ensure_Turn_on_Windows_Defender_protection_against_Potentially_Unwanted_Applications_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\MpEngine' do
  values [{ name: 'MpEnablePus', type: :dword, data: 1 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.3.6_L1_Ensure_WDigest_Authentication_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' do
  values [{ name: 'UseLogonCredential', type: :string, data: 0 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.4.1_L1_Ensure_MSS_AutoAdminLogon_Enable_Automatic_Logon_not_recommended_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' do
  values [{ name: 'AutoAdminLogon', type: :string, data: '0' }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.4.2_L1_Ensure_MSS_DisableIPSourceRouting_IPv6_IP_source_routing_protection_level_protects_against_packet_spoofing_is_set_to_Enabled_Highest_protection_source_routing_is_completely_disabled
registry_key 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip6\Parameters' do
  values [{ name: 'DisableIPSourceRouting', type: :dword, data: 2 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.4.3_L1_Ensure_MSS_DisableIPSourceRouting_IP_source_routing_protection_level_protects_against_packet_spoofing_is_set_to_Enabled_Highest_protection_source_routing_is_completely_disabled
registry_key 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters' do
  values [{ name: 'DisableIPSourceRouting', type: :dword, data: 2 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.4.4_L1_Ensure_MSS_EnableICMPRedirect_Allow_ICMP_redirects_to_override_OSPF_generated_routes_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters' do
  values [{ name: 'EnableICMPRedirect', type: :dword, data: 0 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.4.6_L1_Ensure_MSS_NoNameReleaseOnDemand_Allow_the_computer_to_ignore_NetBIOS_name_release_requests_except_from_WINS_servers_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NetBT\Parameters' do
  values [{ name: 'nonamereleaseondemand', type: :dword, data: 1 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.4.8_L1_Ensure_MSS_SafeDllSearchMode_Enable_Safe_DLL_search_mode_recommended_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager' do
  values [{ name: 'SafeDllSearchMode', type: :dword, data: 1 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.4.9_L1_Ensure_MSS_ScreenSaverGracePeriod_The_time_in_seconds_before_the_screen_saver_grace_period_expires_0_recommended_is_set_to_Enabled_5_or_fewer_seconds
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' do
  values [{ name: 'ScreenSaverGracePeriod', type: :dword, data: 5 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.4.12_L1_Ensure_MSS_WarningLevel_Percentage_threshold_for_the_security_event_log_at_which_the_system_will_generate_a_warning_is_set_to_Enabled_90_or_less
registry_key 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Eventlog\\Security' do
  values [{ name: 'WarningLevel', type: :dword, data: 90 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.5.4.1_L1_Set_NetBIOS_node_type_to_P-node_Ensure_NetBT_Parameter_NodeType_is_set_to_0x2_2_MS_Only
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netbt\\Parameters' do
  values [{ name: 'NodeType', type: :dword, data: 2 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.5.4.2_L1_Ensure_Turn_off_multicast_name_resolution_is_set_to_Enabled_MS_Only
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' do
  values [{ name: 'EnableMulticast', type: :dword, data: 0 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.5.8.1_L1_Ensure_Enable_insecure_guest_logons_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\LanmanWorkstation' do
  values [{ name: 'AllowInsecureGuestAuth', type: :dword, data: 0 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.5.11.2_L1_Ensure_Prohibit_installation_and_configuration_of_Network_Bridge_on_your_DNS_domain_network_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Network Connections' do
  values [{ name: 'NC_AllowNetBridge_NLA', type: :dword, data: 0 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.5.11.3_L1_Ensure_Prohibit_use_of_Internet_Connection_Sharing_on_your_DNS_domain_network_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Network Connections' do
  values [{ name: 'NC_ShowSharedAccessUI', type: :dword, data: 0 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.5.11.4_L1_Ensure_Require_domain_users_to_elevate_when_setting_a_networks_location_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Network Connections' do
  values [{ name: 'NC_StdDomainUserSetLocation', type: :dword, data: 1 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.5.14.1_L1_Ensure_Hardened_UNC_Paths_is_set_to_Enabled_with_Require_Mutual_Authentication_and_Require_Integrity_set_for_all_NETLOGON_and_SYSVOL_shares:
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths' do
  values [{ name: '\\\\*\\SYSVOL', type: :string, data: 'RequireMutualAuthentication=1, RequireIntegrity=1' }, { name: '\\\\*\\NETLOGON', type: :string, data: 'RequireMutualAuthentication=1, RequireIntegrity=1' }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.5.21.1_L1_Ensure_Minimize_the_number_of_simultaneous_connections_to_the_Internet_or_a_Windows_Domain_is_set_to_Enabled:
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WcmSvc\\GroupPolicy' do
  values [{ name: 'fMinimizeConnections', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.8.3.1_L1_Ensure_Include_command_line_in_process_creation_events_is_set_to_Disable
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit' do
  values [{ name: 'ProcessCreationIncludeCmdLine_Enabled', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.8.4.1_L1_Ensure_Remote_host_allows_delegation_of_non-exportable_credentials_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation' do
  values [{ name: 'AllowProtectedCreds', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.8.14.1_L1_Ensure_Boot-Start_Driver_Initialization_Policy_is_set_to_Enabled_Good_unknown_and_bad_but_critical:
registry_key 'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Policies\\EarlyLaunch' do
  values [{ name: 'DriverLoadPolicy', type: :dword, data: 3 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.8.21.2_L1_Ensure_Configure_registry_policy_processing_Do_not_apply_during_periodic_background_processing_is_set_to_Enabled_FALSE:
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Group Policy\\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}' do
  values [{ name: 'NoBackgroundPolicy', type: :dword, data: 0 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.8.21.3_L1_Ensure_Configure_registry_policy_processing_Do_not_apply_during_periodic_background_processing_is_set_to_Enabled_FALSE:
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Group Policy\\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}' do
  values [{ name: 'NoGPOListChanges', type: :dword, data: 0 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.8.21.4__L1_Ensure_Continue_experiences_on_this_device_is_set_to_Disabled:
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System' do
  values [{ name: 'EnableCdp', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.8.21.5_L1_Ensure_Turn_off_background_refresh_of_Group_Policy_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{ name: 'DisableBkGndGroupPolicy', type: :dword, data: 0 }]
  action :delete
end

# xccdf_org.cisecurity.benchmarks_rule_18.8.22.1.1_L1_Ensure_Turn_off_downloading_of_print_drivers_over_HTTP_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Printers' do
  values [{ name: 'DisableWebPnPDownload', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.8.22.1.5_L1_Ensure_Turn_off_downloading_of_print_drivers_over_HTTP_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' do
  values [{ name: 'NoWebServices', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.8.22.1.6_L1_Ensure_Turn_off_printing_over_HTTP_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Printers' do
  values [{ name: 'DisableHTTPPrinting', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.8.27.1_L1_Ensure_Block_user_from_showing_account_details_on_sign-in_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System' do
  values [{ name: 'BlockUserFromShowingAccountDetailsOnSignin', type: :dword, data: 1
  }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.8.27.2_L1_Ensure_Do_not_display_network_selection_UI_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System' do
  values [{ name: 'DontDisplayNetworkSelectionUI', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.8.27.3_L1_Ensure_Do_not_enumerate_connected_users_on_domain-joined_computers_is_set_to_Enabled:
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System' do
  values [{ name: 'DontEnumerateConnectedUsers', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.8.27.4_L1_Ensure_Do_not_enumerate_connected_users_on_domain-joined_computers_is_set_to_Enabled:
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System' do
  values [{ name: 'EnumerateLocalUsers', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.8.27.5_L1_Ensure_Turn_off_app_notifications_on_the_lock_screen_is_set_to_Enabled:
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System' do
  values [{ name: 'DisableLockScreenAppNotifications', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.8.27.6_L1_Ensure_Turn_off_picture_password_sign-in_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System' do
  values [{ name: 'BlockDomainPicturePassword', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.8.27.7_L1_Ensure_Turn_on_convenience_PIN_sign-in_is_set_to_Disabled:
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System' do
  values [{ name: 'AllowDomainPINLogon', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.8.28.1_L1_Ensure_Untrusted_Font_Blocking_is_set_to_Enabled_Block_untrusted_fonts_and_log_events:
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\MitigationOptions' do
  values [{ name: 'MitigationOptions_FontBocking', type: :string, data: '1000000000000' }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.8.33.6.3_L1_Ensure_Untrusted_Font_Blocking_is_set_to_Enabled_Block_untrusted_fonts_and_log_events:
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51' do
  values [{ name: 'DCSettingIndex', type: :string, data: '1' }]
  action :create
  recursive true
end

# xccdf_org.cisecurity.benchmarks_rule_18.8.33.6.4_L1_Ensure_Require_a_password_when_a_computer_wakes_plugged_in_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51' do
  values [{ name: 'ACSettingIndex', type: :string, data: '1' }]
  action :create
  recursive true
end

# xccdf_org.cisecurity.benchmarks_rule_18.8.35.1_L1_Ensure_Configure_Offer_Remote_Assistance_is_set_to_Disabled:
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services' do
  values [{ name: 'fAllowUnsolicited', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.8.35.2_L1_Ensure_Configure_Solicited_Remote_Assistance_is_set_to_Disabled:
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services' do
  values [{ name: 'fAllowToGetHelp', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.8.36.1_L1_Ensure_Enable_RPC_Endpoint_Mapper_Client_Authentication_is_set_to_Enabled_MS_only:
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Rpc' do
  values [{ name: 'EnableAuthEpResolution', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.6.1_L1_Ensure_Allow_Microsoft_accounts_to_be_optional_is_set_to_Enabled:
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' do
  values [{ name: 'MSAOptional', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.8.1_L1_Ensure_Disallow_Autoplay_for_non-volume_devices_is_set_to_Enabled:
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Explorer' do
  values [{ name: 'NoAutoplayfornonVolume', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.8.2_L1_Ensure_Set_the_default_behavior_for_AutoRun_is_set_to_Enabled_Do_not_execute_any_autorun_commands:
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' do
  values [{ name: 'NoAutorun', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.8.3_L1_Ensure_Turn_off_Autoplay_is_set_to_Enabled_All_drives
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' do
  values [{ name: 'NoDriveTypeAutoRun', type: :dword, data: 255 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.80.1.1_L1_Ensure_Configure_Windows_Defender_SmartScreen_is_set_to_Enabled_Warn_and_prevent_bypass
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System' do
  values [{ name: 'ShellSmartScreenLevel', type: :string, data: 'Block' }, { name: 'EnableSmartScreen', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.10.1.1_L1_Ensure_Use_enhanced_anti-spoofing_when_available_is_set_to_Enabled:
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Biometrics\\FacialFeatures' do
  values [{ name: 'EnhancedAntiSpoofing', type: :dword, data: 1 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.101.1.1_L1_Ensure_Manage_preview_builds_is_set_to_Enabled_Disable_preview_builds
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate' do
  values [{ name: 'ManagePreviewBuilds', type: :dword, data: 1 }, { name: 'ManagePreviewBuildsPolicyValue', type: :dword, data: 0 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.101.1.2_L1_Ensure_Select_when_Preview_Builds_and_Feature_Updates_are_received_is_set_to_Enabled_Semi-Annual_Channel_180_or_more_days
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate' do
  values [{ name: 'DeferFeatureUpdates', type: :dword, data: 1 },
          { name: 'BranchReadinessLevel', type: :dword, data: 32 },
          { name: 'DeferFeatureUpdatesPeriodInDays', type: :dword, data: 180 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.101.1.3_L1_Ensure_Select_when_Quality_Updates_are_received_is_set_to_Enabled_0_days
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate' do
  values [{ name: 'DeferQualityUpdates', type: :dword, data: 1 },
          { name: 'DeferQualityUpdatesPeriodInDays', type: :dword, data: 0 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.101.2_L1_Ensure_Configure_Automatic_Updates_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' do
  values [{ name: 'NoAutoUpdate', type: :dword, data: 0 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.101.3_L1_Ensure_Configure_Automatic_Updates_Scheduled_install_day_is_set_to_0_-_Every_day
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' do
  values [{ name: 'ScheduledInstallDay', type: :dword, data: 0 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.101.4_L1_Ensure_No_auto-restart_with_logged_on_users_for_scheduled_automatic_updates_installations_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' do
  values [{ name: 'NoAutoRebootWithLoggedOnUsers', type: :dword, data: 0 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.13.1_L1_Ensure_Turn_off_Microsoft_consumer_experiences_is_set_to_Enabled:
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\CloudContent' do
  values [{ name: 'DisableWindowsConsumerFeatures', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.14.1_L1_Ensure_Require_pin_for_pairing_is_set_to_Enabled:
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Connect' do
  values [{ name: 'RequirePinForPairing', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.15.1_L1_Ensure_Do_not_display_the_password_reveal_button_is_set_to_Enabled:
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\CredUI' do
  values [{ name: 'DisablePasswordReveal', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.15.2_L1_Ensure_Enumerate_administrator_accounts_on_elevation_is_set_to_Disabled:
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\CredUI' do
  values [{ name: 'EnumerateAdministrators', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.16.1_L1_Ensure_Allow_Telemetry_is_set_to_Enabled_0_-_Security_Enterprise_Only:
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\DataCollection' do
  values [{ name: 'AllowTelemetry', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.16.3_L1_Ensure_Disable_pre-release_features_or_settings_is_set_to_Disabled:
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PreviewBuilds' do
  values [{ name: 'EnableConfigFlighting', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.16.4_L1_Ensure_Do_not_show_feedback_notifications_is_set_to_Enabled:
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection' do
  values [{ name: 'DoNotShowFeedbackNotifications', type: :dword, data: 1
  }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.16.5_L1_Ensure_Toggle_user_control_over_Insider_builds_is_set_to_Disabled:
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PreviewBuilds' do
  values [{ name: 'AllowBuildPreview', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.26.1.1_L1_Ensure_Application_Control_Event_Log_behavior_when_the_log_file_reaches_its_maximum_size_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Application' do
  values [{ name: 'Retention', type: :string, data: '0' }]
  action :create
  recursive true
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.26.1.2_L1_Ensure_Application_Control_Event_Log_behavior_when_the_log_file_reaches_its_maximum_size_is_set_to_Disabled:
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Application' do
  values [{ name: 'MaxSize', type: :dword, data: 32768 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.26.2.1_L1_Ensure_Security_Control_Event_Log_behavior_when_the_log_file_reaches_its_maximum_size_is_set_to_Disabled:
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Security' do
  values [{ name: 'Retention', type: :string, data: '0' }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.26.2.2_L1_Ensure_Security_Specify_the_maximum_log_file_size_KB_is_set_to_Enabled_196608_or_greater:
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Security' do
  values [{ name: 'MaxSize', type: :dword, data: 196608 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.26.3.1_L1_Ensure_Setup_Control_Event_Log_behavior_when_the_log_file_reaches_its_maximum_size_is_set_to_Disabled:
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Setup' do
  values [{ name: 'Retention', type: :string, data: '0' }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.26.3.2_L1_Ensure_Setup_Specify_the_maximum_log_file_size_KB_is_set_to_Enabled_32768_or_greater:
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Setup' do
  values [{ name: 'MaxSize', type: :dword, data: 32768 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.26.4.1_L1_Ensure_System_Control_Event_Log_behavior_when_the_log_file_reaches_its_maximum_size_is_set_to_Disabled:
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\System' do
  values [{ name: 'Retention', type: :string, data: '0' }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.26.4.2_L1_Ensure_System_Specify_the_maximum_log_file_size_KB_is_set_to_Enabled_32768_or_greater:
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\System' do
  values [{ name: 'MaxSize', type: :dword, data: 32768 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.30.2_L1_Ensure_Turn_off_Data_Execution_Prevention_for_Explorer_is_set_to_Disabled:
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Explorer' do
  values [{ name: 'NoDataExecutionPrevention', type: :dword, data: 0
  }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.30.3_L1_Ensure_Turn_off_heap_termination_on_corruption_is_set_to_Disabled:
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Explorer' do
  values [{ name: 'NoHeapTerminationOnCorruption', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.30.4_L1_Ensure_Turn_off_shell_protocol_protected_mode_is_set_to_Disabled:
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' do
  values [{ name: 'PreXPSP2ShellProtocolBehavior', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.44.1_L1_Ensure_Block_all_consumer_Microsoft_account_user_authentication_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\MicrosoftAccount' do
  values [{ name: 'DisableUserAuth', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.52.1_L1_Ensure_Do_not_allow_passwords_to_be_saved_is_set_to_Enabled:
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\OneDrive' do
  values [{ name: 'DisableFileSyncNGSC', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.52.2.2_L1_Ensure_Do_not_allow_passwords_to_be_saved_is_set_to_Enabled:
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' do
  values [{ name: 'DisablePasswordSaving', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.58.3.3.2_L1_Ensure_Do_not_allow_drive_redirection_is_set_to_Enabled:
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' do
  values [{ name: 'fDisableCdm', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.58.3.9.1_L1_Ensure_Set_client_connection_encryption_level_is_set_to_Enabled_High_Level:
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' do
  values [{ name: 'fPromptForPassword', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.58.3.9.2_L1_Ensure_Set_client_connection_encryption_level_is_set_to_Enabled_High_Level:
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' do
  values [{ name: 'fEncryptRPCTraffic', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.58.3.9.3_L1_Ensure_Set_client_connection_encryption_level_is_set_to_Enabled_High_Level:
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' do
  values [{ name: 'MinEncryptionLevel', type: :dword, data: 3 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.58.3.11.1_L1_Ensure_Do_not_delete_temp_folders_upon_exit_is_set_to_Disabled:
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services' do
  values [{ name: 'DeleteTempDirsOnExit', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.58.3.11.2_L1_Ensure_Do_not_use_temporary_folders_per_session_is_set_to_Disabled:
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services' do
  values [{ name: 'PerSessionTempDir', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.59.1_L1_Ensure_Prevent_downloading_of_enclosures_is_set_to_Enabled:
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Feeds' do
  values [{ name: 'DisableEnclosureDownload', type: :dword, data: 1 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.60.3_L1_Ensure_Allow_indexing_of_encrypted_files_is_set_to_Disabled:
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search' do
  values [{ name: 'AllowIndexingEncryptedStoresOrItems', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.76.3.1_L1_Ensure_Allow_indexing_of_encrypted_files_is_set_to_Disabled:
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet' do
  values [{ name: 'LocalSettingOverrideSpynetReporting', type: :dword, data: 0 }]
  action :create
  recursive true
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.76.7.1_L1_Ensure_Turn_on_behavior_monitoring_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection' do
  values [{ name: 'DisableBehaviorMonitoring', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.76.10.1_L1_Ensure_Scan_removable_drives_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan' do
  values [{ name: 'DisableRemovableDriveScanning', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.76.10.2_L1_Ensure_Turn_on_e-mail_scanning_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan' do
  values [{ name: 'DisableEmailScanning', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.76.13.1.1_L1_Ensure_Configure_Attack_Surface_Reduction_rules_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR' do
  values [{ name: 'ExploitGuard_ASR_Rules', type: :dword, data: 1 }]
  action :create
  recursive true
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.76.13.1.2_L1_Ensure_Configure_Attack_Surface_Reduction_rules_Set_the_state_for_each_ASR_rule_is_configured
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules' do
  values [{ name: '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84', type: :dword, data: 1 },
          { name: '3b576869-a4ec-4529-8536-b80a7769e899', type: :dword, data: 1 },
          { name: 'd4f940ab-401b-4efc-aadc-ad5f3c50688a', type: :dword, data: 1 },
          { name: '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b', type: :dword, data: 1 },
          { name: '5beb7efe-fd9a-4556-801d-275e5ffc04cc', type: :dword, data: 1 },
          { name: 'd3e037e1-3eb8-44c8-a917-57927947596d', type: :dword, data: 1 },
          { name: 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550', type: :dword, data: 1 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.76.13.3.1_L1_Ensure_Prevent_users_and_apps_from_accessing_dangerous_websites_is_set_to_Enabled_Block
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Network Protection' do
  values [{ name: 'EnableNetworkProtection', type: :dword, data: 1 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.76.14_L1_Ensure_Turn_off_Windows_Defender_AntiVirus_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender' do
  values [{ name: 'DisableAntiSpyware', type: :dword, data: 0 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.79.1.1_L1_Ensure_Prevent_users_from_modifying_settings_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\App and Browser protection' do
  values [{ name: 'DisallowExploitProtectionOverride', type: :dword, data: 1 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.84.2_L1_Ensure_Allow_Windows_Ink_Workspace_is_set_to_Enabled_On_but_disallow_access_above_lock_OR_Disabled_but_not_Enabled_On
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsInkWorkspace' do
  values [{ name: 'AllowWindowsInkWorkspace', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.85.1_L1_Ensure_Allow_user_control_over_installs_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' do
  values [{ name: 'EnableUserControl', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.85.2_L1_Ensure_Always_install_with_elevated_privileges_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' do
  values [{ name: 'AlwaysInstallElevated', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.86.1_L1_Ensure_Sign-in_last_interactive_user_automatically_after_a_system-initiated_restart_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\policies\\system' do
  values [{ name: 'DisableAutomaticRestartSignOn', type: :dword, data: 1 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.95.1_L1_Ensure_Turn_on_PowerShell_Script_Block_Logging_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' do
  values [{ name: 'EnableScriptBlockLogging', type: :dword, data: 0 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.95.2_L1_Ensure_Turn_on_PowerShell_Transcription_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription' do
  values [{ name: 'EnableTranscripting', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.97.1.1_L1_Ensure_Allow_Basic_authentication_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client' do
  values [{ name: 'AllowBasic', type: :dword, data: 0 }]
  recursive true
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.97.1.2_L1_Ensure_Allow_unencrypted_traffic_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client' do
  values [{ name: 'AllowUnencryptedTraffic', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.97.1.3_L1_Ensure_Disallow_Digest_authentication_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client' do
  values [{ name: 'AllowDigest', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.97.2.1_L1_Ensure_Allow_Basic_authentication_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service' do
  values [{ name: 'AllowBasic', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.97.2.3_L1_Ensure_Allow_unencrypted_traffic_is_set_to_Disabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service' do
  values [{ name: 'AllowUnencryptedTraffic', type: :dword, data: 0 }]
  action :create
end

# xccdf_org.cisecurity.benchmarks_rule_18.9.97.2.4_L1_Ensure_Disallow_WinRM_from_storing_RunAs_credentials_is_set_to_Enabled
registry_key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service' do
  values [{ name: 'DisableRunAs', type: :dword, data: 1 }]
  action :create
end
