#
# Cookbook:: cb-cis-level1-win2016-member
# Recipe:: default
#
# Copyright:: 2020, The Authors, All Rights Reserved.

return unless node['platform_family'] == 'windows'

include_recipe 'cb-cis-level1-win2016-member::security_policy'
include_recipe 'cb-cis-level1-win2016-member::section_2'
include_recipe 'cb-cis-level1-win2016-member::section_9'
include_recipe 'cb-cis-level1-win2016-member::section_17'
include_recipe 'cb-cis-level1-win2016-member::section_18'
include_recipe 'cb-cis-level1-win2016-member::section_19'
