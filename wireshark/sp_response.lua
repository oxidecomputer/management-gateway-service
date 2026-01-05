-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

local util = require('util')
local protofields = require('protofields')
local sp_error = require('sp_error')

local M = {}

M.dissect_discover = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpResponse discover')
end

M.dissect_ignition_state = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpResponse ignition_state')
end

M.dissect_bulk_ignition_state = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpResponse bulk_ignition_state')
end

M.dissect_ignition_command_ack = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpResponse ignition_command_ack')
end

M.dissect_sp_state = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpResponse sp_state')
end

M.dissect_sp_update_prepare_ack = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpResponse sp_update_prepare_ack')
end

M.dissect_component_update_prepare_ack = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpResponse component_update_prepare_ack')
end

M.dissect_update_chunk_ack = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpResponse update_chunk_ack')
end

M.dissect_update_status = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpResponse update_status')
end

M.dissect_update_abort_ack = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpResponse update_abort_ack')
end

M.dissect_serial_console_attach_ack = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpResponse serial_console_attach_ack')
end

M.dissect_serial_console_write_ack = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpResponse serial_console_write_ack')
end

M.dissect_serial_console_detach_ack = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpResponse serial_console_detach_ack')
end

M.dissect_power_state = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpResponse power_state')
end

M.dissect_power_state_set = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpResponse power_state_set')
end

M.dissect_reset_prepare_ack = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpResponse reset_prepare_ack')
end

M.dissect_inventory = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpResponse inventory')
end

M.dissect_error = function(buffer, pinfo, tree)
    util.dissect_hubpack_enum(buffer, pinfo, tree, protofields.sp_error, sp_error)
end

M.dissect_startup_options = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpResponse startup_options')
end

M.dissect_set_startup_options_ack = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpResponse set_startup_options_ack')
end

M.dissect_component_details = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpResponse component_details')
end

M.dissect_ignition_link_events = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpResponse ignition_link_events')
end

M.dissect_bulk_ignition_link_events = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpResponse bulk_ignition_link_events')
end

M.dissect_clear_ignition_link_events_ack = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpResponse clear_ignition_link_events_ack')
end

M.dissect_component_clear_status_ack = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpResponse component_clear_status_ack')
end

M.dissect_component_active_slot = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpResponse component_active_slot')
end

M.dissect_component_set_active_slot_ack = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpResponse component_set_active_slot_ack')
end

M.dissect_component_persistent_slot = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpResponse component_persistent_slot')
end

M.dissect_serial_console_break_ack = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpResponse serial_console_break_ack')
end

M.dissect_send_host_nmi_ack = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpResponse send_host_nmi_ack')
end

M.dissect_set_ipcc_key_lookup_value_ack = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpResponse set_ipcc_key_lookup_value_ack')
end

M.dissect_component_set_and_persist_active_slot_ack = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpResponse component_set_and_persist_active_slot_ack')
end

M.dissect_caboose_value = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpResponse caboose_value')
end

M.dissect_serial_console_keep_alive_ack = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpResponse serial_console_keep_alive_ack')
end

M.dissect_reset_component_prepare_ack = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpResponse reset_component_prepare_ack')
end

M.dissect_reset_component_trigger_ack = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpResponse reset_component_trigger_ack')
end

M.dissect_switch_default_image_ack = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpResponse switch_default_image_ack')
end

M.dissect_component_action_ack = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpResponse component_action_ack')
end

M.dissect_sp_state_v2 = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpResponse sp_state_v2')
end

M.dissect_read_sensor = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpResponse read_sensor')
end

M.dissect_current_time = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpResponse current_time')
end

M.dissect_read_rot = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpResponse read_rot')
end

M.dissect_vpd_lock_state = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpResponse vpd_lock_state')
end

M.dissect_disable_component_watchdog_ack = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpResponse disable_component_watchdog_ack')
end

M.dissect_component_watchdog_supported_ack = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpResponse component_watchdog_supported_ack')
end

M.dissect_sp_state_v3 = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpResponse sp_state_v3')
end

M.dissect_rot_boot_info = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpResponse rot_boot_info')
end

M.dissect_component_action = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpResponse component_action')
end

M.dissect_dump = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpResponse dump')
end

M.dissect_power_state_unchanged = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpResponse power_state_unchanged')
end


return M
