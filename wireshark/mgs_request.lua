local util = require('util')
local protofields = require('protofields')

local M = {}

M.dissect_discover = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsRequest discover')
end

M.dissect_ignition_state = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsRequest ignition_state')
end

M.dissect_bulk_ignition_state = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsRequest bulk_ignition_state')
end

M.dissect_ignition_command = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsRequest ignition_command')
end

M.dissect_sp_state = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsRequest sp_state')
end

M.dissect_serial_console_attach = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsRequest serial_console_attach')
end

M.dissect_serial_console_write = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsRequest serial_console_write')
end

M.dissect_serial_console_detach = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsRequest serial_console_detach')
end

M.dissect_sp_update_prepare = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsRequest sp_update_prepare')
end

M.dissect_component_update_prepare = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsRequest component_update_prepare')
end

M.dissect_update_chunk = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsRequest update_chunk')
end

M.dissect_update_status = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsRequest update_status')
end

M.dissect_update_abort = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsRequest update_abort')
end

M.dissect_get_power_state = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsRequest get_power_state')
end

M.dissect_set_power_state = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsRequest set_power_state')
end

M.dissect_reset_prepare = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsRequest reset_prepare')
end

M.dissect_reset_trigger = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsRequest reset_trigger')
end

M.dissect_inventory = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsRequest inventory')
end

M.dissect_get_startup_options = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsRequest get_startup_options')
end

M.dissect_set_startup_options = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsRequest set_startup_options')
end

M.dissect_component_details = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsRequest component_details')
end

M.dissect_ignition_link_events = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsRequest ignition_link_events')
end

M.dissect_bulk_ignition_link_events = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsRequest bulk_ignition_link_events')
end

M.dissect_clear_ignition_link_events = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsRequest clear_ignition_link_events')
end

M.dissect_component_clear_status = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsRequest component_clear_status')
end

M.dissect_component_get_active_slot = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsRequest component_get_active_slot')
end

M.dissect_component_set_active_slot = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsRequest component_set_active_slot')
end

M.dissect_serial_console_break = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsRequest serial_console_break')
end

M.dissect_send_host_nmi = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsRequest send_host_nmi')
end

M.dissect_set_ipcc_key_lookup_value = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsRequest set_ipcc_key_lookup_value')
end

M.dissect_component_set_and_persist_active_slot = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsRequest component_set_and_persist_active_slot')
end

M.dissect_read_caboose = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsRequest read_caboose')
end

M.dissect_serial_console_keep_alive = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsRequest serial_console_keep_alive')
end

M.dissect_reset_component_prepare = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsRequest reset_component_prepare')
end

M.dissect_reset_component_trigger = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsRequest reset_component_trigger')
end

M.dissect_switch_default_image = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsRequest switch_default_image')
end

M.dissect_component_action = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsRequest component_action')
end

M.dissect_read_component_caboose = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsRequest read_component_caboose')
end

M.dissect_read_sensor = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsRequest read_sensor')
end

M.dissect_current_time = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsRequest current_time')
end

M.dissect_read_rot = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsRequest read_rot')
end

M.dissect_vpd_lock_state = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsRequest vpd_lock_state')
end

M.dissect_reset_component_trigger_with_watchdog = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsRequest reset_component_trigger_with_watchdog')
end

M.dissect_disable_component_watchdog = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsRequest disable_component_watchdog')
end

M.dissect_component_watchdog_supported = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsRequest component_watchdog_supported')
end

M.dissect_versioned_rot_boot_info = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsRequest versioned_rot_boot_info')
end

M.dissect_dump = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsRequest dump')
end

return M
