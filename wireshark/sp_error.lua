local util = require('util')
local protofields = require('protofields')

local M = {}

M.dissect_busy = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpError busy')
end

M.dissect_bad_request = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpError bad_request')
end

M.dissect_request_unsupported_for_sp = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpError request_unsupported_for_sp')
end

M.dissect_request_unsupported_for_component = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpError request_unsupported_for_component')
end

M.dissect_ignition = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpError ignition')
end

M.dissect_serial_console_not_attached = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpError serial_console_not_attached')
end

M.dissect_serial_console_already_attached = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpError serial_console_already_attached')
end

M.dissect_other_component_update_in_progress = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpError other_component_update_in_progress')
end

M.dissect_update_not_prepared = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpError update_not_prepared')
end

M.dissect_invalid_update_id = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpError invalid_update_id')
end

M.dissect_update_in_progress = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpError update_in_progress')
end

M.dissect_invalid_update_chunk = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpError invalid_update_chunk')
end

M.dissect_update_failed = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpError update_failed')
end

M.dissect_update_slot_busy = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpError update_slot_busy')
end

M.dissect_power_state_error = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpError power_state_error')
end

M.dissect_reset_trigger_without_prepare = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpError reset_trigger_without_prepare')
end

M.dissect_invalid_slot_for_component = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpError invalid_slot_for_component')
end

M.dissect_component_operation_failed = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpError component_operation_failed')
end

M.dissect_update_is_too_large = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpError update_is_too_large')
end

M.dissect_set_ipcc_key_lookup_value_failed = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpError set_ipcc_key_lookup_value_failed')
end

M.dissect_no_caboose = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpError no_caboose')
end

M.dissect_no_such_caboose_key = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpError no_such_caboose_key')
end

M.dissect_caboose_value_overflow = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpError caboose_value_overflow')
end

M.dissect_caboose_read_error = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpError caboose_read_error')
end

M.dissect_bad_caboose_checksum = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpError bad_caboose_checksum')
end

M.dissect_image_board_unknown = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpError image_board_unknown')
end

M.dissect_image_board_mismatch = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpError image_board_mismatch')
end

M.dissect_reset_component_trigger_without_prepare = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpError reset_component_trigger_without_prepare')
end

M.dissect_switch_default_image_error = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpError switch_default_image_error')
end

M.dissect_sprot = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpError sprot')
end

M.dissect_spi = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpError spi')
end

M.dissect_sprockets = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpError sprockets')
end

M.dissect_update = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpError update')
end

M.dissect_sensor = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpError sensor')
end

M.dissect_vpd = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpError vpd')
end

M.dissect_watchdog = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpError watchdog')
end

M.dissect_monorail = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpError monorail')
end

M.dissect_dump = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpError dump')
end

return M
