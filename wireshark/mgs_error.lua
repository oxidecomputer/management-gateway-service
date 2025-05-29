local util = require('util')
local protofields = require('protofields')
local extra_fields = require('extra_fields')

local M = {}

M.dissect_bad_request = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsError bad_request')
end

M.dissect_host_phase2_unavailable = function(buffer, pinfo, tree)
    local buffer_len = buffer:len()

    if buffer_len == 32 then
        tree:add(extra_fields.phase2_hash, buffer(0))
    else
        tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Expected 32-byte hash")
    end
end

M.dissect_host_phase2_image_bad_offset = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsError host_phase2_image_bad_offset')
end

return M
