-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

local util = require('util')
local protofields = require('protofields')
local extra_fields = require('extra_fields')

local M = {}

M.dissect_serial_console = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse SpRequest serial_console')
end

M.dissect_host_phase2_data = function(buffer, pinfo, tree)
    local buffer_len = buffer:len()

    if buffer_len == 40 then
        tree:add(extra_fields.phase2_hash, buffer(0, 32))
        tree:add(extra_fields.phase2_offset, buffer(32, 8))
    else
        tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Expected 40 bytes")
    end
end

return M
