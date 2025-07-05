-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

local util = require('util')
local protofields = require('protofields')
local mgs_error = require('mgs_error')

local M = {}

M.dissect_error = function(buffer, pinfo, tree)
    util.dissect_hubpack_enum(buffer, pinfo, tree, protofields.mgs_error, mgs_error)
end

M.dissect_host_phase2_data = function(buffer, pinfo, tree)
    tree:add(buffer, 'TODO: parse MgsResponse host_phase2_data')
end

return M
