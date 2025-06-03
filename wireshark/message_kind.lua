-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

local util = require('util')
local protofields = require('protofields')
local mgs_request = require('mgs_request')
local mgs_response = require('mgs_response')
local sp_request = require('sp_request')
local sp_response = require('sp_response')

local M = {}

M.dissect_mgs_request = function(buffer, pinfo, tree)
    util.dissect_hubpack_enum(buffer, pinfo, tree, protofields.mgs_request, mgs_request)
end

M.dissect_mgs_response = function(buffer, pinfo, tree)
    util.dissect_hubpack_enum(buffer, pinfo, tree, protofields.mgs_response, mgs_response)
end

M.dissect_sp_request = function(buffer, pinfo, tree)
    util.dissect_hubpack_enum(buffer, pinfo, tree, protofields.sp_request, sp_request)
end

M.dissect_sp_response = function(buffer, pinfo, tree)
    util.dissect_hubpack_enum(buffer, pinfo, tree, protofields.sp_response, sp_response)
end

return M
