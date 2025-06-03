-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

local mgs = Proto("mgs", "MGS <-> SP control-plane-agent UDP Protocol")

local util = require('util')
local protofields = require('protofields')
local extra_fields = require('extra_fields')
local dissectors = require('message_kind')

local f_version = ProtoField.uint32("mgs.version", "Protocol Version", base.DEC)
local f_message_id = ProtoField.uint32("mgs.message_id", "Message ID", base.HEX)
local f_kind = protofields.message_kind.field

-- Assemble _all_ the `ProtoField`s used by any module pulled in
-- as a part of this plugin. This includes:
--
-- * Our local fields (version and message_id)
-- * All the auto-generated fields (from `protofields.lua`)
-- * Manually-created extra field types (from `extra_fields.lua`)
mgs.fields = { f_version, f_message_id }
for k,v in pairs(protofields) do
    table.insert(mgs.fields, v.field)
end
for k,v in pairs(extra_fields) do
    table.insert(mgs.fields, v)
end

-- main dissector; peel out version and message ID, then
-- recurse into message-kind-specific dissector
function mgs.dissector(buffer, pinfo, tree)
    if buffer:len() < 10 then return end

    pinfo.cols.protocol = mgs.name

    local subtree = tree:add(mgs, buffer(), "MGS/control-plane-agent Protocol")
    local kind = buffer(8,1):uint()

    subtree:add_le(f_version, buffer(0,4))
    subtree:add_le(f_message_id, buffer(4,4))
    local kind_tree = subtree:add(f_kind, buffer(8,1))

    local handler = dissectors[protofields.message_kind.handlers[kind]]
    if handler then
        handler(buffer(9), pinfo, subtree)
    else
        kind_tree:add_expert_info(PI_PROTOCOL, PI_WARN, "Unknown kind")
    end
end

local udp_port = DissectorTable.get("udp.port")

-- Attach to both the SP and MGS control-plane-agent ports.
--
-- We could consider splitting this into "SP -> MGS protocol" and "MGS -> SP
-- protocol" and registering them separately?
udp_port:add(11111, mgs)
udp_port:add(22222, mgs)
