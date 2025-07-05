-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

local M = {}

M.phase2_hash = ProtoField.bytes(
    "mgs.mgs_phase2_hash",
    "Host Phase 2 Hash"
)
M.phase2_offset = ProtoField.uint64(
    "mgs.mgs_phase2_offset",
    "Host Phase 2 Byte Offset",
    base.DEC
)

return M
