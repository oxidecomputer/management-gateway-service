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
