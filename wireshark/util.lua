local M = {}

M.dissect_hubpack_enum = function(buffer, pinfo, tree, field_desc, handlers)
    local buffer_len = buffer:len()

    if buffer_len < 1 then
        tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Missing enum variant")
        return
    end

    local kind = buffer(0,1):uint()
    local kind_tree = tree:add(field_desc.field, buffer(0,1))

    if buffer_len > 1 then
        local handler = handlers[field_desc.handlers[kind]]
        if handler then
            handler(buffer(1), pinfo, kind_tree)
        else
            kind_tree:add_expert_info(PI_PROTOCOL, PI_WARN, "Unknown kind")
        end
    end
end

return M
