-- s7comm_tags.lua - Wireshark plugin: show PLC tag names and decoded values in S7comm packets.
--
-- Wireshark's S7comm dissector shows "read 24 bytes from DB40 at byte 0" and raw bytes.
-- This plugin adds an "S7 Tag Values" section to those packets that names the tags and
-- decodes their values, e.g.   PRS210.PV = 3.72   (DB40,D12, Float)
--
--   Read Var request    -> the tags being asked for
--   Read Var response   -> the tags and the values the PLC returned
--   Write Var request   -> the tags and the values being written (also shown in the Info column)
--   Write Var response  -> the tags and whether the PLC accepted the write
--
-- The decoding method is based on the s7comm-parser tool by Mickael.
--
-- Tag definitions come from CSV files in the folder "s7comm_tags_data" next to this file
-- (put there by s7tags.py). Needed columns: "Tag Name", "Address" (e.g. DB40,D12 or
-- DB20,X2.3) and "Data Type" (Boolean, Float, Long, DWord, Short, Int, Word, Byte).
--
-- Filters:   s7tags                              packets with at least one known tag
--            s7tags.tag == "PRS210.PV"           packets that carry this tag
--            s7tags.reading == "VLV301.Ack=True"   tag with a specific value
--            s7tags.operation == "write request" all writes of known tags
--            s7tags.device == "TMP120"           packets that carry any tag of this device
--            s7tags.single                       packets that touch one lone tag of a device
--            s7tags.single == "TMP120"           ... of this device
--
-- A device is the part of the tag name before the first dot (TMP120.Scale.RawMax -> TMP120).
-- Normal HMI polling reads whole blocks, so many tags of a device appear together. A request
-- that touches exactly one tag of a device that has several is unusual and worth a look.

local s7tags = Proto("s7tags", "S7 Tag Values")
local f_operation = ProtoField.string("s7tags.operation", "Operation")
local f_count = ProtoField.uint32("s7tags.count", "Tags")
local f_request = ProtoField.framenum("s7tags.request_frame", "Request in frame")
local f_tag = ProtoField.string("s7tags.tag", "Tag")
local f_value = ProtoField.string("s7tags.value", "Value")
local f_reading = ProtoField.string("s7tags.reading", "Reading")
local f_device = ProtoField.string("s7tags.device", "Device")
local f_single = ProtoField.string("s7tags.single", "Device with only one tag in this packet")
s7tags.fields = { f_operation, f_count, f_request, f_tag, f_value, f_reading, f_device, f_single }

s7tags.prefs.enabled = Pref.bool("Enabled", true, "Decode tag names and values in S7comm packets")
s7tags.prefs.info = Pref.bool("Show written values in the Info column", true,
    "Append the tags and values of Write Var requests to the Info column")

local f_stream = Field.new("tcp.stream")
local f_rosctr = Field.new("s7comm.header.rosctr")
local f_pduref = Field.new("s7comm.header.pduref")
local f_func = Field.new("s7comm.param.func")
local f_item_size = Field.new("s7comm.param.item.transp_size")
local f_item_len = Field.new("s7comm.param.item.length")
local f_item_db = Field.new("s7comm.param.item.db")
local f_item_area = Field.new("s7comm.param.item.area")
local f_item_byte = Field.new("s7comm.param.item.address.byte")
local f_item_bit = Field.new("s7comm.param.item.address.bit")
local f_retcode = Field.new("s7comm.data.returncode")
local f_data = Field.new("s7comm.resp.data")

local ROSCTR_JOB, ROSCTR_ACK_DATA = 1, 3
local FUNC_READ, FUNC_WRITE = 0x04, 0x05
local AREA_DB = 0x84
local SIZE_BIT = 1
local RETURN_OK = 0xff
-- bytes per unit of the item length, by transport size (BIT is handled separately)
local UNIT_BYTES = { [2] = 1, [3] = 1, [4] = 2, [5] = 2, [6] = 4, [7] = 4, [8] = 4 }
local RETURN_CODES = {
    [0x00] = "reserved", [0x01] = "hardware error", [0x03] = "access not allowed",
    [0x05] = "invalid address", [0x06] = "data type not supported",
    [0x07] = "data type inconsistent", [0x0a] = "object does not exist", [0xff] = "success",
}

-- ------------------------------------------------------------------ tag definitions

-- data type (lower case) -> { size in bytes, decoder(TvbRange) }
local TYPES = {
    boolean = { 1 },
    float = { 4, function(r) return string.format("%.6g", r:float()) end },
    real = { 4, function(r) return string.format("%.6g", r:float()) end },
    long = { 4, function(r) return tostring(r:int()) end },
    dint = { 4, function(r) return tostring(r:int()) end },
    dword = { 4, function(r) return tostring(r:uint()) end },
    short = { 2, function(r) return tostring(r:int()) end },
    int = { 2, function(r) return tostring(r:int()) end },
    word = { 2, function(r) return tostring(r:uint()) end },
    byte = { 1, function(r) return tostring(r:uint()) end },
    char = { 1, function(r) return tostring(r:uint()) end },
}

local tags_by_db = {}   -- db number -> list of tags sorted by byte offset
local tag_count = 0
local device_size = {}  -- device name -> number of tags it has in the tag CSVs

local SEP = package.config:sub(1, 1)
local function data_dir()
    local source = debug and debug.getinfo and debug.getinfo(1, "S").source or ""
    local dir = source:match("^@(.*)[/\\][^/\\]*$")
    if not dir and Dir.personal_plugins_path then dir = Dir.personal_plugins_path() end
    return (dir or ".") .. SEP .. "s7comm_tags_data"
end
local DATA_DIR = data_dir()

local function split_csv_line(line)
    local fields, pos, len = {}, 1, #line
    while pos <= len + 1 do
        if line:sub(pos, pos) == '"' then
            local value, i = "", pos + 1
            while true do
                local quote = line:find('"', i, true)
                if not quote then value = value .. line:sub(i); pos = len + 2; break end
                value = value .. line:sub(i, quote - 1)
                if line:sub(quote + 1, quote + 1) == '"' then
                    value = value .. '"'; i = quote + 2
                else
                    pos = (line:find(",", quote + 1, true) or len + 1) + 1; break
                end
            end
            fields[#fields + 1] = value
        else
            local comma = line:find(",", pos, true) or len + 1
            fields[#fields + 1] = line:sub(pos, comma - 1)
            pos = comma + 1
        end
    end
    return fields
end

local function load_tag_file(path)
    local fh = io.open(path, "r")
    if not fh then return end
    local col_name, col_addr, col_type
    for line in fh:lines() do
        line = line:gsub("^\239\187\191", ""):gsub("\r$", "")
        local row = split_csv_line(line)
        if not col_name then
            for i, header in ipairs(row) do
                local h = header:lower():gsub("^%s+", ""):gsub("%s+$", "")
                if h == "tag name" then col_name = i
                elseif h == "address" then col_addr = i
                elseif h == "data type" then col_type = i end
            end
            if not (col_name and col_addr and col_type) then break end
        else
            local name, addr = row[col_name], row[col_addr]
            local type_name = (row[col_type] or ""):lower()
            local db, byte, bit = (addr or ""):match("^DB(%d+),%a+(%d+)%.?(%d*)$")
            local type_info = TYPES[type_name]
            if name and db and type_info then
                db = tonumber(db)
                local list = tags_by_db[db]
                if not list then list = {}; tags_by_db[db] = list end
                local device = name:match("^([^.]+)%.") or name
                device_size[device] = (device_size[device] or 0) + 1
                list[#list + 1] = {
                    name = name, addr = addr, type = row[col_type], device = device,
                    byte = tonumber(byte), bit = tonumber(bit) or 0,
                    size = type_info[1], decode = type_info[2],
                }
                tag_count = tag_count + 1
            end
        end
    end
    fh:close()
end

local function load_tags()
    tags_by_db, tag_count, device_size = {}, 0, {}
    local ok, iter = pcall(Dir.open, DATA_DIR)
    if not ok or not iter then return end
    for file in iter do
        if file:lower():match("%.csv$") then load_tag_file(DATA_DIR .. SEP .. file) end
    end
    pcall(function() iter:close() end)
    for _, list in pairs(tags_by_db) do
        table.sort(list, function(a, b)
            if a.byte ~= b.byte then return a.byte < b.byte end
            return a.bit < b.bit
        end)
    end
end

-- Tags of one DB that lie completely inside [first_byte, first_byte + nbytes).
-- For a single-bit item only the Boolean tag at exactly that bit matches.
local function tags_in_range(db, first_byte, nbytes, bit)
    local list, found = tags_by_db[db], {}
    if not list then return found end
    local lo, hi = 1, #list
    while lo <= hi do
        local mid = math.floor((lo + hi) / 2)
        if list[mid].byte < first_byte then lo = mid + 1 else hi = mid - 1 end
    end
    local last = first_byte + nbytes
    for i = lo, #list do
        local tag = list[i]
        if tag.byte >= last then break end
        if tag.byte + tag.size <= last then
            if bit < 0 or (tag.size == 1 and not tag.decode and tag.bit == bit) then
                found[#found + 1] = tag
            end
        end
    end
    return found
end

-- ------------------------------------------------------------------ request items

-- The items of a request, as a list of { db, byte, nbytes, bit, tags }.
-- bit is -1 unless the item addresses a single bit.
local function request_items()
    local dbs, areas = { f_item_db() }, { f_item_area() }
    local bytes, bits = { f_item_byte() }, { f_item_bit() }
    local sizes, lens = { f_item_size() }, { f_item_len() }
    local n = #dbs
    if n == 0 or #areas ~= n or #bytes ~= n or #bits ~= n or #sizes ~= n or #lens ~= n then
        return nil
    end
    local items, key = {}, {}
    for i = 1, n do
        local size, length = sizes[i].value, lens[i].value
        local db, byte = dbs[i].value, bytes[i].value
        local bit, nbytes = -1, (UNIT_BYTES[size] or 1) * length
        if size == SIZE_BIT then bit = bits[i].value; nbytes = 1 end
        if areas[i].value ~= AREA_DB then db = -1 end
        items[i] = { db = db, byte = byte, nbytes = nbytes, bit = bit }
        key[i] = db .. "," .. byte .. "," .. nbytes .. "," .. bit
    end
    return items, table.concat(key, ";")
end

-- A response does not repeat what was asked, so each response frame is linked to its
-- request on the first pass. Polling repeats the same few item lists, so they are stored
-- once ("signatures") and each response keeps only: request frame and signature id.
local SIG_SPACE = 1048576
local sig_ids, sig_items, sig_total = {}, {}, 0
local pending = {}    -- tcp stream * 65536 + pdu reference -> request frame * SIG_SPACE + sig id
local responses = {}  -- response frame -> request frame * SIG_SPACE + sig id
local requests = {}   -- request frame -> sig id

local function signature_id(items, key)
    local id = sig_ids[key]
    if id then return id end
    if sig_total >= SIG_SPACE - 1 then return nil end
    sig_total = sig_total + 1
    items.known = 0
    for _, item in ipairs(items) do
        item.tags = item.db >= 0 and tags_in_range(item.db, item.byte, item.nbytes, item.bit) or {}
        items.known = items.known + #item.tags
    end
    -- devices with exactly one tag in this request, out of several they have in total
    local seen, order = {}, {}
    for _, item in ipairs(items) do
        for _, tag in ipairs(item.tags) do
            if not seen[tag.device] then order[#order + 1] = tag.device end
            seen[tag.device] = (seen[tag.device] or 0) + 1
        end
    end
    items.devices, items.device_tags = order, seen
    items.singles = {}
    for _, device in ipairs(order) do
        if seen[device] == 1 and device_size[device] > 1 then
            items.singles[#items.singles + 1] = device
        end
    end
    sig_ids[key], sig_items[sig_total] = sig_total, items
    return sig_total
end

-- ------------------------------------------------------------------ display

local function decode(tag, range, item)
    local offset = tag.byte - item.byte
    if offset + tag.size > range:len() then return nil end
    local slice = range(offset, tag.size)
    if tag.decode then return tag.decode(slice), slice end
    local bit = item.bit >= 0 and 0 or tag.bit   -- a single-bit item carries its bit in bit 0
    return (math.floor(slice:uint() / 2 ^ bit) % 2 == 1) and "True" or "False", slice
end

-- One line for a tag, under the node of its device. The device name is not repeated:
-- "Scale.RawMax = 12.5   (DB60,D48, Float)". The field value is still the full tag name.
local function add_reading(subtree, node, tvb, tag, value, slice, note)
    local item = slice and node:add(f_tag, slice, tag.name) or node:add(f_tag, tvb(0, 0), tag.name)
    local text = tag.name:sub(1, #tag.device + 1) == tag.device .. "." and tag.name:sub(#tag.device + 2)
        or tag.name
    if value then text = text .. " = " .. value end
    item:set_text(text .. "   (" .. tag.addr .. ", " .. tag.type .. (note and ", " .. note or "") .. ")")
    if value then
        item:add(f_value, slice, value)
        subtree:add(f_reading, slice, tag.name .. "=" .. value):set_hidden(true)
    end
end

function s7tags.init()
    load_tags()
    sig_ids, sig_items, sig_total = {}, {}, 0
    pending, responses, requests = {}, {}, {}
end

function s7tags.dissector(tvb, pinfo, tree)
    if not s7tags.prefs.enabled or tag_count == 0 then return end
    local rosctr = f_rosctr()
    if not rosctr then return end
    local func = f_func()
    func = func and func.value
    if func ~= FUNC_READ and func ~= FUNC_WRITE then return end
    rosctr = rosctr.value
    local pduref, stream = f_pduref(), f_stream()
    local pair_key = pduref and stream and stream.value * 65536 + pduref.value

    local items, request_frame
    if rosctr == ROSCTR_JOB then
        local id = requests[pinfo.number]
        if not id then
            local key
            items, key = request_items()
            if not items then return end
            id = signature_id(items, key)
            if not id then return end
            requests[pinfo.number] = id
            if pair_key and not pinfo.visited then pending[pair_key] = pinfo.number * SIG_SPACE + id end
        end
        items = sig_items[id]
    elseif rosctr == ROSCTR_ACK_DATA then
        local link = responses[pinfo.number]
        if not link and pair_key and not pinfo.visited then
            link = pending[pair_key]
            if link then responses[pinfo.number] = link; pending[pair_key] = nil end
        end
        if not link then return end
        request_frame = math.floor(link / SIG_SPACE)
        items = sig_items[link % SIG_SPACE]
    else
        return
    end

    local known = items.known
    if known == 0 then return end

    local is_request, is_write = rosctr == ROSCTR_JOB, func == FUNC_WRITE
    local operation = (is_write and "write " or "read ") .. (is_request and "request" or "response")
    local subtree = tree:add(s7tags, tvb(0, 0))
    local ndev = #items.devices
    subtree:set_text("S7 Tag Values: " .. operation .. ", " .. known .. (known == 1 and " tag" or " tags")
        .. " from " .. ndev .. (ndev == 1 and " device" or " devices"))
    subtree:add(f_operation, tvb(0, 0), operation)
    subtree:add(f_count, tvb(0, 0), known)
    if request_frame then subtree:add(f_request, tvb(0, 0), request_frame) end
    for _, device in ipairs(items.singles) do
        subtree:add(f_single, tvb(0, 0), device):set_hidden(true)
    end

    -- Listing every tag in every polling packet makes loading a capture many times slower,
    -- so read packets get their tag list only when it is needed: the packet is being shown,
    -- or a filter / column uses one of the tag fields. Writes are rare and always decoded.
    if not is_write and not tree.visible then
        local ref_tag = tree:referenced(f_tag)
        local ref_value, ref_reading = tree:referenced(f_value), tree:referenced(f_reading)
        local empty = tvb(0, 0)
        if tree:referenced(f_device) then
            for _, device in ipairs(items.devices) do subtree:add(f_device, empty, device) end
        end
        if not (ref_tag or ref_value or ref_reading) then return end
        -- A filter is being evaluated: add only the bare fields it uses, without display text.
        local data = (ref_value or ref_reading) and not is_request and { f_data() }
        local codes = data and { f_retcode() }
        local data_index = 0
        for i, item in ipairs(items) do
            local range
            if data and codes[i] and codes[i].value == RETURN_OK then
                data_index = data_index + 1
                range = data[data_index] and data[data_index].range
            end
            for _, tag in ipairs(item.tags) do
                if ref_tag then subtree:add(f_tag, empty, tag.name) end
                local value = range and decode(tag, range, item)
                if value then
                    if ref_value then subtree:add(f_value, empty, value) end
                    if ref_reading then subtree:add(f_reading, empty, tag.name .. "=" .. value) end
                end
            end
        end
        return
    end

    local has_values = (is_request and is_write) or (not is_request and not is_write)
    local codes, data = { f_retcode() }, { f_data() }
    local written, data_index = {}, 0

    -- one expandable node per device, in order of appearance, holding that device's tags
    local nodes = {}
    for _, device in ipairs(items.devices) do
        local in_packet, total = items.device_tags[device], device_size[device]
        local node = subtree:add(f_device, tvb(0, 0), device)
        node:set_text(device .. "   (" .. in_packet .. (in_packet == 1 and " tag" or " tags")
            .. " in this packet, " .. total .. " defined"
            .. ((in_packet == 1 and total > 1) and " - lone tag" or "") .. ")")
        nodes[device] = node
    end

    for i, item in ipairs(items) do
        local code = codes[i] and codes[i].value
        local range
        if has_values and (is_write or code == RETURN_OK) then
            -- failed read items carry no data, so data is counted separately from items
            data_index = data_index + 1
            range = data[data_index] and data[data_index].range
        end
        for _, tag in ipairs(item.tags) do
            if range then
                local value, slice = decode(tag, range, item)
                add_reading(subtree, nodes[tag.device], tvb, tag, value, slice)
                if value and is_write then written[#written + 1] = tag.name .. " = " .. value end
            elseif has_values or (is_write and code and code ~= RETURN_OK) then
                add_reading(subtree, nodes[tag.device], tvb, tag, nil, nil,
                    code and string.format("%s (0x%02x)", RETURN_CODES[code] or "error", code) or "no data")
            elseif is_write then
                add_reading(subtree, nodes[tag.device], tvb, tag, nil, nil, "write accepted")
            else
                add_reading(subtree, nodes[tag.device], tvb, tag)
            end
        end
    end

    if #written > 0 and s7tags.prefs.info then
        local shown = table.concat(written, ", ", 1, math.min(#written, 4))
        if #written > 4 then shown = shown .. ", +" .. (#written - 4) .. " more" end
        pinfo.cols.info:append("  [WRITE " .. shown .. "]")
    end
end

register_postdissector(s7tags)
