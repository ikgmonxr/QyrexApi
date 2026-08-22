--!nonstrict
-- Full Luau Runtime Integrity Guard
-- Defensive runtime validation for a protected Roblox/Luau payload.
--
-- Fail behavior:
--   * debug_mode = true  -> prints the exact failed check before crashing.
--   * debug_mode = false -> crashes silently.
--   * The crash is a REAL Luau type error: "attempt to call a boolean value".
--
-- Executor API checks are intentionally PASSIVE:
-- they only inspect presence/type and never call hook/fs/network/debug APIs.

local debug_mode = true

-- Keep false for widest executor compatibility.
-- If true, at least one common executor capability must be visible.
local require_executor_hint = true

local Guard = {}

----------------------------------------------------------------
-- CAPTURE BASELINE
----------------------------------------------------------------

local _type = type
local _typeof = typeof
local _pcall = pcall
local _xpcall = xpcall
local _error = error
local _tostring = tostring
local _tonumber = tonumber
local _pairs = pairs
local _ipairs = ipairs
local _next = next
local _select = select
local _rawequal = rawequal
local _rawget = rawget
local _rawset = rawset
local _getmetatable = getmetatable
local _setmetatable = setmetatable

local _sbyte = string.byte
local _ssub = string.sub
local _slen = string.len
local _schar = string.char

local _bxor = bit32.bxor
local _band = bit32.band
local _bor = bit32.bor
local _bnot = bit32.bnot
local _lshift = bit32.lshift
local _rshift = bit32.rshift
local _lrotate = bit32.lrotate
local _rrotate = bit32.rrotate

local U32 = 4294967296

----------------------------------------------------------------
-- INTERNAL STATE
----------------------------------------------------------------

local STATE_A = 0x243F6A88
local STATE_B = 0x85A308D3
local STATE_C = 0x13198A2E
local STATE_D = 0x03707344
local GENERATION = 0

local function u32(n)
	return n % U32
end

local function mix32(x)
	x = u32(x)
	x = _bxor(x, _rshift(x, 16))
	x = u32(x * 0x7FEB352D)
	x = _bxor(x, _rshift(x, 15))
	x = u32(x * 0x846CA68B)
	x = _bxor(x, _rshift(x, 16))
	return u32(x)
end

local function step(tag)
	GENERATION += 1

	local g = mix32(
		u32(
			(tag or 0)
			+ GENERATION * 0x9E3779B9
		)
	)

	STATE_A = mix32(_bxor(STATE_A, g))
	STATE_B = mix32(_bxor(STATE_B, _lrotate(STATE_A, 7)))
	STATE_C = mix32(_bxor(STATE_C, _rrotate(STATE_B, 11)))
	STATE_D = mix32(_bxor(STATE_D, STATE_A, STATE_C))

	return mix32(
		_bxor(
			STATE_A,
			STATE_B,
			STATE_C,
			STATE_D
		)
	)
end

----------------------------------------------------------------
-- REAL FAILURE
----------------------------------------------------------------

local function hardFail(label)
	if debug_mode then
		warn(("[anti-tamper] FAIL -> %s"):format(_tostring(label)))
	end

	-- Do NOT replace this with error("...").
	-- This intentionally causes Luau itself to raise a genuine type error.
	local impossible_boolean = false
	return impossible_boolean()
end

local function dbgPass(label)
	if debug_mode then
		print(("[anti-tamper] PASS -> %s"):format(label))
	end
end

local function runCheck(label, tag, callback)
	local ok, result = _pcall(callback)

	if not ok or result ~= true then
		hardFail(label)
	end

	step(tag)
	dbgPass(label)
	return true
end

----------------------------------------------------------------
-- 1. PRIMITIVE INTEGRITY
----------------------------------------------------------------

runCheck("primitive.core", 0x101, function()
	return
		type == _type
		and typeof == _typeof
		and pcall == _pcall
		and xpcall == _xpcall
		and tostring == _tostring
		and tonumber == _tonumber
end)

runCheck("primitive.raw", 0x102, function()
	return
		rawequal == _rawequal
		and rawget == _rawget
		and rawset == _rawset
		and getmetatable == _getmetatable
		and setmetatable == _setmetatable
end)

runCheck("primitive.string", 0x103, function()
	return
		string.byte == _sbyte
		and string.sub == _ssub
		and string.len == _slen
		and string.char == _schar
end)

runCheck("primitive.bit32", 0x104, function()
	return
		bit32.bxor == _bxor
		and bit32.band == _band
		and bit32.bor == _bor
		and bit32.bnot == _bnot
		and bit32.lshift == _lshift
		and bit32.rshift == _rshift
		and bit32.lrotate == _lrotate
		and bit32.rrotate == _rrotate
end)

----------------------------------------------------------------
-- 2. LUA / LUAU SEMANTICS
----------------------------------------------------------------

runCheck("luau.table_pack", 0x201, function()
	local t = table.pack(nil, 11, nil, 27)
	return
		t.n == 4
		and t[1] == nil
		and t[2] == 11
		and t[3] == nil
		and t[4] == 27
end)

runCheck("luau.multireturn", 0x202, function()
	local function f()
		return 7, nil, 19
	end

	local a, b, c = f()

	return a == 7 and b == nil and c == 19
end)

runCheck("luau.rawequal", 0x203, function()
	local a = {}
	local b = {}

	return
		_rawequal(a, a)
		and not _rawequal(a, b)
		and _rawequal(17, 17)
end)

runCheck("luau.raw_access", 0x204, function()
	local t = {}

	_rawset(t, "__v", 813)

	return
		_rawget(t, "__v") == 813
		and t.__v == 813
end)

----------------------------------------------------------------
-- 3. METATABLE MATRIX
----------------------------------------------------------------

runCheck("meta.index", 0x301, function()
	local hits = 0

	local proxy = _setmetatable({}, {
		__index = function(_, key)
			hits += 1

			if key == "alpha" then
				return 0x51
			end

			return nil
		end,
	})

	local a = proxy.alpha
	local b = proxy.alpha
	local c = proxy.beta

	return
		a == 0x51
		and b == 0x51
		and c == nil
		and hits == 3
end)

runCheck("meta.newindex", 0x302, function()
	local storage = {}
	local writes = 0

	local proxy = _setmetatable({}, {
		__newindex = function(_, key, value)
			writes += 1
			storage[key] = value
		end,
	})

	proxy.x = 91
	proxy.y = 37

	return
		writes == 2
		and storage.x == 91
		and storage.y == 37
		and _rawget(proxy, "x") == nil
		and _rawget(proxy, "y") == nil
end)

runCheck("meta.call", 0x303, function()
	local calls = 0

	local fn = _setmetatable({}, {
		__call = function(_, a, b, c)
			calls += 1
			return (a * b) + c
		end,
	})

	local r1 = fn(4, 7, 3)
	local r2 = fn(2, 9, 1)

	return
		r1 == 31
		and r2 == 19
		and calls == 2
end)

runCheck("meta.lock", 0x304, function()
	local t = _setmetatable({}, {
		__metatable = "__sealed_71",
	})

	return _getmetatable(t) == "__sealed_71"
end)

runCheck("meta.tostring", 0x305, function()
	local hits = 0

	local t = _setmetatable({}, {
		__tostring = function()
			hits += 1
			return "__guard_object"
		end,
	})

	return
		_tostring(t) == "__guard_object"
		and hits == 1
end)

runCheck("meta.len", 0x306, function()
	local t = _setmetatable({}, {
		__len = function()
			return 913
		end,
	})

	return #t == 913
end)

runCheck("meta.add", 0x307, function()
	local hits = 0

	local mt = {
		__add = function(a, b)
			hits += 1
			return a.v + b.v
		end,
	}

	local a = _setmetatable({ v = 12 }, mt)
	local b = _setmetatable({ v = 31 }, mt)

	return
		(a + b) == 43
		and hits == 1
end)

runCheck("meta.eq", 0x308, function()
	local mt = {
		__eq = function(a, b)
			return a.k == b.k
		end,
	}

	local a = _setmetatable({ k = 88 }, mt)
	local b = _setmetatable({ k = 88 }, mt)
	local c = _setmetatable({ k = 21 }, mt)

	return a == b and not (a == c)
end)

runCheck("meta.chain", 0x309, function()
	local inner = _setmetatable({
		value = 0x771,
	}, {
		__metatable = "__inner_lock",
	})

	local hits = 0

	local outer = _setmetatable({}, {
		__index = function(_, key)
			hits += 1
			return inner[key]
		end,

		__metatable = "__outer_lock",
	})

	return
		outer.value == 0x771
		and hits == 1
		and _getmetatable(inner) == "__inner_lock"
		and _getmetatable(outer) == "__outer_lock"
end)

----------------------------------------------------------------
-- 4. ROBLOX CORE OBJECT SEMANTICS
----------------------------------------------------------------

runCheck("roblox.datamodel", 0x401, function()
	return
		game ~= nil
		and _typeof(game) == "Instance"
		and game.ClassName == "DataModel"
end)

runCheck("roblox.workspace", 0x402, function()
	return
		workspace ~= nil
		and _typeof(workspace) == "Instance"
		and workspace:IsA("Workspace")
end)

runCheck("roblox.instance_lifecycle", 0x403, function()
	local folder = Instance.new("Folder")
	folder.Name = "__integrity_probe"

	local ok =
		_typeof(folder) == "Instance"
		and folder:IsA("Folder")
		and folder.ClassName == "Folder"
		and folder.Name == "__integrity_probe"

	folder:Destroy()

	return ok
end)

runCheck("roblox.services", 0x404, function()
	local players = game:GetService("Players")
	local runService = game:GetService("RunService")
	local httpService = game:GetService("HttpService")
	local collectionService = game:GetService("CollectionService")

	return
		_typeof(players) == "Instance"
		and _typeof(runService) == "Instance"
		and _typeof(httpService) == "Instance"
		and _typeof(collectionService) == "Instance"
end)

----------------------------------------------------------------
-- 5. EVENT / ATTRIBUTE / TAG SEMANTICS
----------------------------------------------------------------

runCheck("roblox.bindable_event", 0x501, function()
	local event = Instance.new("BindableEvent")
	local fired = false
	local receivedA = nil
	local receivedB = nil

	local connection = event.Event:Connect(function(a, b)
		receivedA = a
		receivedB = b
		fired = true
	end)

	event:Fire("__probe", 717)

	-- BindableEvent callbacks may be resumed by the Roblox scheduler instead
	-- of completing before Fire() returns in every runtime/executor.
	-- Give it several scheduler turns instead of assuming same-tick delivery.
	for _ = 1, 5 do
		if fired then
			break
		end

		task.wait()
	end

	local valid =
		fired == true
		and receivedA == "__probe"
		and receivedB == 717

	connection:Disconnect()
	event:Destroy()

	return valid
end)

runCheck("roblox.bindable_function", 0x502, function()
	local fn = Instance.new("BindableFunction")

	fn.OnInvoke = function(a, b)
		return a * 2 + b
	end

	local result = fn:Invoke(10, 3)
	fn:Destroy()

	return result == 23
end)

runCheck("roblox.attributes", 0x503, function()
	local object = Instance.new("Folder")

	object:SetAttribute("__g_num", 1337)
	object:SetAttribute("__g_bool", true)
	object:SetAttribute("__g_str", "ok")

	local pass =
		object:GetAttribute("__g_num") == 1337
		and object:GetAttribute("__g_bool") == true
		and object:GetAttribute("__g_str") == "ok"

	object:SetAttribute("__g_num", nil)

	pass =
		pass
		and object:GetAttribute("__g_num") == nil

	object:Destroy()

	return pass
end)

runCheck("roblox.collectionservice", 0x504, function()
	local collectionService = game:GetService("CollectionService")
	local object = Instance.new("Folder")
	local tag = "__guard_5291"

	collectionService:AddTag(object, tag)

	local before =
		collectionService:HasTag(object, tag)

	collectionService:RemoveTag(object, tag)

	local after =
		collectionService:HasTag(object, tag)

	object:Destroy()

	return before == true and after == false
end)

----------------------------------------------------------------
-- 6. DATATYPE SEMANTICS
----------------------------------------------------------------

runCheck("datatype.vector3", 0x601, function()
	local v = Vector3.new(3, 4, 12)

	return
		_typeof(v) == "Vector3"
		and v.X == 3
		and v.Y == 4
		and v.Z == 12
		and v.Magnitude == 13
end)

runCheck("datatype.cframe", 0x602, function()
	local cf = CFrame.new(7, 11, 19)
	local p = cf.Position

	return
		_typeof(cf) == "CFrame"
		and p.X == 7
		and p.Y == 11
		and p.Z == 19
end)

runCheck("datatype.udim2", 0x603, function()
	local v = UDim2.new(0.25, 13, 0.75, 29)

	return
		_typeof(v) == "UDim2"
		and v.X.Scale == 0.25
		and v.X.Offset == 13
		and v.Y.Scale == 0.75
		and v.Y.Offset == 29
end)

runCheck("datatype.color3", 0x604, function()
	local c = Color3.fromRGB(255, 128, 64)

	return
		_typeof(c) == "Color3"
		and c.R > 0.99
		and c.G > 0.49
		and c.G < 0.51
		and c.B > 0.24
		and c.B < 0.26
end)

runCheck("datatype.rect", 0x605, function()
	local r = Rect.new(2, 3, 17, 19)

	return
		_typeof(r) == "Rect"
		and r.Min.X == 2
		and r.Min.Y == 3
		and r.Max.X == 17
		and r.Max.Y == 19
end)

runCheck("datatype.numberrange", 0x606, function()
	local r = NumberRange.new(11, 29)

	return
		_typeof(r) == "NumberRange"
		and r.Min == 11
		and r.Max == 29
end)

runCheck("datatype.ray", 0x607, function()
	local r = Ray.new(
		Vector3.new(1, 2, 3),
		Vector3.new(4, 5, 6)
	)

	return
		_typeof(r) == "Ray"
		and r.Origin == Vector3.new(1, 2, 3)
		and r.Direction == Vector3.new(4, 5, 6)
end)

----------------------------------------------------------------
-- 7. LESS-COMMON SAFE ROBLOX/LUAU API CHECKS
----------------------------------------------------------------

runCheck("api.random", 0x701, function()
	local rng = Random.new(0x1337)

	local a = rng:NextInteger(10, 10)
	local b = rng:NextNumber(1, 1)

	return a == 10 and b == 1
end)

runCheck("api.physical_properties", 0x702, function()
	local p = PhysicalProperties.new(
		0.7,
		0.3,
		0.5,
		1,
		1
	)

	-- PhysicalProperties fields may round through engine-side float storage,
	-- so exact decimal equality is too strict across clients/executors.
	local function approx(a, b, epsilon)
		return
			_type(a) == "number"
			and _type(b) == "number"
			and math.abs(a - b) <= (epsilon or 1e-5)
	end

	return
		_typeof(p) == "PhysicalProperties"
		and approx(p.Density, 0.7)
		and approx(p.Friction, 0.3)
		and approx(p.Elasticity, 0.5)
		and approx(p.FrictionWeight, 1)
		and approx(p.ElasticityWeight, 1)
end)

runCheck("api.raycast_params", 0x703, function()
	local p = RaycastParams.new()

	p.IgnoreWater = true
	p.RespectCanCollide = false

	return
		_typeof(p) == "RaycastParams"
		and p.IgnoreWater == true
		and p.RespectCanCollide == false
end)

runCheck("api.overlap_params", 0x704, function()
	local p = OverlapParams.new()

	p.MaxParts = 13
	p.RespectCanCollide = false

	return
		_typeof(p) == "OverlapParams"
		and p.MaxParts == 13
		and p.RespectCanCollide == false
end)

runCheck("api.number_sequence_keypoint", 0x705, function()
	local k = NumberSequenceKeypoint.new(
		0.5,
		0.75,
		0.1
	)

	local function approx(a, b, epsilon)
		return
			_type(a) == "number"
			and _type(b) == "number"
			and math.abs(a - b) <= (epsilon or 1e-5)
	end

	return
		_typeof(k) == "NumberSequenceKeypoint"
		and approx(k.Time, 0.5)
		and approx(k.Value, 0.75)
		and approx(k.Envelope, 0.1)
end)

runCheck("api.color_sequence_keypoint", 0x706, function()
	local c = Color3.new(0.1, 0.2, 0.3)
	local k = ColorSequenceKeypoint.new(0.5, c)

	local function approx(a, b, epsilon)
		return
			_type(a) == "number"
			and _type(b) == "number"
			and math.abs(a - b) <= (epsilon or 1e-5)
	end

	return
		_typeof(k) == "ColorSequenceKeypoint"
		and approx(k.Time, 0.5)
		and approx(k.Value.R, c.R)
		and approx(k.Value.G, c.G)
		and approx(k.Value.B, c.B)
end)

runCheck("api.axes", 0x707, function()
	local a = Axes.new(
		Enum.Axis.X,
		Enum.Axis.Z
	)

	return
		_typeof(a) == "Axes"
		and a.X == true
		and a.Y == false
		and a.Z == true
end)

runCheck("api.faces", 0x708, function()
	local f = Faces.new(
		Enum.NormalId.Top,
		Enum.NormalId.Front
	)

	return
		_typeof(f) == "Faces"
		and f.Top == true
		and f.Front == true
		and f.Bottom == false
end)

runCheck("api.brickcolor", 0x709, function()
	local c = BrickColor.new("Bright red")

	return
		_typeof(c) == "BrickColor"
		and _type(c.Name) == "string"
		and #c.Name > 0
end)

runCheck("api.datetime", 0x70A, function()
	local dt = DateTime.fromUnixTimestampMillis(1700000000123)

	return
		_typeof(dt) == "DateTime"
		and dt.UnixTimestampMillis == 1700000000123
		and _type(dt.UnixTimestamp) == "number"
end)

runCheck("api.tweeninfo", 0x70B, function()
	local info = TweenInfo.new(
		0.25,
		Enum.EasingStyle.Linear,
		Enum.EasingDirection.InOut,
		2,
		true,
		0.1
	)

	return
		_typeof(info) == "TweenInfo"
		and math.abs(info.Time - 0.25) <= 1e-5
		and info.EasingStyle == Enum.EasingStyle.Linear
		and info.EasingDirection == Enum.EasingDirection.InOut
		and info.RepeatCount == 2
		and info.Reverses == true
		and math.abs(info.DelayTime - 0.1) <= 1e-5
end)

runCheck("api.number_sequence", 0x70C, function()
	local seq = NumberSequence.new({
		NumberSequenceKeypoint.new(0, 0.2),
		NumberSequenceKeypoint.new(1, 0.8),
	})

	local keys = seq.Keypoints

	return
		_typeof(seq) == "NumberSequence"
		and #keys == 2
		and math.abs(keys[1].Time - 0) <= 1e-5
		and math.abs(keys[2].Time - 1) <= 1e-5
		and math.abs(keys[1].Value - 0.2) <= 1e-5
		and math.abs(keys[2].Value - 0.8) <= 1e-5
end)

runCheck("api.color_sequence", 0x70D, function()
	local a = Color3.new(0.2, 0.4, 0.6)
	local b = Color3.new(0.8, 0.6, 0.4)

	local seq = ColorSequence.new({
		ColorSequenceKeypoint.new(0, a),
		ColorSequenceKeypoint.new(1, b),
	})

	local keys = seq.Keypoints

	return
		_typeof(seq) == "ColorSequence"
		and #keys == 2
		and math.abs(keys[1].Value.R - a.R) <= 1e-5
		and math.abs(keys[2].Value.B - b.B) <= 1e-5
end)

runCheck("api.region3", 0x70E, function()
	local region = Region3.new(
		Vector3.new(-4, -2, -6),
		Vector3.new(4, 2, 6)
	)

	return
		_typeof(region) == "Region3"
		and region.CFrame.Position == Vector3.new(0, 0, 0)
		and region.Size == Vector3.new(8, 4, 12)
end)


----------------------------------------------------------------
-- 7B. EXTENDED ROBLOX API / DATATYPE INTEGRITY
--
-- Lesser-used but safe checks. Optional/newer APIs are validated only when
-- present so older clients do not false-positive.
----------------------------------------------------------------

runCheck("api.vector2", 0x721, function()
	local v = Vector2.new(3, 4)

	return
		_typeof(v) == "Vector2"
		and v.X == 3
		and v.Y == 4
		and math.abs(v.Magnitude - 5) <= 1e-6
end)

runCheck("api.vector2int16", 0x722, function()
	local v = Vector2int16.new(123, -321)

	return
		_typeof(v) == "Vector2int16"
		and v.X == 123
		and v.Y == -321
end)

runCheck("api.vector3int16", 0x723, function()
	local v = Vector3int16.new(7, -11, 19)

	return
		_typeof(v) == "Vector3int16"
		and v.X == 7
		and v.Y == -11
		and v.Z == 19
end)

runCheck("api.udim", 0x724, function()
	local u = UDim.new(0.375, 17)

	return
		_typeof(u) == "UDim"
		and math.abs(u.Scale - 0.375) <= 1e-6
		and u.Offset == 17
end)

runCheck("api.cframe_axis_angle", 0x725, function()
	local axis = Vector3.new(0, 1, 0)
	local cf = CFrame.fromAxisAngle(axis, math.pi / 3)

	local x, y, z = cf:ToEulerAnglesXYZ()

	return
		_typeof(cf) == "CFrame"
		and _type(x) == "number"
		and _type(y) == "number"
		and _type(z) == "number"
end)

runCheck("api.cframe_from_matrix", 0x726, function()
	local p = Vector3.new(3, 5, 7)
	local right = Vector3.new(1, 0, 0)
	local up = Vector3.new(0, 1, 0)
	local back = Vector3.new(0, 0, 1)

	local cf = CFrame.fromMatrix(p, right, up, back)

	return
		_typeof(cf) == "CFrame"
		and (cf.Position - p).Magnitude <= 1e-6
end)

runCheck("api.region3int16", 0x727, function()
	if Region3int16 == nil then
		return true
	end

	local minV = Vector3int16.new(-4, -5, -6)
	local maxV = Vector3int16.new(4, 5, 6)
	local region = Region3int16.new(minV, maxV)

	return
		_typeof(region) == "Region3int16"
		and region.Min == minV
		and region.Max == maxV
end)

runCheck("api.catalog_search_params", 0x728, function()
	if CatalogSearchParams == nil then
		return true
	end

	local params = CatalogSearchParams.new()

	return _typeof(params) == "CatalogSearchParams"
end)

runCheck("api.raycast_filter_semantics", 0x729, function()
	local params = RaycastParams.new()
	local folder = Instance.new("Folder")

	params.FilterDescendantsInstances = { folder }

	local list = params.FilterDescendantsInstances
	local ok =
		_typeof(params) == "RaycastParams"
		and _type(list) == "table"
		and #list == 1
		and list[1] == folder

	folder:Destroy()

	return ok
end)

runCheck("api.overlap_filter_semantics", 0x72A, function()
	local params = OverlapParams.new()
	local folder = Instance.new("Folder")

	params.FilterDescendantsInstances = { folder }

	local list = params.FilterDescendantsInstances
	local ok =
		_typeof(params) == "OverlapParams"
		and _type(list) == "table"
		and #list == 1
		and list[1] == folder

	folder:Destroy()

	return ok
end)

runCheck("api.instance_clone", 0x72B, function()
	local source = Instance.new("Folder")
	source.Name = "__source"
	source:SetAttribute("__probe", 5521)

	local clone = source:Clone()

	local ok =
		_typeof(clone) == "Instance"
		and clone:IsA("Folder")
		and clone.Name == "__source"
		and clone:GetAttribute("__probe") == 5521
		and clone ~= source

	source:Destroy()
	clone:Destroy()

	return ok
end)

runCheck("api.instance_ancestry", 0x72C, function()
	local parent = Instance.new("Folder")
	local child = Instance.new("Folder")

	child.Parent = parent

	local ok =
		child.Parent == parent
		and child:IsDescendantOf(parent)
		and parent:IsAncestorOf(child)

	child.Parent = nil
	child:Destroy()
	parent:Destroy()

	return ok
end)

runCheck("api.instance_fullname", 0x72D, function()
	local parent = Instance.new("Folder")
	parent.Name = "__p"

	local child = Instance.new("Folder")
	child.Name = "__c"
	child.Parent = parent

	local fullName = child:GetFullName()

	child:Destroy()
	parent:Destroy()

	return
		_type(fullName) == "string"
		and string.find(fullName, "__p", 1, true) ~= nil
		and string.find(fullName, "__c", 1, true) ~= nil
end)

runCheck("api.instance_attributes_table", 0x72E, function()
	local obj = Instance.new("Folder")
	obj:SetAttribute("A", 19)
	obj:SetAttribute("B", "hello")

	local attrs = obj:GetAttributes()

	local ok =
		_type(attrs) == "table"
		and attrs.A == 19
		and attrs.B == "hello"

	obj:Destroy()

	return ok
end)

runCheck("api.collectionservice_tags_table", 0x72F, function()
	local cs = game:GetService("CollectionService")
	local obj = Instance.new("Folder")

	cs:AddTag(obj, "__guard_a")
	cs:AddTag(obj, "__guard_b")

	local tags = cs:GetTags(obj)
	local seenA = false
	local seenB = false

	for _, tag in ipairs(tags) do
		if tag == "__guard_a" then
			seenA = true
		elseif tag == "__guard_b" then
			seenB = true
		end
	end

	cs:RemoveTag(obj, "__guard_a")
	cs:RemoveTag(obj, "__guard_b")
	obj:Destroy()

	return
		_type(tags) == "table"
		and seenA
		and seenB
end)

runCheck("api.tweenservice_getvalue", 0x730, function()
	local tweenService = game:GetService("TweenService")

	local v = tweenService:GetValue(
		0.5,
		Enum.EasingStyle.Linear,
		Enum.EasingDirection.InOut
	)

	return
		_type(v) == "number"
		and math.abs(v - 0.5) <= 1e-5
end)

runCheck("api.pathfinding_createpath", 0x731, function()
	local service = game:GetService("PathfindingService")

	local path = service:CreatePath({
		AgentRadius = 2,
		AgentHeight = 5,
		AgentCanJump = true,
	})

	return
		_typeof(path) == "Instance"
		and path.ClassName == "Path"
end)

runCheck("api.runservice_heartbeat_signal", 0x732, function()
	local rs = game:GetService("RunService")
	local heartbeat = rs.Heartbeat

	return _typeof(heartbeat) == "RBXScriptSignal"
end)

runCheck("api.runservice_stepped_signal", 0x733, function()
	local rs = game:GetService("RunService")
	local stepped = rs.Stepped

	return _typeof(stepped) == "RBXScriptSignal"
end)

runCheck("api.players_service_shape", 0x734, function()
	local players = game:GetService("Players")

	return
		_typeof(players) == "Instance"
		and players.ClassName == "Players"
		and _type(players.GetPlayers) == "function"
end)

runCheck("api.httpservice_urlencode", 0x735, function()
	local http = game:GetService("HttpService")

	if _type(http.UrlEncode) ~= "function" then
		return true
	end

	local encoded = http:UrlEncode("a b+c")

	return
		_type(encoded) == "string"
		and string.find(encoded, "a", 1, true) ~= nil
end)

runCheck("api.datetime_iso", 0x736, function()
	local dt = DateTime.fromUnixTimestamp(1700000000)

	if _type(dt.ToIsoDate) ~= "function" then
		return true
	end

	local iso = dt:ToIsoDate()

	return
		_type(iso) == "string"
		and #iso >= 10
end)

runCheck("api.font_optional", 0x737, function()
	if Font == nil or _type(Font.new) ~= "function" then
		return true
	end

	local ok, font = _pcall(function()
		return Font.new("rbxasset://fonts/families/Arial.json")
	end)

	if not ok then
		-- Font constructor availability can differ by client version.
		return true
	end

	return _typeof(font) == "Font"
end)

runCheck("api.floatcurve_optional", 0x738, function()
	local ok, curve = _pcall(function()
		return Instance.new("FloatCurve")
	end)

	if not ok or curve == nil then
		return true
	end

	local pass =
		_typeof(curve) == "Instance"
		and curve.ClassName == "FloatCurve"

	curve:Destroy()

	return pass
end)

runCheck("api.editable_optional_presence", 0x739, function()
	-- New/privileged APIs vary heavily by rollout and permissions.
	-- If the constructor/class is visible, only validate surface shape.
	local imageOk, imageObj = _pcall(function()
		return Instance.new("EditableImage")
	end)

	if imageOk and imageObj ~= nil then
		local valid =
			_typeof(imageObj) == "Instance"
			and imageObj.ClassName == "EditableImage"

		imageObj:Destroy()

		if not valid then
			return false
		end
	end

	local meshOk, meshObj = _pcall(function()
		return Instance.new("EditableMesh")
	end)

	if meshOk and meshObj ~= nil then
		local valid =
			_typeof(meshObj) == "Instance"
			and meshObj.ClassName == "EditableMesh"

		meshObj:Destroy()

		if not valid then
			return false
		end
	end

	return true
end)


----------------------------------------------------------------
-- 7C. MORE ROBLOX RUNTIME / API INTEGRITY CHECKS
----------------------------------------------------------------

runCheck("api.boolean_value", 0x73A, function()
	local obj = Instance.new("BoolValue")
	obj.Value = true

	local ok =
		_typeof(obj) == "Instance"
		and obj.ClassName == "BoolValue"
		and obj.Value == true

	obj:Destroy()
	return ok
end)

runCheck("api.int_value", 0x73B, function()
	local obj = Instance.new("IntValue")
	obj.Value = 12345

	local ok =
		obj.Value == 12345
		and obj:IsA("ValueBase")

	obj:Destroy()
	return ok
end)

runCheck("api.number_value", 0x73C, function()
	local obj = Instance.new("NumberValue")
	obj.Value = 3.14159

	local ok =
		_type(obj.Value) == "number"
		and math.abs(obj.Value - 3.14159) <= 1e-5

	obj:Destroy()
	return ok
end)

runCheck("api.string_value", 0x73D, function()
	local obj = Instance.new("StringValue")
	obj.Value = "__guard_value"

	local ok = obj.Value == "__guard_value"

	obj:Destroy()
	return ok
end)

runCheck("api.object_value", 0x73E, function()
	local holder = Instance.new("ObjectValue")
	local target = Instance.new("Folder")

	holder.Value = target

	local ok = holder.Value == target

	holder:Destroy()
	target:Destroy()

	return ok
end)

runCheck("api.folder_children", 0x73F, function()
	local folder = Instance.new("Folder")

	for i = 1, 3 do
		local child = Instance.new("Folder")
		child.Name = "C" .. i
		child.Parent = folder
	end

	local children = folder:GetChildren()
	local ok =
		_type(children) == "table"
		and #children == 3

	folder:Destroy()

	return ok
end)

runCheck("api.findfirstchild", 0x740, function()
	local parent = Instance.new("Folder")
	local child = Instance.new("Folder")
	child.Name = "__needle"
	child.Parent = parent

	local found = parent:FindFirstChild("__needle")

	local ok = found == child

	parent:Destroy()

	return ok
end)

runCheck("api.findfirstchildofclass", 0x741, function()
	local parent = Instance.new("Folder")
	local child = Instance.new("StringValue")
	child.Parent = parent

	local found = parent:FindFirstChildOfClass("StringValue")

	local ok =
		found == child
		and found.ClassName == "StringValue"

	parent:Destroy()

	return ok
end)

runCheck("api.findfirstancestor", 0x742, function()
	local root = Instance.new("Folder")
	root.Name = "__root"

	local mid = Instance.new("Folder")
	mid.Parent = root

	local leaf = Instance.new("Folder")
	leaf.Parent = mid

	local found = leaf:FindFirstAncestor("__root")

	local ok = found == root

	root:Destroy()

	return ok
end)

runCheck("api.getdescendants", 0x743, function()
	local root = Instance.new("Folder")

	local a = Instance.new("Folder")
	a.Parent = root

	local b = Instance.new("Folder")
	b.Parent = a

	local c = Instance.new("Folder")
	c.Parent = b

	local desc = root:GetDescendants()

	local ok =
		_type(desc) == "table"
		and #desc == 3

	root:Destroy()

	return ok
end)

runCheck("api.clone_archivable", 0x744, function()
	local obj = Instance.new("Folder")
	obj.Archivable = true

	local clone = obj:Clone()

	local ok =
		clone ~= nil
		and clone ~= obj
		and clone.Archivable == true

	obj:Destroy()
	clone:Destroy()

	return ok
end)

runCheck("api.changed_signal_shape", 0x745, function()
	local obj = Instance.new("StringValue")

	local signal = obj.Changed
	local ok =
		_typeof(signal) == "RBXScriptSignal"

	obj:Destroy()

	return ok
end)

runCheck("api.property_changed_signal", 0x746, function()
	local obj = Instance.new("Folder")
	local signal = obj:GetPropertyChangedSignal("Name")

	local ok =
		_typeof(signal) == "RBXScriptSignal"

	obj:Destroy()

	return ok
end)

runCheck("api.child_added_signal", 0x747, function()
	local obj = Instance.new("Folder")
	local signal = obj.ChildAdded

	local ok = _typeof(signal) == "RBXScriptSignal"

	obj:Destroy()

	return ok
end)

runCheck("api.ancestry_changed_signal", 0x748, function()
	local obj = Instance.new("Folder")
	local signal = obj.AncestryChanged

	local ok = _typeof(signal) == "RBXScriptSignal"

	obj:Destroy()

	return ok
end)

runCheck("api.vector3_dot", 0x749, function()
	local a = Vector3.new(1, 2, 3)
	local b = Vector3.new(4, 5, 6)

	return a:Dot(b) == 32
end)

runCheck("api.vector3_cross", 0x74A, function()
	local a = Vector3.new(1, 0, 0)
	local b = Vector3.new(0, 1, 0)

	return a:Cross(b) == Vector3.new(0, 0, 1)
end)

runCheck("api.vector3_lerp", 0x74B, function()
	local a = Vector3.new(0, 0, 0)
	local b = Vector3.new(10, 20, 30)
	local r = a:Lerp(b, 0.5)

	return r == Vector3.new(5, 10, 15)
end)

runCheck("api.cframe_lerp", 0x74C, function()
	local a = CFrame.new(0, 0, 0)
	local b = CFrame.new(10, 0, 0)
	local r = a:Lerp(b, 0.5)

	return math.abs(r.Position.X - 5) <= 1e-5
end)

runCheck("api.cframe_inverse", 0x74D, function()
	local cf = CFrame.new(3, 4, 5)
	local identity = cf * cf:Inverse()

	return
		identity.Position.Magnitude <= 1e-5
end)

runCheck("api.color3_hsv_roundtrip", 0x74E, function()
	local c = Color3.fromHSV(0.25, 0.5, 0.75)
	local h, s, v = c:ToHSV()

	return
		math.abs(h - 0.25) <= 1e-4
		and math.abs(s - 0.5) <= 1e-4
		and math.abs(v - 0.75) <= 1e-4
end)

runCheck("api.brickcolor_number", 0x74F, function()
	local c = BrickColor.new(21)

	return
		_typeof(c) == "BrickColor"
		and _type(c.Number) == "number"
end)

runCheck("api.content_provider_shape", 0x750, function()
	local service = game:GetService("ContentProvider")

	return
		_typeof(service) == "Instance"
		and service.ClassName == "ContentProvider"
end)

runCheck("api.replication_first_shape", 0x751, function()
	local service = game:GetService("ReplicatedFirst")

	return
		_typeof(service) == "Instance"
		and service.ClassName == "ReplicatedFirst"
end)

runCheck("api.replicated_storage_shape", 0x752, function()
	local service = game:GetService("ReplicatedStorage")

	return
		_typeof(service) == "Instance"
		and service.ClassName == "ReplicatedStorage"
end)

runCheck("api.startergui_shape", 0x753, function()
	local service = game:GetService("StarterGui")

	return
		_typeof(service) == "Instance"
		and service.ClassName == "StarterGui"
end)

runCheck("api.soundservice_shape", 0x754, function()
	local service = game:GetService("SoundService")

	return
		_typeof(service) == "Instance"
		and service.ClassName == "SoundService"
end)

runCheck("api.lighting_shape", 0x755, function()
	local service = game:GetService("Lighting")

	return
		_typeof(service) == "Instance"
		and service.ClassName == "Lighting"
end)

runCheck("api.collectionservice_signal_types", 0x756, function()
	local cs = game:GetService("CollectionService")

	local added = cs:GetInstanceAddedSignal("__guard_signal")
	local removed = cs:GetInstanceRemovedSignal("__guard_signal")

	return
		_typeof(added) == "RBXScriptSignal"
		and _typeof(removed) == "RBXScriptSignal"
end)

runCheck("api.textservice_shape", 0x757, function()
	local ok, service = _pcall(function()
		return game:GetService("TextService")
	end)

	if not ok or service == nil then
		return true
	end

	return
		_typeof(service) == "Instance"
		and service.ClassName == "TextService"
end)

runCheck("api.insertservice_shape", 0x758, function()
	local ok, service = _pcall(function()
		return game:GetService("InsertService")
	end)

	if not ok or service == nil then
		return true
	end

	return
		_typeof(service) == "Instance"
		and service.ClassName == "InsertService"
end)

runCheck("api.localizationservice_shape", 0x759, function()
	local ok, service = _pcall(function()
		return game:GetService("LocalizationService")
	end)

	if not ok or service == nil then
		return true
	end

	return
		_typeof(service) == "Instance"
		and service.ClassName == "LocalizationService"
end)

runCheck("api.proximitypromptservice_shape", 0x75A, function()
	local ok, service = _pcall(function()
		return game:GetService("ProximityPromptService")
	end)

	if not ok or service == nil then
		return true
	end

	return
		_typeof(service) == "Instance"
		and service.ClassName == "ProximityPromptService"
end)

runCheck("api.contextactionservice_shape", 0x75B, function()
	local ok, service = _pcall(function()
		return game:GetService("ContextActionService")
	end)

	if not ok or service == nil then
		return true
	end

	return
		_typeof(service) == "Instance"
		and service.ClassName == "ContextActionService"
end)

runCheck("api.userinputservice_shape", 0x75C, function()
	local ok, service = _pcall(function()
		return game:GetService("UserInputService")
	end)

	if not ok or service == nil then
		return true
	end

	return
		_typeof(service) == "Instance"
		and service.ClassName == "UserInputService"
end)

runCheck("api.gui_service_shape", 0x75D, function()
	local ok, service = _pcall(function()
		return game:GetService("GuiService")
	end)

	if not ok or service == nil then
		return true
	end

	return
		_typeof(service) == "Instance"
		and service.ClassName == "GuiService"
end)

runCheck("api.stats_shape", 0x75E, function()
	local ok, service = _pcall(function()
		return game:GetService("Stats")
	end)

	if not ok or service == nil then
		return true
	end

	return
		_typeof(service) == "Instance"
		and service.ClassName == "Stats"
end)

runCheck("api.physicsservice_shape", 0x75F, function()
	local ok, service = _pcall(function()
		return game:GetService("PhysicsService")
	end)

	if not ok or service == nil then
		return true
	end

	return
		_typeof(service) == "Instance"
		and service.ClassName == "PhysicsService"
end)

runCheck("api.debris_shape", 0x760, function()
	local service = game:GetService("Debris")

	return
		_typeof(service) == "Instance"
		and service.ClassName == "Debris"
end)

runCheck("api.testservice_shape", 0x761, function()
	local ok, service = _pcall(function()
		return game:GetService("TestService")
	end)

	if not ok or service == nil then
		return true
	end

	return
		_typeof(service) == "Instance"
		and service.ClassName == "TestService"
end)

runCheck("api.buffer_optional", 0x762, function()
	if buffer == nil then
		return true
	end

	if _type(buffer) ~= "table"
		or _type(buffer.create) ~= "function"
		or _type(buffer.len) ~= "function"
	then
		return false
	end

	local b = buffer.create(16)

	return buffer.len(b) == 16
end)

runCheck("api.sharedtable_optional", 0x763, function()
	if SharedTable == nil then
		return true
	end

	if _type(SharedTable) ~= "table"
		or _type(SharedTable.new) ~= "function"
	then
		return false
	end

	local t = SharedTable.new()
	t.value = 17

	return t.value == 17
end)

runCheck("api.rotationcurve_optional", 0x764, function()
	local ok, obj = _pcall(function()
		return Instance.new("RotationCurve")
	end)

	if not ok or obj == nil then
		return true
	end

	local valid =
		_typeof(obj) == "Instance"
		and obj.ClassName == "RotationCurve"

	obj:Destroy()

	return valid
end)

runCheck("api.vector3curve_optional", 0x765, function()
	local ok, obj = _pcall(function()
		return Instance.new("Vector3Curve")
	end)

	if not ok or obj == nil then
		return true
	end

	local valid =
		_typeof(obj) == "Instance"
		and obj.ClassName == "Vector3Curve"

	obj:Destroy()

	return valid
end)

runCheck("api.path2d_optional", 0x766, function()
	local ok, obj = _pcall(function()
		return Instance.new("Path2D")
	end)

	if not ok or obj == nil then
		return true
	end

	local valid =
		_typeof(obj) == "Instance"
		and obj.ClassName == "Path2D"

	obj:Destroy()

	return valid
end)

runCheck("api.audiofilter_optional", 0x767, function()
	local ok, obj = _pcall(function()
		return Instance.new("AudioFilter")
	end)

	if not ok or obj == nil then
		return true
	end

	local valid =
		_typeof(obj) == "Instance"
		and obj.ClassName == "AudioFilter"

	obj:Destroy()

	return valid
end)


----------------------------------------------------------------
-- 7D. ENCODING / ZSTD / BUFFER INTEGRITY
--
-- EncodingService was added to the Roblox engine with Zstd compression,
-- hashing and Base64 buffer operations.
----------------------------------------------------------------

runCheck("encoding.service_shape", 0x768, function()
	local ok, service = _pcall(function()
		return game:GetService("EncodingService")
	end)

	if not ok or service == nil then
		-- Compatibility fallback for clients that do not expose it yet.
		return true
	end

	return
		_typeof(service) == "Instance"
		and service.ClassName == "EncodingService"
end)

runCheck("encoding.zstd_enum", 0x769, function()
	if Enum.CompressionAlgorithm == nil then
		return true
	end

	local zstd = Enum.CompressionAlgorithm.Zstd

	return
		_typeof(Enum.CompressionAlgorithm) == "Enum"
		and _typeof(zstd) == "EnumItem"
		and zstd.Name == "Zstd"
end)

runCheck("encoding.zstd_roundtrip", 0x76A, function()
	local okService, service = _pcall(function()
		return game:GetService("EncodingService")
	end)

	if not okService
		or service == nil
		or Enum.CompressionAlgorithm == nil
		or Enum.CompressionAlgorithm.Zstd == nil
		or buffer == nil
		or _type(buffer.fromstring) ~= "function"
		or _type(buffer.tostring) ~= "function"
	then
		return true
	end

	local payload =
		"ANTI_TAMPER_ZSTD_PROBE::"
		.. string.rep("ABCD1234", 32)
		.. "::END"

	local original = buffer.fromstring(payload)

	local okCompress, compressed = _pcall(function()
		return service:CompressBuffer(
			original,
			Enum.CompressionAlgorithm.Zstd,
			1
		)
	end)

	if not okCompress or _typeof(compressed) ~= "buffer" then
		return false
	end

	local okDecompress, decompressed = _pcall(function()
		return service:DecompressBuffer(
			compressed,
			Enum.CompressionAlgorithm.Zstd
		)
	end)

	if not okDecompress or _typeof(decompressed) ~= "buffer" then
		return false
	end

	return buffer.tostring(decompressed) == payload
end)

runCheck("encoding.zstd_size", 0x76B, function()
	local okService, service = _pcall(function()
		return game:GetService("EncodingService")
	end)

	if not okService
		or service == nil
		or Enum.CompressionAlgorithm == nil
		or Enum.CompressionAlgorithm.Zstd == nil
		or buffer == nil
		or _type(buffer.fromstring) ~= "function"
	then
		return true
	end

	local payload = string.rep("zstd-size-probe-", 20)
	local original = buffer.fromstring(payload)

	local okCompress, compressed = _pcall(function()
		return service:CompressBuffer(
			original,
			Enum.CompressionAlgorithm.Zstd,
			1
		)
	end)

	if not okCompress or _typeof(compressed) ~= "buffer" then
		return false
	end

	local okSize, size = _pcall(function()
		return service:GetDecompressedBufferSize(
			compressed,
			Enum.CompressionAlgorithm.Zstd
		)
	end)

	return
		okSize
		and _type(size) == "number"
		and size == #payload
end)

runCheck("encoding.zstd_deterministic_decode", 0x76C, function()
	local okService, service = _pcall(function()
		return game:GetService("EncodingService")
	end)

	if not okService
		or service == nil
		or Enum.CompressionAlgorithm == nil
		or Enum.CompressionAlgorithm.Zstd == nil
		or buffer == nil
		or _type(buffer.fromstring) ~= "function"
		or _type(buffer.tostring) ~= "function"
	then
		return true
	end

	local payload = string.rep("Q7k_", 80)
	local original = buffer.fromstring(payload)

	local okCompress, compressed = _pcall(function()
		return service:CompressBuffer(
			original,
			Enum.CompressionAlgorithm.Zstd,
			1
		)
	end)

	if not okCompress then
		return false
	end

	local okA, a = _pcall(function()
		return service:DecompressBuffer(
			compressed,
			Enum.CompressionAlgorithm.Zstd
		)
	end)

	local okB, b = _pcall(function()
		return service:DecompressBuffer(
			compressed,
			Enum.CompressionAlgorithm.Zstd
		)
	end)

	return
		okA
		and okB
		and _typeof(a) == "buffer"
		and _typeof(b) == "buffer"
		and buffer.tostring(a) == payload
		and buffer.tostring(b) == payload
end)

runCheck("encoding.base64_roundtrip", 0x76D, function()
	local okService, service = _pcall(function()
		return game:GetService("EncodingService")
	end)

	if not okService
		or service == nil
		or buffer == nil
		or _type(buffer.fromstring) ~= "function"
		or _type(buffer.tostring) ~= "function"
	then
		return true
	end

	local source = buffer.fromstring(
		"base64::Roblox::integrity::0123456789"
	)

	local okEncode, encoded = _pcall(function()
		return service:Base64Encode(source)
	end)

	if not okEncode or _typeof(encoded) ~= "buffer" then
		return false
	end

	local okDecode, decoded = _pcall(function()
		return service:Base64Decode(encoded)
	end)

	return
		okDecode
		and _typeof(decoded) == "buffer"
		and buffer.tostring(decoded)
			== "base64::Roblox::integrity::0123456789"
end)

runCheck("encoding.hash_enum", 0x76E, function()
	if Enum.HashAlgorithm == nil then
		return true
	end

	local names = {
		"Md5",
		"Sha1",
		"Sha256",
		"Blake2b",
		"Blake3",
	}

	for _, name in ipairs(names) do
		local value = Enum.HashAlgorithm[name]

		if value ~= nil then
			if _typeof(value) ~= "EnumItem" then
				return false
			end
		end
	end

	return true
end)

runCheck("encoding.sha256_string", 0x76F, function()
	local okService, service = _pcall(function()
		return game:GetService("EncodingService")
	end)

	if not okService
		or service == nil
		or Enum.HashAlgorithm == nil
		or Enum.HashAlgorithm.Sha256 == nil
	then
		return true
	end

	local okA, hashA = _pcall(function()
		return service:ComputeStringHash(
			"integrity-A",
			Enum.HashAlgorithm.Sha256
		)
	end)

	local okB, hashB = _pcall(function()
		return service:ComputeStringHash(
			"integrity-A",
			Enum.HashAlgorithm.Sha256
		)
	end)

	local okC, hashC = _pcall(function()
		return service:ComputeStringHash(
			"integrity-B",
			Enum.HashAlgorithm.Sha256
		)
	end)

	return
		okA
		and okB
		and okC
		and _type(hashA) == "string"
		and #hashA > 0
		and hashA == hashB
		and hashA ~= hashC
end)

runCheck("encoding.blake3_string_optional", 0x770, function()
	local okService, service = _pcall(function()
		return game:GetService("EncodingService")
	end)

	if not okService
		or service == nil
		or Enum.HashAlgorithm == nil
		or Enum.HashAlgorithm.Blake3 == nil
	then
		return true
	end

	local okA, hashA = _pcall(function()
		return service:ComputeStringHash(
			"blake3-probe",
			Enum.HashAlgorithm.Blake3
		)
	end)

	local okB, hashB = _pcall(function()
		return service:ComputeStringHash(
			"blake3-probe",
			Enum.HashAlgorithm.Blake3
		)
	end)

	return
		okA
		and okB
		and _type(hashA) == "string"
		and #hashA > 0
		and hashA == hashB
end)

runCheck("encoding.buffer_hash", 0x771, function()
	local okService, service = _pcall(function()
		return game:GetService("EncodingService")
	end)

	if not okService
		or service == nil
		or Enum.HashAlgorithm == nil
		or Enum.HashAlgorithm.Sha256 == nil
		or buffer == nil
		or _type(buffer.fromstring) ~= "function"
		or _type(buffer.tostring) ~= "function"
	then
		return true
	end

	local input = buffer.fromstring("buffer-hash-probe")

	local okA, hashA = _pcall(function()
		return service:ComputeBufferHash(
			input,
			Enum.HashAlgorithm.Sha256
		)
	end)

	local okB, hashB = _pcall(function()
		return service:ComputeBufferHash(
			input,
			Enum.HashAlgorithm.Sha256
		)
	end)

	return
		okA
		and okB
		and _typeof(hashA) == "buffer"
		and _typeof(hashB) == "buffer"
		and buffer.tostring(hashA) == buffer.tostring(hashB)
end)

runCheck("buffer.fromstring_tostring", 0x772, function()
	if buffer == nil
		or _type(buffer.fromstring) ~= "function"
		or _type(buffer.tostring) ~= "function"
	then
		return true
	end

	local s = "buffer-roundtrip\0binary\1\2\3"
	local b = buffer.fromstring(s)

	return
		_typeof(b) == "buffer"
		and buffer.tostring(b) == s
end)

runCheck("buffer.u8_rw", 0x773, function()
	if buffer == nil
		or _type(buffer.create) ~= "function"
		or _type(buffer.writeu8) ~= "function"
		or _type(buffer.readu8) ~= "function"
	then
		return true
	end

	local b = buffer.create(4)

	buffer.writeu8(b, 0, 0)
	buffer.writeu8(b, 1, 127)
	buffer.writeu8(b, 2, 255)
	buffer.writeu8(b, 3, 42)

	return
		buffer.readu8(b, 0) == 0
		and buffer.readu8(b, 1) == 127
		and buffer.readu8(b, 2) == 255
		and buffer.readu8(b, 3) == 42
end)

runCheck("buffer.i16_u16_rw", 0x774, function()
	if buffer == nil
		or _type(buffer.create) ~= "function"
		or _type(buffer.writei16) ~= "function"
		or _type(buffer.readi16) ~= "function"
		or _type(buffer.writeu16) ~= "function"
		or _type(buffer.readu16) ~= "function"
	then
		return true
	end

	local b = buffer.create(8)

	buffer.writei16(b, 0, -12345)
	buffer.writeu16(b, 2, 54321)

	return
		buffer.readi16(b, 0) == -12345
		and buffer.readu16(b, 2) == 54321
end)

runCheck("buffer.i32_u32_rw", 0x775, function()
	if buffer == nil
		or _type(buffer.create) ~= "function"
		or _type(buffer.writei32) ~= "function"
		or _type(buffer.readi32) ~= "function"
		or _type(buffer.writeu32) ~= "function"
		or _type(buffer.readu32) ~= "function"
	then
		return true
	end

	local b = buffer.create(12)

	buffer.writei32(b, 0, -123456789)
	buffer.writeu32(b, 4, 3234567890)

	return
		buffer.readi32(b, 0) == -123456789
		and buffer.readu32(b, 4) == 3234567890
end)

runCheck("buffer.float_rw", 0x776, function()
	if buffer == nil
		or _type(buffer.create) ~= "function"
		or _type(buffer.writef32) ~= "function"
		or _type(buffer.readf32) ~= "function"
		or _type(buffer.writef64) ~= "function"
		or _type(buffer.readf64) ~= "function"
	then
		return true
	end

	local b = buffer.create(16)

	buffer.writef32(b, 0, 3.25)
	buffer.writef64(b, 8, -123.5)

	return
		math.abs(buffer.readf32(b, 0) - 3.25) <= 1e-6
		and math.abs(buffer.readf64(b, 8) + 123.5) <= 1e-10
end)

runCheck("buffer.string_rw", 0x777, function()
	if buffer == nil
		or _type(buffer.create) ~= "function"
		or _type(buffer.writestring) ~= "function"
		or _type(buffer.readstring) ~= "function"
	then
		return true
	end

	local b = buffer.create(32)
	local value = "LuauBufferProbe"

	buffer.writestring(b, 3, value)

	return buffer.readstring(b, 3, #value) == value
end)

runCheck("buffer.fill", 0x778, function()
	if buffer == nil
		or _type(buffer.create) ~= "function"
		or _type(buffer.fill) ~= "function"
		or _type(buffer.readu8) ~= "function"
	then
		return true
	end

	local b = buffer.create(12)
	buffer.fill(b, 2, 0x5A, 7)

	for i = 2, 8 do
		if buffer.readu8(b, i) ~= 0x5A then
			return false
		end
	end

	return true
end)

runCheck("buffer.copy", 0x779, function()
	if buffer == nil
		or _type(buffer.fromstring) ~= "function"
		or _type(buffer.create) ~= "function"
		or _type(buffer.copy) ~= "function"
		or _type(buffer.tostring) ~= "function"
	then
		return true
	end

	local src = buffer.fromstring("ABCDEFGH")
	local dst = buffer.create(8)

	buffer.copy(dst, 0, src, 0, 8)

	return buffer.tostring(dst) == "ABCDEFGH"
end)

runCheck("buffer.bit_rw_optional", 0x77A, function()
	if buffer == nil
		or _type(buffer.create) ~= "function"
		or _type(buffer.writebits) ~= "function"
		or _type(buffer.readbits) ~= "function"
	then
		return true
	end

	local b = buffer.create(4)

	buffer.writebits(b, 3, 5, 0x15)

	return buffer.readbits(b, 3, 5) == 0x15
end)


----------------------------------------------------------------
-- 7E. 30+ ADDITIONAL ROBLOX API CHECKS
----------------------------------------------------------------

runCheck("api.remote_event_shape", 0x77B, function()
	local obj = Instance.new("RemoteEvent")
	local ok =
		_typeof(obj) == "Instance"
		and obj.ClassName == "RemoteEvent"
		and _typeof(obj.OnClientEvent) == "RBXScriptSignal"
	obj:Destroy()
	return ok
end)

runCheck("api.remote_function_shape", 0x77C, function()
	local obj = Instance.new("RemoteFunction")
	local ok =
		_typeof(obj) == "Instance"
		and obj.ClassName == "RemoteFunction"
	obj:Destroy()
	return ok
end)

runCheck("api.unreliable_remote_event_optional", 0x77D, function()
	local okNew, obj = _pcall(function()
		return Instance.new("UnreliableRemoteEvent")
	end)

	if not okNew or obj == nil then
		return true
	end

	local ok =
		_typeof(obj) == "Instance"
		and obj.ClassName == "UnreliableRemoteEvent"

	obj:Destroy()
	return ok
end)

runCheck("api.attribute_changed_signal", 0x77E, function()
	local obj = Instance.new("Folder")
	local signal = obj:GetAttributeChangedSignal("__guard_attr")

	local ok = _typeof(signal) == "RBXScriptSignal"

	obj:Destroy()
	return ok
end)

runCheck("api.descendant_added_signal", 0x77F, function()
	local obj = Instance.new("Folder")
	local signal = obj.DescendantAdded

	local ok = _typeof(signal) == "RBXScriptSignal"

	obj:Destroy()
	return ok
end)

runCheck("api.descendant_removing_signal", 0x780, function()
	local obj = Instance.new("Folder")
	local signal = obj.DescendantRemoving

	local ok = _typeof(signal) == "RBXScriptSignal"

	obj:Destroy()
	return ok
end)

runCheck("api.child_removed_signal", 0x781, function()
	local obj = Instance.new("Folder")
	local signal = obj.ChildRemoved

	local ok = _typeof(signal) == "RBXScriptSignal"

	obj:Destroy()
	return ok
end)

runCheck("api.destroying_signal", 0x782, function()
	local obj = Instance.new("Folder")
	local signal = obj.Destroying

	local ok = _typeof(signal) == "RBXScriptSignal"

	obj:Destroy()
	return ok
end)

runCheck("api.number_sequence_scalar_ctor", 0x783, function()
	local seq = NumberSequence.new(0.42)
	local keys = seq.Keypoints

	return
		_typeof(seq) == "NumberSequence"
		and #keys == 2
		and math.abs(keys[1].Value - 0.42) <= 1e-5
		and math.abs(keys[2].Value - 0.42) <= 1e-5
end)

runCheck("api.color_sequence_scalar_ctor", 0x784, function()
	local color = Color3.new(0.2, 0.4, 0.6)
	local seq = ColorSequence.new(color)
	local keys = seq.Keypoints

	return
		_typeof(seq) == "ColorSequence"
		and #keys == 2
		and math.abs(keys[1].Value.R - color.R) <= 1e-5
		and math.abs(keys[2].Value.B - color.B) <= 1e-5
end)

runCheck("api.color3_from_hex_optional", 0x785, function()
	if _type(Color3.fromHex) ~= "function" then
		return true
	end

	local c = Color3.fromHex("#336699")

	return
		_typeof(c) == "Color3"
		and math.abs(c.R - (0x33 / 255)) <= 1e-5
		and math.abs(c.G - (0x66 / 255)) <= 1e-5
		and math.abs(c.B - (0x99 / 255)) <= 1e-5
end)

runCheck("api.color3_to_hex_optional", 0x786, function()
	local c = Color3.fromRGB(51, 102, 153)

	if _type(c.ToHex) ~= "function" then
		return true
	end

	local hex = c:ToHex()

	return
		_type(hex) == "string"
		and string.lower(hex) == "336699"
end)

runCheck("api.cframe_lookat", 0x787, function()
	local from = Vector3.new(1, 2, 3)
	local to = Vector3.new(1, 2, -7)

	local cf = CFrame.lookAt(from, to)

	return
		_typeof(cf) == "CFrame"
		and (cf.Position - from).Magnitude <= 1e-6
end)

runCheck("api.cframe_lookalong_optional", 0x788, function()
	if _type(CFrame.lookAlong) ~= "function" then
		return true
	end

	local from = Vector3.new(4, 5, 6)
	local direction = Vector3.new(0, 0, -1)

	local cf = CFrame.lookAlong(from, direction)

	return
		_typeof(cf) == "CFrame"
		and (cf.Position - from).Magnitude <= 1e-6
end)

runCheck("api.cframe_euler_xyz", 0x789, function()
	local cf = CFrame.fromEulerAnglesXYZ(0.1, 0.2, 0.3)
	local x, y, z = cf:ToEulerAnglesXYZ()

	return
		_typeof(cf) == "CFrame"
		and _type(x) == "number"
		and _type(y) == "number"
		and _type(z) == "number"
end)

runCheck("api.random_unit_vector_optional", 0x78A, function()
	local rng = Random.new(1234)

	if _type(rng.NextUnitVector) ~= "function" then
		return true
	end

	local v = rng:NextUnitVector()

	return
		_typeof(v) == "Vector3"
		and math.abs(v.Magnitude - 1) <= 1e-4
end)

runCheck("api.enum_get_items", 0x78B, function()
	local items = Enum.Axis:GetEnumItems()

	return
		_type(items) == "table"
		and #items >= 3
		and _typeof(items[1]) == "EnumItem"
end)

runCheck("api.enum_from_value_optional", 0x78C, function()
	if _type(Enum.Axis.FromValue) ~= "function" then
		return true
	end

	local item = Enum.Axis:FromValue(Enum.Axis.X.Value)

	return item == Enum.Axis.X
end)

runCheck("api.datetime_now", 0x78D, function()
	local dt = DateTime.now()

	return
		_typeof(dt) == "DateTime"
		and _type(dt.UnixTimestampMillis) == "number"
		and dt.UnixTimestampMillis > 0
end)

runCheck("api.datetime_universal", 0x78E, function()
	-- DateTime itself exposes timestamps; calendar fields come from
	-- :ToUniversalTime(). Keep this compatibility-safe across client builds.
	if DateTime == nil
		or _type(DateTime.fromUniversalTime) ~= "function"
	then
		return true
	end

	local okCreate, dt = _pcall(function()
		return DateTime.fromUniversalTime(
			2024, 1, 2,
			3, 4, 5,
			0
		)
	end)

	-- Do not false-positive on a client where this constructor/signature
	-- is unavailable even though DateTime itself exists.
	if not okCreate or _typeof(dt) ~= "DateTime" then
		return true
	end

	if _type(dt.ToUniversalTime) ~= "function" then
		return true
	end

	local okParts, parts = _pcall(function()
		return dt:ToUniversalTime()
	end)

	if not okParts or _type(parts) ~= "table" then
		return true
	end

	return
		parts.Year == 2024
		and parts.Month == 1
		and parts.Day == 2
		and parts.Hour == 3
		and parts.Minute == 4
		and parts.Second == 5
end)

runCheck("api.marketplace_service_shape", 0x78F, function()
	local service = game:GetService("MarketplaceService")

	return
		_typeof(service) == "Instance"
		and service.ClassName == "MarketplaceService"
end)

runCheck("api.badge_service_shape", 0x790, function()
	local service = game:GetService("BadgeService")

	return
		_typeof(service) == "Instance"
		and service.ClassName == "BadgeService"
end)

runCheck("api.teleport_service_shape", 0x791, function()
	local service = game:GetService("TeleportService")

	return
		_typeof(service) == "Instance"
		and service.ClassName == "TeleportService"
end)

runCheck("api.teams_shape", 0x792, function()
	local service = game:GetService("Teams")

	return
		_typeof(service) == "Instance"
		and service.ClassName == "Teams"
end)

runCheck("api.starterpack_shape", 0x793, function()
	local service = game:GetService("StarterPack")

	return
		_typeof(service) == "Instance"
		and service.ClassName == "StarterPack"
end)

runCheck("api.starterplayer_shape", 0x794, function()
	local service = game:GetService("StarterPlayer")

	return
		_typeof(service) == "Instance"
		and service.ClassName == "StarterPlayer"
end)

runCheck("api.material_service_shape", 0x795, function()
	local service = game:GetService("MaterialService")

	return
		_typeof(service) == "Instance"
		and service.ClassName == "MaterialService"
end)

runCheck("api.vr_service_shape", 0x796, function()
	local okService, service = _pcall(function()
		return game:GetService("VRService")
	end)

	if not okService or service == nil then
		return true
	end

	return
		_typeof(service) == "Instance"
		and service.ClassName == "VRService"
end)

runCheck("api.haptic_service_shape", 0x797, function()
	local okService, service = _pcall(function()
		return game:GetService("HapticService")
	end)

	if not okService or service == nil then
		return true
	end

	return
		_typeof(service) == "Instance"
		and service.ClassName == "HapticService"
end)

runCheck("api.policy_service_shape", 0x798, function()
	local okService, service = _pcall(function()
		return game:GetService("PolicyService")
	end)

	if not okService or service == nil then
		return true
	end

	return
		_typeof(service) == "Instance"
		and service.ClassName == "PolicyService"
end)

runCheck("api.group_service_shape", 0x799, function()
	local okService, service = _pcall(function()
		return game:GetService("GroupService")
	end)

	if not okService or service == nil then
		return true
	end

	return
		_typeof(service) == "Instance"
		and service.ClassName == "GroupService"
end)

runCheck("api.log_service_shape", 0x79A, function()
	local service = game:GetService("LogService")

	return
		_typeof(service) == "Instance"
		and service.ClassName == "LogService"
end)

runCheck("api.change_history_service_optional", 0x79B, function()
	local okService, service = _pcall(function()
		return game:GetService("ChangeHistoryService")
	end)

	if not okService or service == nil then
		return true
	end

	return
		_typeof(service) == "Instance"
		and service.ClassName == "ChangeHistoryService"
end)

runCheck("api.selection_service_optional", 0x79C, function()
	local okService, service = _pcall(function()
		return game:GetService("Selection")
	end)

	if not okService or service == nil then
		return true
	end

	return
		_typeof(service) == "Instance"
		and service.ClassName == "Selection"
end)

runCheck("api.runservice_postsimulation_optional", 0x79D, function()
	local rs = game:GetService("RunService")

	if rs.PostSimulation == nil then
		return true
	end

	return _typeof(rs.PostSimulation) == "RBXScriptSignal"
end)

runCheck("api.runservice_presimulation_optional", 0x79E, function()
	local rs = game:GetService("RunService")

	if rs.PreSimulation == nil then
		return true
	end

	return _typeof(rs.PreSimulation) == "RBXScriptSignal"
end)

runCheck("api.runservice_preanimation_optional", 0x79F, function()
	local rs = game:GetService("RunService")

	if rs.PreAnimation == nil then
		return true
	end

	return _typeof(rs.PreAnimation) == "RBXScriptSignal"
end)

runCheck("api.runservice_prerender_optional", 0x7A0, function()
	local rs = game:GetService("RunService")

	if rs.PreRender == nil then
		return true
	end

	return _typeof(rs.PreRender) == "RBXScriptSignal"
end)

----------------------------------------------------------------
-- 8. HTTPSERVICE LOCAL SEMANTICS
----------------------------------------------------------------

runCheck("http.guid", 0x801, function()
	local http = game:GetService("HttpService")

	local a = http:GenerateGUID(false)
	local b = http:GenerateGUID(false)

	return
		_type(a) == "string"
		and _type(b) == "string"
		and #a > 20
		and #b > 20
		and a ~= b
end)

runCheck("http.json", 0x802, function()
	local http = game:GetService("HttpService")

	local encoded = http:JSONEncode({
		alpha = 81,
		flag = true,
		text = "__probe",
	})

	local decoded = http:JSONDecode(encoded)

	return
		decoded.alpha == 81
		and decoded.flag == true
		and decoded.text == "__probe"
end)

----------------------------------------------------------------
-- 9. ENUM SEMANTICS
----------------------------------------------------------------

runCheck("enum.basic", 0x901, function()
	local item = Enum.Material.Plastic

	return
		_typeof(Enum.Material) == "Enum"
		and _typeof(item) == "EnumItem"
		and item.Name == "Plastic"
		and item.EnumType == Enum.Material
end)

runCheck("enum.axis", 0x902, function()
	return
		Enum.Axis.X.Name == "X"
		and Enum.Axis.Y.Name == "Y"
		and Enum.Axis.Z.Name == "Z"
end)

----------------------------------------------------------------
-- 10. RUNSERVICE / STUDIO RUNTIME SANITY
--
-- These validate Roblox runtime behavior only. They do not block Studio.
----------------------------------------------------------------

runCheck("studio.is_studio_type", 0x951, function()
	local runService = game:GetService("RunService")
	local value = runService:IsStudio()

	if debug_mode then
		print(("[anti-tamper] Studio=%s"):format(_tostring(value)))
	end

	return _type(value) == "boolean"
end)

runCheck("studio.is_running_type", 0x952, function()
	local runService = game:GetService("RunService")
	local value = runService:IsRunning()

	return _type(value) == "boolean"
end)

runCheck("studio.client_state", 0x953, function()
	local runService = game:GetService("RunService")
	local isClient = runService:IsClient()
	local isServer = runService:IsServer()

	return
		_type(isClient) == "boolean"
		and _type(isServer) == "boolean"
		and not (isClient and isServer)
end)

runCheck("studio.context_consistency", 0x954, function()
	local runService = game:GetService("RunService")

	local studioA = runService:IsStudio()
	local studioB = runService:IsStudio()
	local clientA = runService:IsClient()
	local clientB = runService:IsClient()

	return
		studioA == studioB
		and clientA == clientB
end)

----------------------------------------------------------------
-- 11. INTERNAL STATE CROSS-CHECK
----------------------------------------------------------------

runCheck("state.redundancy", 0xA01, function()
	local a = mix32(_bxor(STATE_A, STATE_C, 0x517CC1B7))
	local b = mix32(_bxor(STATE_A, STATE_C, 0x517CC1B7))

	return a == b
end)

runCheck("state.progress", 0xA02, function()
	return
		GENERATION > 20
		and STATE_A ~= 0
		and STATE_B ~= 0
		and STATE_C ~= 0
		and STATE_D ~= 0
end)


----------------------------------------------------------------
-- RUNTIME AUTHENTICITY / MOCK-ENV CHECKS
--
-- Defensive only: validates normal Roblox/Luau semantics.
-- Does NOT probe for debuggers, sandboxes, VMs, analysis tools, files,
-- processes, network endpoints, or attempt environment evasion.
----------------------------------------------------------------

runCheck("runtime.datamodel_identity", 0xA31, function()
	return
		game ~= nil
		and _typeof(game) == "Instance"
		and game.ClassName == "DataModel"
		and _type(game.GetService) == "function"
end)

runCheck("runtime.instance_roundtrip", 0xA32, function()
	local parent = Instance.new("Folder")
	local child = Instance.new("Folder")
	child.Name = "__guard_child"
	child.Parent = parent

	local found = parent:FindFirstChild("__guard_child")

	local ok =
		found == child
		and child.Parent == parent
		and child:IsDescendantOf(parent)
		and parent:IsAncestorOf(child)

	child:Destroy()
	parent:Destroy()

	return ok
end)

runCheck("runtime.signal_semantics", 0xA33, function()
	local bindable = Instance.new("BindableEvent")
	local fired = false
	local gotA, gotB

	local connection = bindable.Event:Connect(function(a, b)
		fired = true
		gotA = a
		gotB = b
	end)

	bindable:Fire("__runtime_probe", 9182)

	for _ = 1, 5 do
		if fired then
			break
		end
		task.wait()
	end

	local ok =
		fired
		and gotA == "__runtime_probe"
		and gotB == 9182
		and _typeof(bindable.Event) == "RBXScriptSignal"

	connection:Disconnect()
	bindable:Destroy()

	return ok
end)

runCheck("runtime.attribute_semantics", 0xA34, function()
	local obj = Instance.new("Folder")

	obj:SetAttribute("__a", 123)
	obj:SetAttribute("__b", true)
	obj:SetAttribute("__c", "xyz")

	local attrs = obj:GetAttributes()

	local ok =
		_type(attrs) == "table"
		and attrs.__a == 123
		and attrs.__b == true
		and attrs.__c == "xyz"

	obj:SetAttribute("__a", nil)

	ok =
		ok
		and obj:GetAttribute("__a") == nil

	obj:Destroy()

	return ok
end)

runCheck("runtime.collection_semantics", 0xA35, function()
	local cs = game:GetService("CollectionService")
	local obj = Instance.new("Folder")

	local tagA = "__rt_a"
	local tagB = "__rt_b"

	cs:AddTag(obj, tagA)
	cs:AddTag(obj, tagB)

	local hasA = cs:HasTag(obj, tagA)
	local hasB = cs:HasTag(obj, tagB)

	local tags = cs:GetTags(obj)

	local seenA, seenB = false, false

	for _, tag in ipairs(tags) do
		if tag == tagA then
			seenA = true
		elseif tag == tagB then
			seenB = true
		end
	end

	cs:RemoveTag(obj, tagA)
	cs:RemoveTag(obj, tagB)

	local removed =
		not cs:HasTag(obj, tagA)
		and not cs:HasTag(obj, tagB)

	obj:Destroy()

	return
		hasA
		and hasB
		and seenA
		and seenB
		and removed
end)

runCheck("runtime.vector_semantics", 0xA36, function()
	local a = Vector3.new(3, 4, 0)
	local b = Vector3.new(0, 0, 5)

	local dot = a:Dot(b)
	local cross = a:Cross(b)

	return
		math.abs(a.Magnitude - 5) <= 1e-6
		and dot == 0
		and cross == Vector3.new(20, -15, 0)
end)

runCheck("runtime.cframe_semantics", 0xA37, function()
	local a = CFrame.new(1, 2, 3)
	local b = CFrame.new(4, 5, 6)
	local c = a * b
	local inv = a * a:Inverse()

	return
		_typeof(c) == "CFrame"
		and inv.Position.Magnitude <= 1e-5
end)

runCheck("runtime.json_semantics", 0xA38, function()
	local http = game:GetService("HttpService")

	local source = {
		x = 17,
		y = true,
		z = "guard",
		arr = {1, 2, 3},
	}

	local encoded = http:JSONEncode(source)
	local decoded = http:JSONDecode(encoded)

	return
		_type(encoded) == "string"
		and decoded.x == 17
		and decoded.y == true
		and decoded.z == "guard"
		and _type(decoded.arr) == "table"
		and decoded.arr[3] == 3
end)

runCheck("runtime.service_consistency", 0xA39, function()
	local names = {
		"Players",
		"RunService",
		"HttpService",
		"CollectionService",
		"TweenService",
		"PathfindingService",
	}

	for _, name in ipairs(names) do
		local a = game:GetService(name)
		local b = game:GetService(name)

		if
			_typeof(a) ~= "Instance"
			or _typeof(b) ~= "Instance"
			or a ~= b
		then
			return false
		end
	end

	return true
end)

runCheck("runtime.enum_semantics", 0xA3A, function()
	local items = Enum.Axis:GetEnumItems()

	if _type(items) ~= "table" or #items < 3 then
		return false
	end

	for _, item in ipairs(items) do
		if _typeof(item) ~= "EnumItem" then
			return false
		end

		if item.EnumType ~= Enum.Axis then
			return false
		end
	end

	return true
end)

runCheck("runtime.clone_semantics", 0xA3B, function()
	local src = Instance.new("Folder")
	src.Name = "__clone_src"
	src:SetAttribute("__n", 772)

	local child = Instance.new("StringValue")
	child.Name = "__child"
	child.Value = "ok"
	child.Parent = src

	local clone = src:Clone()

	local cloneChild = clone:FindFirstChild("__child")

	local ok =
		clone ~= src
		and clone.Name == "__clone_src"
		and clone:GetAttribute("__n") == 772
		and cloneChild ~= nil
		and cloneChild:IsA("StringValue")
		and cloneChild.Value == "ok"

	src:Destroy()
	clone:Destroy()

	return ok
end)

runCheck("runtime.scheduler_shape", 0xA3C, function()
	return
		_type(task) == "table"
		and _type(task.spawn) == "function"
		and _type(task.defer) == "function"
		and _type(task.delay) == "function"
		and _type(task.wait) == "function"
end)

runCheck("runtime.runservice_consistency", 0xA3D, function()
	local rs = game:GetService("RunService")

	local studioA = rs:IsStudio()
	local studioB = rs:IsStudio()
	local clientA = rs:IsClient()
	local clientB = rs:IsClient()

	return
		_type(studioA) == "boolean"
		and _type(clientA) == "boolean"
		and studioA == studioB
		and clientA == clientB
end)

----------------------------------------------------------------
-- 12. EXECUTOR API CHECKS
-- MUST STAY AT THE END.
--
-- Passive only. Missing optional APIs are allowed for compatibility.
-- If an API exists but has an impossible/wrong type, the check fails.
----------------------------------------------------------------

local function safeGlobal(name)
	local ok, value = _pcall(function()
		return _G[name]
	end)

	if ok then
		return value
	end

	return nil
end

local function readPath(root, path)
	local current = root

	for part in string.gmatch(path, "[^%.]+") do
		if _type(current) ~= "table" then
			return nil
		end

		local ok, value = _pcall(function()
			return current[part]
		end)

		if not ok then
			return nil
		end

		current = value
	end

	return current
end

local function pushUniqueRoot(roots, value)
	if _type(value) ~= "table" then
		return
	end

	for _, existing in ipairs(roots) do
		if _rawequal(existing, value) then
			return
		end
	end

	roots[#roots + 1] = value
end

local function collectExecutorRoots()
	local roots = {}

	-- Some executors mirror globals into _G, others do not.
	pushUniqueRoot(roots, _G)

	-- The active Luau environment is an important compatibility fallback.
	if _type(getfenv) == "function" then
		for _, level in ipairs({0, 1}) do
			local ok, env = _pcall(getfenv, level)

			if ok then
				pushUniqueRoot(roots, env)
			end
		end
	end

	-- Resolve getgenv from all roots gathered so far.
	local getgenvValue = nil

	for _, root in ipairs(roots) do
		local candidate = readPath(root, "getgenv")

		if _type(candidate) == "function" then
			getgenvValue = candidate
			break
		end
	end

	if getgenvValue ~= nil then
		local ok, env = _pcall(getgenvValue)

		if ok then
			pushUniqueRoot(roots, env)
		end
	end

	-- Some runtimes expose getrenv even when getgenv is absent/hidden.
	local getrenvValue = nil

	for _, root in ipairs(roots) do
		local candidate = readPath(root, "getrenv")

		if _type(candidate) == "function" then
			getrenvValue = candidate
			break
		end
	end

	if getrenvValue ~= nil then
		local ok, env = _pcall(getrenvValue)

		if ok then
			pushUniqueRoot(roots, env)
		end
	end

	return roots
end

local EXEC_ROOTS = collectExecutorRoots()

local function readExecutorPath(path)
	for _, root in ipairs(EXEC_ROOTS) do
		local value = readPath(root, path)

		if value ~= nil then
			return value
		end
	end

	return nil
end

local executorSpecs = {
	-- environment
	{ "getgenv", "function" },
	{ "getrenv", "function" },
	{ "getsenv", "function" },
	{ "getgc", "function" },
	{ "getreg", "function" },

	-- closure / hook
	{ "hookfunction", "function" },
	{ "hookmetamethod", "function" },
	{ "newcclosure", "function" },
	{ "checkcaller", "function" },
	{ "iscclosure", "function" },
	{ "islclosure", "function" },

	-- script/introspection
	{ "getscriptbytecode", "function" },
	{ "getscripthash", "function" },
	{ "getloadedmodules", "function" },
	{ "getconnections", "function" },

	-- instance helpers
	{ "getinstances", "function" },
	{ "getnilinstances", "function" },
	{ "cloneref", "function" },
	{ "compareinstances", "function" },

	-- identity
	{ "identifyexecutor", "function" },
	{ "getexecutorname", "function" },

	-- commonly namespaced
	{ "syn", "table" },
	{ "crypt", "table" },
	{ "cache", "table" },
	{ "Drawing", "table" },
}

runCheck("executor.api_types", 0xB01, function()
	for _, spec in ipairs(executorSpecs) do
		local name = spec[1]
		local expectedType = spec[2]

		local value = readExecutorPath(name)

		-- Optional API: absent is okay.
		-- But if present, its type must look sane.
		if value ~= nil and _type(value) ~= expectedType then
			if debug_mode then
				warn(
					("[anti-tamper] malformed executor API: %s -> %s")
						:format(name, _type(value))
				)
			end

			return false
		end
	end

	return true
end)

runCheck("executor.namespaced_types", 0xB02, function()
	local optionalFunctions = {
		"syn.request",
		"crypt.encrypt",
		"crypt.decrypt",
		"crypt.hash",
		"cache.invalidate",
		"cache.iscached",
		"cache.replace",
		"Drawing.new",
	}

	for _, path in ipairs(optionalFunctions) do
		local value = readExecutorPath(path)

		if value ~= nil and _type(value) ~= "function" then
			if debug_mode then
				warn(
					("[anti-tamper] malformed executor API: %s -> %s")
						:format(path, _type(value))
				)
			end

			return false
		end
	end

	return true
end)


runCheck("executor.alias_matrix", 0xB04, function()
	local aliasGroups = {
		{ "identifyexecutor", "getexecutorname" },
		{ "request", "http_request", "syn.request", "http.request" },
		{ "queue_on_teleport", "queueonteleport", "syn.queue_on_teleport" },
		{ "setclipboard", "toclipboard" },
		{ "getthreadidentity", "getidentity" },
		{ "setthreadidentity", "setidentity" },
	}

	for _, aliases in ipairs(aliasGroups) do
		for _, name in ipairs(aliases) do
			local value = readExecutorPath(name)

			if value ~= nil and _type(value) ~= "function" then
				return false
			end
		end
	end

	return true
end)

runCheck("executor.namespace_matrix", 0xB05, function()
	local namespaceSpecs = {
		{
			name = "syn",
			members = {
				"request",
				"queue_on_teleport",
				"protect_gui",
				"unprotect_gui",
			},
		},
		{
			name = "crypt",
			members = {
				"encrypt",
				"decrypt",
				"hash",
				"base64encode",
				"base64decode",
			},
		},
		{
			name = "cache",
			members = {
				"invalidate",
				"iscached",
				"replace",
				"cloneref",
			},
		},
		{
			name = "Drawing",
			members = {
				"new",
			},
		},
	}

	for _, spec in ipairs(namespaceSpecs) do
		local ns = readExecutorPath(spec.name)

		if ns ~= nil then
			if _type(ns) ~= "table" then
				return false
			end

			for _, member in ipairs(spec.members) do
				local path = spec.name .. "." .. member
				local value = readExecutorPath(path)

				if value ~= nil and _type(value) ~= "function" then
					return false
				end
			end
		end
	end

	return true
end)

runCheck("executor.passive_surface", 0xB06, function()
	local functionSpecs = {
		"getgenv", "getrenv", "getsenv", "getfenv", "setfenv", "getgc", "getreg",
		"hookfunction", "hookmetamethod", "newcclosure", "clonefunction",
		"checkcaller", "iscclosure", "islclosure", "isexecutorclosure", "isourclosure",
		"getrawmetatable", "setrawmetatable", "setreadonly", "isreadonly",
		"make_readonly", "make_writeable", "getnamecallmethod", "setnamecallmethod",
		"getscriptbytecode", "dumpstring", "getscripthash", "getscriptclosure",
		"getloadedmodules", "getconnections", "firesignal",
		"getinstances", "getnilinstances", "cloneref", "compareinstances",
		"gethui", "gethiddenproperty", "sethiddenproperty", "getproperties",
		"gethiddenproperties", "identifyexecutor", "getexecutorname",
		"getthreadidentity", "setthreadidentity", "getidentity", "setidentity",
		"isfile", "isfolder", "readfile", "writefile", "appendfile", "makefolder",
		"delfile", "delfolder", "listfiles", "loadfile", "request", "http_request",
		"queue_on_teleport", "queueonteleport", "setclipboard", "toclipboard",
		"mouse1click", "mouse1press", "mouse1release",
		"mouse2click", "mouse2press", "mouse2release",
		"keypress", "keyrelease", "rconsoleprint", "rconsolewarn", "rconsoleerr",
		"rconsoleclear", "rconsolename", "isrenderobj",
		"getrenderproperty", "setrenderproperty",
	}

	for _, name in ipairs(functionSpecs) do
		local value = readExecutorPath(name)

		if value ~= nil and _type(value) ~= "function" then
			if debug_mode then
				warn(("[anti-tamper] malformed passive API: %s -> %s")
					:format(name, _type(value)))
			end

			return false
		end
	end

	return true
end)

runCheck("executor.env_crosscheck", 0xB07, function()
	if #EXEC_ROOTS < 1 then
		return false
	end

	local known = {
		"getgenv",
		"getrenv",
		"hookfunction",
		"newcclosure",
		"checkcaller",
		"identifyexecutor",
		"getexecutorname",
		"getconnections",
		"cloneref",
		"gethui",
	}

	for _, name in ipairs(known) do
		local seenType = nil

		for _, root in ipairs(EXEC_ROOTS) do
			local value = readPath(root, name)

			if value ~= nil then
				local t = _type(value)

				if t ~= "function" then
					return false
				end

				if seenType ~= nil and seenType ~= t then
					return false
				end

				seenType = t
			end
		end
	end

	return true
end)

runCheck("executor.table_shape", 0xB08, function()
	for _, nsName in ipairs({ "syn", "crypt", "cache", "Drawing" }) do
		local ns = readExecutorPath(nsName)

		if ns ~= nil then
			if _type(ns) ~= "table" then
				return false
			end

			local okPairs = _pcall(function()
				for _ in _pairs(ns) do
					break
				end
			end)

			if not okPairs then
				return false
			end
		end
	end

	return true
end)

runCheck("executor.capability_fingerprint", 0xB09, function()
	local capabilities = {
		{ "getgenv", "getrenv", "getsenv" },
		{ "hookfunction", "hookmetamethod", "newcclosure", "checkcaller" },
		{ "getinstances", "getnilinstances", "cloneref", "gethui" },
		{ "isfile", "readfile", "writefile", "request" },
	}

	local fingerprint = 0
	local bit = 1

	for _, names in ipairs(capabilities) do
		local groupPresent = false

		for _, name in ipairs(names) do
			if _type(readExecutorPath(name)) == "function" then
				groupPresent = true
				break
			end
		end

		if groupPresent then
			fingerprint += bit
		end

		bit *= 2
	end

	STATE_D = mix32(_bxor(STATE_D, fingerprint, 0x0BADC0DE))

	return true
end)

runCheck("executor.environment_shape", 0xB03, function()
	if #EXEC_ROOTS == 0 then
		return false
	end

	local hints = 0
	local namespaces = 0

	for _, nsName in ipairs({ "syn", "crypt", "cache", "Drawing" }) do
		if _type(readExecutorPath(nsName)) == "table" then
			namespaces += 1
		end
	end

	-- Broad passive capability set. These functions are never invoked.
	local hintNames = {
		"getgenv",
		"getrenv",
		"getsenv",
		"hookfunction",
		"hookmetamethod",
		"newcclosure",
		"checkcaller",
		"identifyexecutor",
		"getexecutorname",
		"getconnections",
		"cloneref",
		"isexecutorclosure",
		"isourclosure",
		"gethui",
		"gethiddenproperty",
		"sethiddenproperty",
		"getnamecallmethod",
		"setnamecallmethod",
		"getthreadidentity",
		"setthreadidentity",
		"queue_on_teleport",
		"request",
		"http_request",
		"isfile",
		"readfile",
		"setclipboard",
	}

	for _, name in ipairs(hintNames) do
		if _type(readExecutorPath(name)) == "function" then
			hints += 1
		end
	end

	if not require_executor_hint then
		return true
	end

	if hints >= 1 or namespaces >= 1 then
		return true
	end

	-- A few executors intentionally hide their injected API table.
	-- Avoid a false positive by requiring a strong real Roblox/Luau shape.
	local engineFallback =
		_typeof(game) == "Instance"
		and game.ClassName == "DataModel"
		and _typeof(workspace) == "Instance"
		and workspace:IsA("Workspace")
		and _type(Instance) == "table"
		and _type(Instance.new) == "function"
		and _type(task) == "table"
		and _type(task.defer) == "function"
		and _type(bit32) == "table"
		and _type(typeof) == "function"

	if debug_mode and engineFallback then
		print("[anti-tamper] executor API surface hidden -> Roblox runtime fallback accepted")
	end

	return engineFallback
end)

----------------------------------------------------------------
-- FINISH
----------------------------------------------------------------

if debug_mode then
	print(
		("[anti-tamper] completed | checks=%d | state=%08X")
			:format(GENERATION, step(0xC01))
	)
end

print("hii")

return Guard
