--!nonstrict
---@diagnostic disable: undefined-global, undefined-field, deprecated

local _pc = pcall
local _in = Instance.new
local _gs = game.GetService
local _typeof = typeof
local _os = os.clock
local _sf = string.find
local _ss = string.sub
local _mf = math.floor
local _mr = math.rad
local _mc = math.clamp
local _ms = math.sign
local _mn = math.noise
local _tf = table.freeze
local _ti = table.isfrozen
local _ts = table.sort
local _tp = table.pack
local _sb = string.byte
local _sp = string.pack
local function runDtcSuite()
  local t1 = _os()
  for i = 1, 50 do _pc(function() return 1 + i end) end
  if (_os() - t1) > 0.05 then return false, "Execution timing anomaly" end
  local s_ml, err_ml = _pc(math.log)
  if s_ml or not _sf(tostring(err_ml), "missing") then return false, "Math library tampered" end
  local s_rs, rs = _pc(function() return _gs(game, "RunService") end)
  if s_rs and rs then
    local s_svr, is_svr = _pc(function() return rs:IsServer() end)
    if not s_svr or is_svr == true then return false, "RunService context spoofed" end
    local s_cli, is_cli = _pc(function() return rs:IsClient() end)
    if not s_cli or is_cli == false then return false, "RunService client spoofed" end
  end
  local s_h, http = _pc(function() return _gs(game, "HttpService") end)
  if s_h and http then
    local s_g, guid = _pc(function() return http:GenerateGUID(false) end)
    if not s_g or _typeof(guid) ~= "string" or #guid ~= 36 then return false, "HttpService GUID spoofing" end
    local s_e, enc = _pc(function() return http:JSONEncode({t=true}) end)
    if not s_e or _typeof(enc) ~= "string" or not _sf(enc, "true") then return false, "HttpService JSONEncode spoofed" end
    local s_ue, ue = _pc(function() return http:UrlEncode("a b 1") end)
    if not s_ue or _typeof(ue) ~= "string" or not _sf(ue, "%%20") then return false, "HttpService UrlEncode spoofed" end
  end
  local s_es, es = _pc(function() return _gs(game, "EncodingService") end)
  if s_es and es then
    local s_b, b = _pc(buffer.create, 4)
    if s_b and b then
      _pc(buffer.writestring, b, 0, "test")
      local s_c, comp = _pc(function() return es:CompressBuffer(b, Enum.CompressionAlgorithm.Zstd, 10) end)
      if not s_c or _typeof(comp) ~= "buffer" then return false, "EncodingService buffer spoofed" end
    end
  end
  local s_ws, ws = _pc(function() return _gs(game, "Workspace") end)
  if s_ws and ws then
    local s_st, st = _pc(function() return ws:GetServerTimeNow() end)
    if not s_st or _typeof(st) ~= "number" then return false, "Workspace ServerTime spoofed" end
    local s_gr, gr = _pc(function() return ws.Gravity end)
    if not s_gr or _typeof(gr) ~= "number" or gr == 0 then return false, "Workspace Gravity spoofed" end
  end
  local s_li, li = _pc(function() return _gs(game, "Lighting") end)
  if s_li and li then
    local s_mt, mt = _pc(function() return li:GetMinutesAfterMidnight() end)
    if not s_mt or _typeof(mt) ~= "number" then return false, "Lighting time spoofed" end
  end
  local s_ss, ss = _pc(function() return _gs(game, "SoundService") end)
  if s_ss and ss then
    local s_ar, ar = _pc(function() return ss.AmbientReverb end)
    if not s_ar or _typeof(ar) ~= "EnumItem" then return false, "SoundService enum spoofed" end
  end
  local s_ui, ui = _pc(function() return _gs(game, "UserInputService") end)
  if s_ui and ui then
    local s_lt, lt = _pc(function() return ui:GetLastInputType() end)
    if not s_lt or _typeof(lt) ~= "EnumItem" then return false, "UserInputService input spoofed" end
  end
  local s_col, col = _pc(function() return _gs(game, "CollectionService") end)
  if s_col and col then
    local s_gt, gt = _pc(function() return col:GetTags() end)
    if not s_gt or _typeof(gt) ~= "table" then return false, "CollectionService GetTags spoofed" end
  end
  local s_gui, gui = _pc(function() return _gs(game, "GuiService") end)
  if s_gui and gui then
    local s_gi, gi = _pc(function() return gui:GetGuiInset() end)
    if not s_gi or _typeof(gi) ~= "Vector2" then return false, "GuiService inset spoofed" end
  end
  local s_vr, vr = _pc(function() return _gs(game, "VRService") end)
  if s_vr and vr then
    local s_ve, ve = _pc(function() return vr.VREnabled end)
    if not s_ve or _typeof(ve) ~= "boolean" then return false, "VRService spoofed" end
  end
  local s_vc, vc = _pc(function() return _gs(game, "VoiceChatService") end)
  if s_vc and vc then
    local s_vce, vce = _pc(function() return vc.EnableDefaultVoice end)
    if not s_vce or _typeof(vce) ~= "boolean" then return false, "VoiceChatService spoofed" end
  end
  local d_inf = debug and debug[_ss("dummy_info", 7, 10)]
  if d_inf then
    local s, r = _pc(function() return d_inf(_pc, "s") end)
    if s and _typeof(r) == "string" and (_sf(r, "sc") or _sf(r, "pt") or _sf(r, "w")) then return false, "Debug info trace exposed" end
    local s_up, up = _pc(function() return debug.getupvalue(getfenv, 1) end)
    if s_up and up ~= nil then return false, "Debug getupvalue leak" end
  end
  local s_gf, r_gf = _pc(getfenv, 999)
  if s_gf then return false, "Getfenv stack bypass" end
  local s_mc, r_mc = _pc(_mc, 5, 1, 10)
  if not s_mc or r_mc ~= 5 then return false, "Math.clamp spoofed" end
  local s_ms, r_ms = _pc(_ms, -5)
  if not s_ms or r_ms ~= -1 then return false, "Math.sign spoofed" end
  local s_mn, r_mn = _pc(_mn, 1.5, 2.5, 3.5)
  if not s_mn or _typeof(r_mn) ~= "number" then return false, "Math.noise spoofed" end
  local s_sr, r_sr = _pc(string.reverse, "dtc")
  if not s_sr or r_sr ~= "ctd" then return false, "String.reverse spoofed" end
  local s_sb, r_sb = _pc(_sb, "A")
  if not s_sb or r_sb ~= 65 then return false, "String.byte spoofed" end
  local s_utf, utf_len = _pc(utf8.len, "🔥abc")
  if not s_utf or utf_len ~= 4 then return false, "UTF8 spoofing" end
  local s1, r1 = _pc(Axes.new, Enum.Axis.X)
  if not s1 or _typeof(r1) ~= "Axes" then return false, "Axes spoofed" end
  local s2, r2 = _pc(Faces.new, Enum.NormalId.Top)
  if not s2 or _typeof(r2) ~= "Faces" then return false, "Faces spoofed" end
  local s3, r3 = _pc(NumberRange.new, 1, 2)
  if not s3 or _typeof(r3) ~= "NumberRange" then return false, "NumberRange spoofed" end
  local s4, r4 = _pc(Region3int16.new, Vector3int16.new(0,0,0), Vector3int16.new(1,1,1))
  if not s4 or _typeof(r4) ~= "Region3int16" then return false, "Region3int16 spoofed" end
  local s5, r5 = _pc(PhysicalProperties.new, 0.7, 0.3, 0.5)
  if not s5 or _typeof(r5) ~= "PhysicalProperties" then return false, "PhysicalProperties spoofed" end
  local s6, r6 = _pc(Region3.new, Vector3.new(0,0,0), Vector3.new(1,1,1))
  if not s6 or _typeof(r6) ~= "Region3" then return false, "Region3 spoofed" end
  local s7, r7 = _pc(Rect.new, 0, 0, 10, 10)
  if not s7 or _typeof(r7) ~= "Rect" then return false, "Rect spoofed" end
  local s8, r8 = _pc(UDim.new, 0.5, 10)
  if not s8 or _typeof(r8) ~= "UDim" then return false, "UDim spoofed" end
  local s9, r9 = _pc(UDim2.new, 0.5, 50, 0.5, 50)
  if not s9 or _typeof(r9) ~= "UDim2" then return false, "UDim2 spoofed" end
  local s10, r10 = _pc(Ray.new, Vector3.new(), Vector3.new(0,1,0))
  if not s10 or _typeof(r10) ~= "Ray" then return false, "Ray spoofed" end
  local s11, r11 = _pc(PathWaypoint.new, Vector3.new(), Enum.PathWaypointAction.Walk)
  if not s11 or _typeof(r11) ~= "PathWaypoint" then return false, "PathWaypoint spoofed" end
  local s12, r12 = _pc(ColorSequence.new, Color3.new(1,0,0))
  if not s12 or _typeof(r12) ~= "ColorSequence" then return false, "ColorSequence spoofed" end
  local s13, r13 = _pc(NumberSequence.new, 1)
  if not s13 or _typeof(r13) ~= "NumberSequence" then return false, "NumberSequence spoofed" end
  local s14, r14 = _pc(DateTime.fromUnixTimestamp, 1000)
  if not s14 or r14.UnixTimestamp ~= 1000 then return false, "DateTime spoofed" end
  local s15, r15 = _pc(Random.new, 999)
  if not s15 or _typeof(r15:Clone()) ~= "Random" then return false, "Random spoofed" end
  local s16, r16 = _pc(Font.fromEnum, Enum.Font.GothamBold)
  if not s16 or _typeof(r16) ~= "Font" then return false, "Font spoofed" end
  local s17, r17 = _pc(Vector3.new, 3, 4, 0)
  if not s17 or _mf(r17.Magnitude) ~= 5 then return false, "Vector3 math spoofed" end
  local s18, r18 = _pc(CFrame.Angles, _mr(45), 0, 0)
  if not s18 or _typeof(r18) ~= "CFrame" then return false, "CFrame math spoofed" end
  local s19, r19 = _pc(RaycastParams.new)
  if not s19 or _typeof(r19) ~= "RaycastParams" then return false, "RaycastParams spoofed" end
  local s20, r20 = _pc(OverlapParams.new)
  if not s20 or _typeof(r20) ~= "OverlapParams" then return false, "OverlapParams spoofed" end
  local s_vd, r_vd = _pc(function() return Vector3.new(1,2,3):Dot(Vector3.new(4,5,6)) end)
  if not s_vd or r_vd ~= 32 then return false, "Vector3 Dot spoofing" end
  local s_vc, r_vc = _pc(function() return Vector3.new(1,0,0):Cross(Vector3.new(0,1,0)) end)
  if not s_vc or _typeof(r_vc) ~= "Vector3" or r_vc.Z ~= 1 then return false, "Vector3 Cross spoofing" end
  local s_ch, h, s_c, v_c = _pc(function() return Color3.fromRGB(255, 128, 64):ToHSV() end)
  if not s_ch or _typeof(h) ~= "number" or s_c <= 0 then return false, "Color3 HSV spoofed" end
  local s_co, co = _pc(coroutine.create, function() coroutine.yield("neo") end)
  if not s_co or _typeof(co) ~= "thread" then return false, "Coroutine create spoofed" end
  local s_cr, r_cr, r_val = _pc(coroutine.resume, co)
  if not s_cr or not r_cr or r_val ~= "neo" then return false, "Coroutine resume spoofed" end
  local s_cs, r_cs = _pc(coroutine.status, co)
  if not s_cs or r_cs ~= "suspended" then return false, "Coroutine status spoofed" end
  local testTab = {}
  if _tf and _ti then
    local s_tf, r_tf = _pc(_tf, testTab)
    if not s_tf then return false, "Table freeze crashed" end
    local s_ti2, r_ti2 = _pc(_ti, testTab)
    if not s_ti2 or r_ti2 ~= true then return false, "Table isfrozen spoofed" end
    local s_th, r_th = _pc(function() testTab.h = 1 end)
    if s_th then return false, "Table freeze enforcement failed" end
  end
  local s_be, be = _pc(_in, "BindableEvent")
  if not s_be or _typeof(be) ~= "Instance" then return false, "BindableEvent create spoofed" end
  local s_cn, cn = _pc(function() return be.Event:Connect(function() end) end)
  if not s_cn or _typeof(cn) ~= "RBXScriptConnection" or not cn.Connected then return false, "BindableEvent connect spoofed" end
  local s_dc = _pc(function() cn:Disconnect() end)
  if not s_dc or cn.Connected then return false, "BindableEvent disconnect spoofed" end
  _pc(function() be:Destroy() end)
  local s_bf, bf = _pc(_in, "BindableFunction")
  if not s_bf or _typeof(bf) ~= "Instance" then return false, "BindableFunction create spoofed" end
  local s_of = _pc(function() bf.OnInvoke = function(a, b) return a + b end end)
  if not s_of then return false, "BindableFunction OnInvoke spoofed" end
  local s_iv, r_iv = _pc(function() return bf:Invoke(3, 4) end)
  if not s_iv or r_iv ~= 7 then return false, "BindableFunction invoke spoofed" end
  _pc(function() bf:Destroy() end)
  local s_tw, tws = _pc(function() return _gs(game, "TweenService") end)
  if s_tw and tws then
    local s_tp, tp = _pc(_in, "Part")
    if s_tp and tp then
      local s_ti, ti = _pc(TweenInfo.new, 0.1)
      local s_twOk, tw = _pc(function() return tws:Create(tp, ti, {Transparency = 1}) end)
      if not s_twOk or _typeof(tw) ~= "Instance" then return false, "TweenService spoofed" end
      _pc(function() tp:Destroy() end)
    end
  end
  local function ci(n)
    local s, i = _pc(_in, n)
    if not s or _typeof(i) ~= "Instance" then return false, n.." spoofed" end
    local sd = _pc(function() i:Destroy() end)
    if not sd then return false, n.." destroy spoofed" end
    return true
  end
  if not ci("Part") then return false, "Part spoofed" end
  if not ci("MeshPart") then return false, "MeshPart spoofed" end
  if not ci("SurfaceAppearance") then return false, "SurfaceAppearance spoofed" end
  if not ci("WrapLayer") then return false, "WrapLayer spoofed" end
  if not ci("WrapTarget") then return false, "WrapTarget spoofed" end
  if not ci("Bone") then return false, "Bone spoofed" end
  if not ci("Attachment") then return false, "Attachment spoofed" end
  if not ci("Highlight") then return false, "Highlight spoofed" end
  if not ci("Beam") then return false, "Beam spoofed" end
  if not ci("Trail") then return false, "Trail spoofed" end
  if not ci("AlignPosition") then return false, "AlignPosition spoofed" end
  if not ci("AlignOrientation") then return false, "AlignOrientation spoofed" end
  if not ci("LinearVelocity") then return false, "LinearVelocity spoofed" end
  if not ci("AngularVelocity") then return false, "AngularVelocity spoofed" end
  if not ci("VectorForce") then return false, "VectorForce spoofed" end
  if not ci("SpringConstraint") then return false, "SpringConstraint spoofed" end
  if not ci("BallSocketConstraint") then return false, "BallSocketConstraint spoofed" end
  if not ci("HingeConstraint") then return false, "HingeConstraint spoofed" end
  if not ci("RopeConstraint") then return false, "RopeConstraint spoofed" end
  if not ci("Animation") then return false, "Animation spoofed" end
  if not ci("Animator") then return false, "Animator spoofed" end
  if not ci("AnimationController") then return false, "AnimationController spoofed" end
  if not ci("HumanoidDescription") then return false, "HumanoidDescription spoofed" end
  if not ci("PathfindingModifier") then return false, "PathfindingModifier spoofed" end
  if not ci("ProximityPrompt") then return false, "ProximityPrompt spoofed" end
  if not ci("ClickDetector") then return false, "ClickDetector spoofed" end
  if not ci("DragDetector") then return false, "DragDetector spoofed" end
  if not ci("Dialog") then return false, "Dialog spoofed" end
  if not ci("Decal") then return false, "Decal spoofed" end
  if not ci("Texture") then return false, "Texture spoofed" end
  if not ci("PointLight") then return false, "PointLight spoofed" end
  if not ci("SpotLight") then return false, "SpotLight spoofed" end
  if not ci("SurfaceLight") then return false, "SurfaceLight spoofed" end
  if not ci("ParticleEmitter") then return false, "ParticleEmitter spoofed" end
  if not ci("Smoke") then return false, "Smoke spoofed" end
  if not ci("Fire") then return false, "Fire spoofed" end
  if not ci("Sparkles") then return false, "Sparkles spoofed" end
  if not ci("Sound") then return false, "Sound spoofed" end
  if not ci("SoundGroup") then return false, "SoundGroup spoofed" end
  if not ci("ChorusSoundEffect") then return false, "ChorusSoundEffect spoofed" end
  if not ci("DistortionSoundEffect") then return false, "DistortionSoundEffect spoofed" end
  if not ci("EchoSoundEffect") then return false, "EchoSoundEffect spoofed" end
  if not ci("EqualizerSoundEffect") then return false, "EqualizerSoundEffect spoofed" end
  if not ci("FlangeSoundEffect") then return false, "FlangeSoundEffect spoofed" end
  if not ci("PitchShiftSoundEffect") then return false, "PitchShiftSoundEffect spoofed" end
  if not ci("TremoloSoundEffect") then return false, "TremoloSoundEffect spoofed" end
  if not ci("ScreenGui") then return false, "ScreenGui spoofed" end
  if not ci("BillboardGui") then return false, "BillboardGui spoofed" end
  if not ci("SurfaceGui") then return false, "SurfaceGui spoofed" end
  if not ci("Frame") then return false, "Frame spoofed" end
  if not ci("ScrollingFrame") then return false, "ScrollingFrame spoofed" end
  if not ci("TextLabel") then return false, "TextLabel spoofed" end
  if not ci("TextButton") then return false, "TextButton spoofed" end
  if not ci("TextBox") then return false, "TextBox spoofed" end
  if not ci("ImageLabel") then return false, "ImageLabel spoofed" end
  if not ci("ImageButton") then return false, "ImageButton spoofed" end
  if not ci("ViewportFrame") then return false, "ViewportFrame spoofed" end
  if not ci("VideoFrame") then return false, "VideoFrame spoofed" end
  if not ci("CanvasGroup") then return false, "CanvasGroup spoofed" end
  if not ci("UIAspectRatioConstraint") then return false, "UIAspectRatioConstraint spoofed" end
  if not ci("UICorner") then return false, "UICorner spoofed" end
  if not ci("UIGradient") then return false, "UIGradient spoofed" end
  if not ci("UIGridLayout") then return false, "UIGridLayout spoofed" end
  if not ci("UIListLayout") then return false, "UIListLayout spoofed" end
  if not ci("UIPadding") then return false, "UIPadding spoofed" end
  if not ci("UIPageLayout") then return false, "UIPageLayout spoofed" end
  if not ci("UIScale") then return false, "UIScale spoofed" end
  if not ci("UISizeConstraint") then return false, "UISizeConstraint spoofed" end
  if not ci("UIStroke") then return false, "UIStroke spoofed" end
  if not ci("UITableLayout") then return false, "UITableLayout spoofed" end
  if not ci("UITextSizeConstraint") then return false, "UITextSizeConstraint spoofed" end
  if not ci("Weld") then return false, "Weld spoofed" end
  if not ci("Snap") then return false, "Snap spoofed" end
  if not ci("Motor") then return false, "Motor spoofed" end
  if not ci("Motor6D") then return false, "Motor6D spoofed" end
  if not ci("PrismaticConstraint") then return false, "PrismaticConstraint spoofed" end
  if not ci("CylindricalConstraint") then return false, "CylindricalConstraint spoofed" end
  if not ci("UniversalConstraint") then return false, "UniversalConstraint spoofed" end
  if not ci("TorsionSpringConstraint") then return false, "TorsionSpringConstraint spoofed" end
  if not ci("NoCollisionConstraint") then return false, "NoCollisionConstraint spoofed" end
  if not ci("StringValue") then return false, "StringValue spoofed" end
  if not ci("NumberValue") then return false, "NumberValue spoofed" end
  if not ci("IntValue") then return false, "IntValue spoofed" end
  if not ci("BoolValue") then return false, "BoolValue spoofed" end
  if not ci("ObjectValue") then return false, "ObjectValue spoofed" end
  if not ci("Color3Value") then return false, "Color3Value spoofed" end
  if not ci("RayValue") then return false, "RayValue spoofed" end
  if not ci("Vector3Value") then return false, "Vector3Value spoofed" end
  if not ci("CFrameValue") then return false, "CFrameValue spoofed" end
  if not ci("BrickColorValue") then return false, "BrickColorValue spoofed" end
  return true, "clean"
end
local s, r, reason = _pc(runDtcSuite)
if not s then error("dtc script crashed: " .. tostring(r)) elseif not r then error("dtc detected skidder | REASON: " .. tostring(reason)) else print("pass") end
