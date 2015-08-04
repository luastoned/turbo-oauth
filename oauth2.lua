local oauth2 = {
	_VERSION		= "v1.0.0",
	_DESCRIPTION	= "OAuth2 for Turbo.lua",
	_URL			= "https://github.com/luastoned/turbo-oauth",
	_LICENSE		= [[Copyright (c) 2015 @LuaStoned]],
}

-- Always set me when using SSL, before loading framework.
TURBO_SSL = true
local turbo = require("turbo")

local function request(method, url, params, headers)
	local options = {
		method = method,
		params = params,
		on_headers = function(self)
			for k, v in pairs(headers or {}) do
				self:add(k, v)
			end
		end,
	}
	
	local res = coroutine.yield(turbo.async.HTTPClient():fetch(url, options))
	if (res.error) then
		error(res.error)
	end
	
	return res.body
end

local function sha1(str, key, raw)
	return turbo.hash.HMAC(key, str, raw)
end

local function base64(str)
	return turbo.escape.base64_encode(str)
end

-- Parameter encoding according to RFC3986
-- http://tools.ietf.org/html/rfc3986#section-2.3
-- http://oauth.net/core/1.0a/#encoding_parameters
local function encodeParam(str)
	return string.gsub(tostring(str), "[^-._~%w]", function(char)
		return string.format("%%%02x", char:byte()):upper()
	end)
end

local function decodeParam(str)
	str = string.gsub(tostring(str), "+", " ")
	str = string.gsub(str, "%%(%x%x)", function(h) return string.char(tonumber(h, 16)) end)
	str = string.gsub(str, "\r\n", "\n")
	return str
end

-- oauth2

function oauth2:getAccessToken(grantType, extraArg)
	local arg = {
		grant_type = grantType or "client_credentials",
	}
	
	if (extraArg and type(extraArg) == "table") then
		for key, val in pairs(extraArg) do
			if (val ~= nil) then
				arg[key] = tostring(val)
			end
		end
	end
	
	local res = self:request("POST", self.accessUrl, arg)
	local tbl = turbo.escape.json_decode(res)
	self.tokenType = decodeParam(tbl.token_type)
	self.accessToken = decodeParam(tbl.access_token)
	
	return {res, self.tokenType, self.accessToken}
end

function oauth2:request(method, url, arg)
	local params = {
	}
	
	if (arg and type(arg) == "table") then
		for key, val in pairs(arg) do
			if (val ~= nil) then
				params[key] = tostring(val)
			end
		end
	end
	
	local headers = {}
	headers["Authorization"] = self:getAuthorizationHeader()
	for key, val in pairs(self.headers or {}) do
		headers[key] = val
	end
	
	return request(method, url, params, headers)
end

function oauth2:getAuthorizationHeader()
	if (self.accessToken) then
		return string.format("Bearer %s", encodeParam(self.accessToken))
	else
		return string.format("Basic %s", string.gsub(base64(self.consumerKey .. ":" .. self.consumerSecret), "\r\n", ""))
	end
end

local function createClient(consumerKey, consumerSecret, arg)
	local tbl = {
		consumerKey = consumerKey,
		consumerSecret = consumerSecret,
	}
	
	for key, val in pairs(arg) do
		tbl[key] = val
	end
	
	setmetatable(tbl, oauth2)
	return tbl
end

local meta = {
	__call = function(tbl, ...)
		return createClient(unpack({...}))
	end,
}

oauth2.__index = oauth2
setmetatable(oauth2, meta)
return oauth2
