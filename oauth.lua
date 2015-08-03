local oauth = {
	_VERSION		= "v1.0.0",
	_DESCRIPTION	= "OAuth for Turbo.lua",
	_URL			= "https://github.com/luastoned/turbo-oauth",
	_LICENSE		= [[Copyright (c) 2015 @LuaStoned]],
}

-- Always set me when using SSL, before loading framework.
TURBO_SSL = true
local turbo = require("turbo")

local function request(method, url, request, headers)
	local options = {
		method = method,
		params = request,
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

local function generateNonce()
	return sha1(tostring(math.random()) .. tostring(os.time()), "magic_key")
end

local function generateTimestamp()
	return tostring(os.time())
end

local function isParam(str)
	local params = {
		oauth_callback = true,
		oauth_consumer_key = true,
		oauth_nonce = true,
		oauth_signature_method = true,
		oauth_token = true,
		oauth_timestamp = true,
		oauth_verifier = true,
		oauth_version = true,
		scope = true,
	}
	
	return params[str]
end

-- Parameter encoding according to RFC3986
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

-- oauth

function oauth:getRequestToken(callbackUrl)
	local arg = {
		oauth_callback = callbackUrl or self.tokenReady,
	}
	
	local res = self:request("POST", self.requestUrl, arg)
	self.accessToken = decodeParam(res:match("oauth_token=([^&]+)"))
	self.accessTokenSecret = decodeParam(res:match("oauth_token_secret=([^&]+)"))
	if (self.authorizeUrl) then
		self.tokenUrl = self.authorizeUrl .. "?oauth_token=" .. encodeParam(self.accessToken)
	end
	
	return {res, self.accessToken, self.accessTokenSecret, self.tokenUrl}
end

function oauth:getAccessToken(verifier)
	local arg = {
		oauth_verifier = verifier,
	}
	
	local res = self:request("POST", self.accessUrl, arg)
	self.accessToken = decodeParam(res:match("oauth_token=([^&]+)"))
	self.accessTokenSecret = decodeParam(res:match("oauth_token_secret=([^&]+)"))
	
	return {res, self.accessToken, self.accessTokenSecre}
end

function oauth:request(method, url, arg)
	local params = {
		oauth_version = "1.0",
		oauth_nonce = generateNonce(),
		oauth_timestamp = generateTimestamp(),
		oauth_signature_method = "HMAC-SHA1",
		oauth_consumer_key = self.consumerKey,
		oauth_token = self.accessToken,
		oauth_token_secret = self.accessTokenSecret,
	}
	
	local tokenSecret = arg.oauth_token_secret or self.accessTokenSecret
	if (arg and type(arg) == "table") then
		for key, val in pairs(arg) do
			if (val ~= nil) then
				params[key] = tostring(val)
			end
		end
	end
	params.oauth_token_secret = nil

	local signature = self:getSignature(method, url, params, tokenSecret)
	local authHeader = self:getAuthorizationHeader(params, signature)

	local headers = {}
	headers["Authorization"] = authHeader
	for key, val in pairs(self.headers or {}) do
		headers[key] = val
	end
	
	for key, val in pairs(params) do
		if (isParam(key)) then
			params[key] = nil
		end
	end
	
	return request(method, url, params, headers)
end

function oauth:getAuthorizationHeader(params, signature)
	local header = {}
	
	for key, val in pairs(params) do
		if (isParam(key)) then
			table.insert(header, string.format("%s=\"%s\"", key, encodeParam(val)))
		end
	end
	
	table.insert(header, "oauth_signature=\"" .. encodeParam(signature) .. "\"")
	table.sort(header, function(a, b) return a < b end)
	return string.format("OAuth %s", table.concat(header, ", "))
end

function oauth:getSignature(method, url, params, tokenSecret)
	tokenSecret = tokenSecret or ""
	
	-- oauth-encode each key and value, and get them set up for a Lua table sort
	local keys_and_values = {}

	for key, val in pairs(params) do
		table.insert(keys_and_values, {
			key = encodeParam(key),
			val = encodeParam(val),
		})
	end

	-- sort by key first, then value
	table.sort(keys_and_values, function(a, b) return a.key == b.key and (a.val < b.val) or (a.key < b.key) end)
	
	-- now combine key and value into key=value
	local key_value_pairs = {}
	for _, rec in pairs(keys_and_values) do
		table.insert(key_value_pairs, rec.key .. "=" .. rec.val)
	end
	
	local signatureBase = string.format("%s&%s&%s", method, encodeParam(url), encodeParam(table.concat(key_value_pairs, "&")))
	local signatureKey = string.format("%s&%s", encodeParam(self.consumerSecret), encodeParam(tokenSecret))
	
	-- Now have our text and key for HMAC-SHA1 signing
	local hmac_binary = sha1(signatureBase, signatureKey, true)
	local hmac_b64 = base64(hmac_binary)
	
	return hmac_b64
end

local function createClient(consumerKey, consumerSecret, arg)
	local tbl = {
		consumerKey = consumerKey,
		consumerSecret = consumerSecret,
	}
	
	for key, val in pairs(arg) do
		tbl[key] = val
	end
	
	setmetatable(tbl, oauth)
	return tbl
end

local meta = {
	__call = function(tbl, ...)
		return createClient(unpack({...}))
	end,
}

oauth.__index = oauth
setmetatable(oauth, meta)
return oauth
