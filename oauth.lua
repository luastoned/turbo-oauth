local oauth = {
	_VERSION		= "v1.0.0",
	_DESCRIPTION	= "OAuth for Turbo.lua",
	_URL			= "https://github.com/luastoned/turbo-oauth",
	_LICENSE		= [[Copyright (c) 2015 @LuaStoned]],
}

-- Always set me when using SSL, before loading framework.
TURBO_SSL = true
local turbo = require("turbo")
