
local ffi = require "ffi"
local turbo = {}
turbo.util = require "turbo.util"
turbo.select = require "turbo.select_ffi"

local sock = ffi.load("Ws2_32")
local timev = ffi.new("struct timeval", 0)
timev.tv_usec = 0
timev.tv_sec = 10
print(sock.select(0,nil,nil,nil, timev))

print(turbo.util.gettimeofday())
print(turbo.select.create())