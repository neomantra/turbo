
local ffi = require "ffi"
local turbo = require "turbo.cdef"

print("mukle")
local sock = ffi.load("ws2_32")
local timev = ffi.new("struct timeval", 0)
print(timev)
timev.tv_usec = 0
timev.tv_sec = 10
print(sock.select)
sock.select(0,nil,nil,nil, timev)