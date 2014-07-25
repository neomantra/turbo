--- Turbo.lua Linux Epoll module
--
-- Copyright 2011, 2012, 2013 John Abrahamsen
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
-- http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

local ffi = require "ffi"
require "turbo.cdef"

-- Defines for epoll_ctl.
local epoll = {
    EPOLL_CTL_ADD = 1,
    EPOLL_CTL_DEL = 2, 
    EPOLL_CTL_MOD = 3, 
    EPOLL_EVENTS = {
        EPOLLIN  = 0x001,
        EPOLLPRI = 0x002,
        EPOLLOUT = 0x004,
        EPOLLERR = 0x008,
        EPOLLHUP = 0x0010,
    }
}

--- Create a new epoll fd. Returns the fd of the created epoll instance and -1 
-- and errno on error.
-- @return epoll fd on success, else -1 and errno.
function epoll.epoll_create()
    local fd = ffi.C.epoll_create(124)

    if fd == -1 then
        return -1, ffi.errno()
    end

    return fd
end

--- Control a epoll fd.
-- @param epfd Epoll fd to control
-- @param op Operation for the target fd:
--  EPOLL_CTL_ADD
--  Register the target file descriptor fd on the epoll  instance referred to 
--  by the file descriptor epfd and associate the event event with the internal
--  file linked to fd.
--  EPOLL_CTL_MOD
--  Change the event event associated with the target file descriptor fd.
--  EPOLL_CTL_DEL
--  Remove (deregister) the target file descriptor fd from the epoll instance 
--  referred to by epfd. The epoll_events is ignored and can be nil.
-- @param fd (Number) The fd to control.
-- @param epoll_events (Number) The events bit mask to set. Defined in 
-- epoll.EPOLL_EVENTS.
-- @return 0 on success and -1 on error together with errno.
local _event = ffi.new("epoll_event")
function epoll.epoll_ctl(epfd, op, fd, epoll_events)
    local rc
    
    ffi.fill(_event, ffi.sizeof(_event), 0)
    _event.data.fd = fd
    _event.events = epoll_events
    rc = ffi.C.epoll_ctl(epfd, op, fd, _event)
    if (rc == -1) then
        return -1, ffi.errno()
    end
    return rc
end

--- Wait for events on a epoll instance.    
-- @param epfd (Number) Epoll fd to wait on.
-- @param timeout (Number) How long to wait if no events occur.
-- @return On success, epoll_event array is returned, on error, -1 and errno 
-- are returned.      
local _events = ffi.new("struct epoll_event[124]")
function epoll.epoll_wait(epfd, timeout)
    local num_events = ffi.C.epoll_wait(epfd, _events, 124, timeout)
    if num_events == -1 then
        return -1, ffi.errno()
    end  
    return 0, num_events, _events
end

return epoll
