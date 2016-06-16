local bin = require "bin"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[ This will Scan for TeamViewer services using the CMD_PINGOK method
If it responds correctly then it will change the service name. If it does not respond
correctly then it will report the port closed/filtered. This is done this way to ONLY
track TeamViewer within output of scanning hosts. 

]]
---
-- @usage
-- nmap --script teamviewer-ping -p 5938 <host>
--
--
-- @output
author = "tothehilt"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "version"}

--
--
--
portrule = shortport.portnumber(5938, "tcp")

---
--  Function to set the nmap output for the host, if a valid TeamViewer packet
--  is received then the output will show that the port is open instead of
--  <code>open|filtered</code>
--
-- @param host Host that was passed in via nmap
-- @param port port that TeamViewer is running on (Default TCP/5938)
function set_nmap(host, port,state)

  if state == "open" then
    port.state = state
    port.version.name = "TeamViewer CMD_PINGOK"
    nmap.set_port_version(host, port)
    nmap.set_port_state(host, port, state)
  elseif state == "closed" then
    port.state = state
    port.version.name = "NotTeamViewer"
    nmap.set_port_version(host, port)
    nmap.set_port_state(host, port, state)
  end

end

---
--
-- @param host Host that was scanned via nmap
-- @param port port that was scanned via nmap
action = function(host,port)
  local req_info = bin.pack("H","172410040000000000")
  -- create table for output
  local output = stdnse.output_table()
  -- create local vars for socket handling
  local socket, try, catch
  -- create new socket
  socket = nmap.new_socket()
  -- define the catch of the try statement
  catch = function()
    socket:close()
    set_nmap(host, port, "closed")
    return nil
  end
  -- create new try
  try = nmap.new_try(catch)
  try(socket:connect(host, port))
  -- connect to port on host
  try(socket:send(req_info))
  -- receive response
 local rcvstatus, response = socket:receive()
  if(rcvstatus == false) then
    socket:close()
    set_nmap(host, port, "closed")
    return false, response
  end    
  local pos, check1 = bin.unpack("C",response,1)
  local pos, check2 = bin.unpack("C",response,2)
  local pos, check3 = bin.unpack("C",response,3)
  if(check1 == 0x17 and check2 == 0x24 and check3 == 0x11) then
    set_nmap(host, port,"open") 
  else 
    set_nmap(host, port,"closed")
  end
  -- close socket
  socket:close()
  -- return nil
  return nil
end

