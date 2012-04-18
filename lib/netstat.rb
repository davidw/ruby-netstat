module Netstat
  PROC_NET_TCP = "/proc/net/tcp"

  # States from http://snippets.dzone.com/posts/show/12653
  TCP_STATES = {
    '00' => 'UNKNOWN',  # Bad state ... Impossible to achieve ...
    'FF' => 'UNKNOWN',  # Bad state ... Impossible to achieve ...
    '01' => 'ESTABLISHED',
    '02' => 'SYN_SENT',
    '03' => 'SYN_RECV',
    '04' => 'FIN_WAIT1',
    '05' => 'FIN_WAIT2',
    '06' => 'TIME_WAIT',
    '07' => 'CLOSE',
    '08' => 'CLOSE_WAIT',
    '09' => 'LAST_ACK',
    '0A' => 'LISTEN',
    '0B' => 'CLOSING'
  }

  # Read all the TCP data and return it.
  def self.read_tcp
    sockets = []
    File.readlines(PROC_NET_TCP)[1..-1].each do |line|
      # These are currently the fields listed in /proc/net/tcp
      # sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode 
      splitline = line.split
      localaddr, localport = splitline[1].split(':')
      remoteaddr, remoteport = splitline[2].split(':')
      socket = {
        :remote_address => remoteaddr,
        :remote_address_quad => [remoteaddr].pack("H*").unpack("C*").reverse.join("."),
        :remote_port => remoteport.to_i(16),
        :local_address => localaddr,
        :local_address_quad => [localaddr].pack("H*").unpack("C*").reverse.join("."),
        :local_port => localport.to_i(16),
        :state => TCP_STATES[splitline[3]]
      }

      sockets << socket
    end
    return sockets
  end

  # Takes a hash with the key and value to search for and returns all
  # matches.  If there are multiple parameters, has an AND behavior.
  def self.filter(params)
    return Netstat.read_tcp.select do |sock|
      retval = true
      params.keys.each do |k|
        unless sock[k] && (sock[k].to_s == params[k].to_s)
          retval = false
          break
        end
      end
      retval
    end
  end

end
