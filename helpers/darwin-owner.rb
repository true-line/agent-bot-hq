# The system LaunchDaemon checks in under its own PID, then replaces this
# process with HQ. The peer and listener operations inspect fd 3 only.
require 'socket'
require 'fiddle'
require 'etc'

abort 'requires macOS' unless RUBY_PLATFORM.include?('darwin')
CONTROL = '/private/var/agent-bot-hq-control.sock'.freeze

def activation
  Fiddle::Function.new(Fiddle::Handle::DEFAULT['launch_activate_socket'],
                       [Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP],
                       Fiddle::TYPE_INT)
end

def listener?(sock)
  sock.local_address.unix? && sock.local_address.unix_path == CONTROL &&
    sock.getsockopt(Socket::SOL_SOCKET, Socket::SO_TYPE).int == Socket::SOCK_STREAM &&
    sock.getsockopt(Socket::SOL_SOCKET, Socket::SO_ACCEPTCONN).int != 0
end

case ARGV.shift
when 'probe'
  exit 1 unless ARGV.empty?
  activation
  left, right = UNIXSocket.pair
  exit(left.getpeereid.first == Process.euid && right.getpeereid.first == Process.euid)
when 'launch'
  node, entry, *arguments = ARGV
  abort 'expected dedicated HQ launch arguments' unless Etc.getpwuid(Process.euid).name == '_agent-bot-hq' &&
    node && node.start_with?('/') && entry && entry.start_with?('/') && arguments.first == 'run'
  # launch_activate_socket returns a malloc'd array of int and a size_t count.
  # exec releases the allocation; only the single validated stream is inherited.
  list = Fiddle::Pointer.malloc(Fiddle::SIZEOF_VOIDP)
  count = Fiddle::Pointer.malloc(Fiddle::SIZEOF_SIZE_T)
  result = activation.call("owner-control\0", list, count)
  abort "launch_activate_socket failed (#{result})" unless result == 0
  abort 'expected exactly one owner-control descriptor' unless count[0, Fiddle::SIZEOF_SIZE_T].unpack1('J') == 1
  descriptors = Fiddle::Pointer.new(list[0, Fiddle::SIZEOF_VOIDP].unpack1('J'))
  socket = Socket.for_fd(descriptors[0, Fiddle::SIZEOF_INT].unpack1('i!'))
  abort 'unexpected launchd listener' unless listener?(socket)
  exec({'HQ_LAUNCHD_OWNER_PID' => Process.pid.to_s}, [node, node], entry, *arguments, 3 => socket, :close_others => true)
when 'listener'
  exit(ARGV == [CONTROL] && listener?(Socket.for_fd(3)))
when 'peer'
  exit 1 unless ARGV.length == 1 && /\A[0-9]+\z/.match?(ARGV.first)
  socket = UNIXSocket.for_fd(3)
  exit(socket.local_address.unix? && socket.getsockopt(Socket::SOL_SOCKET, Socket::SO_TYPE).int == Socket::SOCK_STREAM &&
       socket.getsockopt(Socket::SOL_SOCKET, Socket::SO_ACCEPTCONN).int == 0 &&
       socket.getpeereid.first == Integer(ARGV.first, 10))
else
  exit 1
end
