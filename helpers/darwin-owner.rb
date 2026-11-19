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

def published_control?
  return false unless ['/private', '/private/var'].all? do |path|
    dir = File.lstat(path)
    dir.directory? && dir.uid.zero? && (dir.mode & 0o022).zero?
  end
  socket = File.lstat(CONTROL)
  socket.socket? && socket.uid.zero? && (socket.mode & 0o7777) == 0o666
end

def published_peer?(path, name)
  Socket.open(Socket::AF_UNIX, Socket::SOCK_STREAM) do |peer|
    result = peer.connect_nonblock(Socket.sockaddr_un(path), exception: false)
    if result == :wait_writable
      return false unless IO.select(nil, [peer], nil, 0.5)
      return false unless peer.getsockopt(Socket::SOL_SOCKET, Socket::SO_ERROR).int.zero?
    end
    peer.remote_address.unix_path == name
  end
rescue SystemCallError, SocketError
  false
end

def renamed_launchd_listener?(sock, name, path)
  # launchd may publish a renamed socket. Darwin keeps its original bound
  # address in both the listening fd and the peer seen at the public path.
  manager = %r{\A(?:/private)?/var/run/(com\.apple\.launchd\.[a-zA-Z0-9]+)/owner-control\z}.match(name)
  return false unless manager && sock.stat.uid.zero?
  dir = File.lstat("/private/var/run/#{manager[1]}")
  return false unless dir.directory? && dir.uid.zero? && (dir.mode & 0o7777) == 0o700
  published_peer?(path, name)
end

def listener?(sock)
  return false unless sock.local_address.unix? &&
                      sock.getsockopt(Socket::SOL_SOCKET, Socket::SO_TYPE).int == Socket::SOCK_STREAM
  # Darwin's Unix stream sockets do not implement SO_ACCEPTCONN.
  begin
    sock.getpeername
    return false
  rescue Errno::ENOTCONN
    # A listening stream has no peer.
  end
  return false unless published_control?
  name = sock.local_address.unix_path
  return false unless name == CONTROL || renamed_launchd_listener?(sock, name, CONTROL)
  sock.listen(Socket::SOMAXCONN) == 0
rescue SystemCallError, SocketError
  false
end

return unless __FILE__ == $PROGRAM_NAME

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
       socket.remote_address.unix? &&
       socket.getpeereid.first == Integer(ARGV.first, 10))
else
  exit 1
end
