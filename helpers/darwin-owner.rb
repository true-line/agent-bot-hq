# The system LaunchDaemon checks in under its own PID, then replaces this
# process with HQ. The peer and listener operations receive a socket on fd 3.
require 'socket'
require 'fiddle'
require 'etc'

abort 'requires macOS' unless RUBY_PLATFORM.include?('darwin')
CONTROL = '/Library/Application Support/ai.true-line.agent-bot-hq/owner-control.sock'.freeze
# darwin-hq-launch-exits/v2 describes launcher stages only. Keep helper CLI
# boolean refusals and unrelated Ruby failures outside this mapping.
LAUNCH_ROLE = 80
LAUNCH_CHECKIN = 81
LAUNCH_COUNT = 82
LAUNCH_DESCRIPTOR = 83
LAUNCH_PUBLIC_PATH = 84
LAUNCH_ADDRESS = 85
LAUNCH_EXEC = 86
LAUNCH_CHECKIN_159 = 88

def stop_launch(code, message)
  warn message
  exit code
end

def activation
  Fiddle::Function.new(Fiddle::Handle::DEFAULT['launch_activate_socket'],
                       [Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP],
                       Fiddle::TYPE_INT)
end

def published_control?(wait: 0)
  deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + wait
  loop do
    ['/', '/Library', '/Library/Application Support', File.dirname(CONTROL)].each do |path|
      dir = File.lstat(path)
      return false unless dir.directory? && dir.uid.zero? && (dir.mode & 0o022).zero?
    end
    begin
      socket = File.lstat(CONTROL)
    rescue Errno::ENOENT
      remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
      return false unless remaining.positive?
      sleep [remaining, 0.025].min
      next
    end
    return socket.socket? && socket.uid.zero? && (socket.mode & 0o7777) == 0o666
  end
rescue SystemCallError
  false
end

def published_peer?(path, name)
  deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 0.5
  begin
    Socket.open(Socket::AF_UNIX, Socket::SOCK_STREAM) do |peer|
      result = peer.connect_nonblock(Socket.sockaddr_un(path), exception: false)
      if result == :wait_writable
        remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
        return false unless remaining.positive? && IO.select(nil, [peer], nil, remaining)
        return false unless peer.getsockopt(Socket::SOL_SOCKET, Socket::SO_ERROR).int.zero?
      end
      peer.remote_address.unix_path == name
    end
  rescue Errno::ECONNREFUSED, Errno::EAGAIN
    return false if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
    sleep 0.01
    retry
  end
rescue SystemCallError, SocketError
  false
end

def launchd_address?(sock, name)
  # launchd may publish a renamed socket. Darwin keeps its original bound
  # address in both the listening fd and the peer seen at the public path.
  manager = %r{\A(?:/private)?/var/run/(com\.apple\.launchd\.[a-zA-Z0-9]+)/owner-control\z}.match(name)
  return false unless manager && sock.stat.uid.zero?
  dir = File.lstat("/private/var/run/#{manager[1]}")
  dir.directory? && dir.uid.zero? && (dir.mode & 0o7777) == 0o700
rescue SystemCallError, SocketError
  false
end

def listener_status(sock, verify_public: true, publication_wait: 0)
  return LAUNCH_DESCRIPTOR unless sock.local_address.unix? &&
                                 sock.getsockopt(Socket::SOL_SOCKET, Socket::SO_TYPE).int == Socket::SOCK_STREAM
  # Darwin's Unix stream sockets do not implement SO_ACCEPTCONN.
  begin
    sock.getpeername
    return LAUNCH_DESCRIPTOR
  rescue Errno::ENOTCONN
    # A listening stream has no peer.
  end
  return LAUNCH_PUBLIC_PATH unless published_control?(wait: publication_wait)
  name = sock.local_address.unix_path
  unless name == CONTROL
    return LAUNCH_ADDRESS unless launchd_address?(sock, name)
    return LAUNCH_ADDRESS if verify_public && !published_peer?(CONTROL, name)
  end
  sock.listen(Socket::SOMAXCONN) == 0 ? 0 : LAUNCH_DESCRIPTOR
rescue SystemCallError, SocketError
  LAUNCH_DESCRIPTOR
end

def listener?(sock, verify_public: true)
  listener_status(sock, verify_public: verify_public).zero?
end

# fstat on a Darwin Unix stream identifies the socket, while lstat on the
# published path identifies its filesystem vnode. Compare two descriptors only.
def duplicate_socket?(socket, copy)
  original = socket.stat
  duplicate = copy.stat
  original.ino.positive? && original.dev == duplicate.dev && original.ino == duplicate.ino &&
    socket.getsockname == copy.getsockname
end

def activated_socket
  # launch_activate_socket returns a malloc'd array of int and a size_t count.
  # exec releases the allocation. Both inherited descriptors refer to this stream.
  list = Fiddle::Pointer.malloc(Fiddle::SIZEOF_VOIDP)
  count = Fiddle::Pointer.malloc(Fiddle::SIZEOF_SIZE_T)
  result = begin
    activation.call("owner-control\0", list, count)
  rescue Fiddle::DLError
    stop_launch(LAUNCH_CHECKIN, 'launchd socket activation unavailable')
  end
  stop_launch(LAUNCH_CHECKIN_159, 'launchd socket activation returned 159') if result == 159
  stop_launch(LAUNCH_CHECKIN, 'launchd socket activation failed') unless result == 0
  stop_launch(LAUNCH_COUNT, 'expected exactly one owner-control descriptor') unless count[0, Fiddle::SIZEOF_SIZE_T].unpack1('J') == 1
  descriptors = Fiddle::Pointer.new(list[0, Fiddle::SIZEOF_VOIDP].unpack1('J'))
  begin
    Socket.for_fd(descriptors[0, Fiddle::SIZEOF_INT].unpack1('i!'))
  rescue SystemCallError, SocketError
    stop_launch(LAUNCH_DESCRIPTOR, 'could not open the inherited launchd socket')
  end
end

def exec_hq(node, entry, arguments, socket)
  exec({'HQ_LAUNCHD_OWNER_PID' => Process.pid.to_s}, [node, node], entry, *arguments, 3 => socket, 4 => socket, :close_others => true)
rescue SystemCallError
  stop_launch(LAUNCH_EXEC, 'could not exec the approved HQ runtime')
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
  role = begin
    Etc.getpwuid(Process.euid).name
  rescue ArgumentError
    stop_launch(LAUNCH_ROLE, 'cannot resolve the dedicated HQ account')
  end
  stop_launch(LAUNCH_ROLE, 'expected dedicated HQ launch arguments') unless role == '_agent-bot-hq' &&
    node && node.start_with?('/') && entry && entry.start_with?('/') && arguments.first == 'run'
  socket = activated_socket
  # HQ verifies the public peer after it can accept paused streams.
  # Machine also waits up to three seconds for launchd to publish the leaf.
  # Missing ancestors and unsafe existing entries still fail immediately.
  code = listener_status(socket, verify_public: false, publication_wait: 3)
  stop_launch(code, 'unexpected launchd listener') unless code.zero?
  exec_hq(node, entry, arguments, socket)
when 'descriptor'
  socket = Socket.for_fd(3)
  copy = Socket.for_fd(4)
  exit(ARGV == [CONTROL] && duplicate_socket?(socket, copy) && listener?(socket, verify_public: false))
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
