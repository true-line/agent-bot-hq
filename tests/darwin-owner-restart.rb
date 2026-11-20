# Keep the renamed listening descriptor across two ordinary service instances.
require 'json'
require 'socket'
require 'tmpdir'
require 'timeout'
node = ARGV.fetch(0)
worker = File.expand_path('darwin-owner-restart.mjs', __dir__)
Dir.mktmpdir('hq-restart-', '/private/tmp') do |dir|
  name, path = %w[original published].map { |n| File.join(dir, n) }
  Socket.open(:UNIX, :STREAM) do |listener|
    listener.bind(Socket.sockaddr_un(name))
    listener.listen(16)
    File.rename(name, path)
    [1, 16].each do |requests|
      clients = Array.new(requests) { UNIXSocket.new(path) }
      clients.each_with_index { |s, id| s.puts(JSON.generate(id: id, op: 'status')) }
      read, write = IO.pipe
      pid = spawn(node, worker, path, name, 'ready', 3 => listener, 4 => listener, in: read)
      read.close
      begin
        Timeout.timeout(8) do
          clients.each_with_index do |s, id|
            answer = JSON.parse(s.gets)
            raise 'pending owner request lost' unless answer == { 'id' => id, 'ok' => true, 'result' => { 'ready' => true } }
          end
          write.puts('stop')
          _, status = Process.wait2(pid)
          pid = nil
          raise 'worker did not exit cleanly' unless status.success?
        end
      ensure
        if pid
          Process.kill('KILL', pid) rescue nil
          Process.wait(pid) rescue nil
        end
        write.close
        clients.each(&:close)
      end
    end

    # A mismatched public peer must close the paused stream before dispatch.
    UNIXSocket.open(path) do |waiting|
      waiting.write("{\"id\":1,\"op\":\"status\"}\n")
      raise 'mismatch accepted' unless system(node, worker, path, name + '-other', 'refused',
                                               3 => listener, 4 => listener)
      begin
        Timeout.timeout(3) do
          raise 'unverified request received a reply' unless waiting.read.empty?
        end
      rescue Errno::ECONNRESET
        # The queued unread request was refused.
      end
    end
  end
end
