##
# Cellular SOCKS5 Proxy (Serial AT) v0.06.4
#
# The purpose of this module is to proxy is to allow for directing metasploit
# modules and external clients the ability to redirect communication through a 
# cellular modules main UART port leveraging cellular module AT socket command
#
#   This module is currently designed and tested for Quectel cellular  modules
##


require 'msf/core'
require 'thread'

class MetasploitModule < Msf::Auxiliary
  Rank = NormalRanking

  include Msf::Exploit::Remote::TcpServer

  DEFAULT_MAX_CHUNK_SIZE        = 1024  # bytes per QISEND chunk
  DEFAULT_SELECT_TIMEOUT_MS     = 20    # IO.select poll interval (ms)
  DEFAULT_PROMPT_TIMEOUT_MS     = 5000  # wait for '>' after QISEND (ms)
  DEFAULT_ACK_TIMEOUT_MS        = 8000  # wait for SEND OK/FAIL (ms)
  DEFAULT_OPEN_TIMEOUT_MS       = 30000 # wait for +QIOPEN URC (ms)
  DEFAULT_CMD_TIMEOUT_MS        = 6000  # wait for AT command OK/ERROR (ms)

  # === v0.06.4 modem health / readiness defaults ===============================
  DEFAULT_STARTUP_OK_TIMEOUT_S    = 0     # total seconds to wait for first AT OK (0 = no timeout)
  DEFAULT_STARTUP_OK_INTERVAL_MS  = 1000  # delay between AT probes at startup (ms)
  DEFAULT_HEALTHCHECK_INTERVAL_S  = 3     # seconds between AT probes at runtime
  DEFAULT_HEALTHCHECK_TIMEOUT_MS  = 2000  # per-probe AT timeout (ms)
  DEFAULT_HEALTHCHECK_MAX_FAILS   = 3     # consecutive failures before marking NOT READY

  DEFAULT_MODEM_SOCKETS         = 12    # SID pool size (0..N-1); Quectel Cell Module supports up to 12
  DEFAULT_RECV_DRAIN_MAX_CHUNKS = 64    # max recv queue pops per relay loop
  DEFAULT_RECV_DRAIN_MAX_BYTES  = 262144 # max bytes written per relay loop

  LISTEN_BACKLOG                = 64

  #
  # === Timestamp-only change (console output) ================================
  #
  def ts_now
    # HH:MM:SS.mmm (local time)
    ::Time.now.strftime('%H:%M:%S.%L')
  end

  def print_status(msg = '')
    super("[#{ts_now}] #{msg}")
  end

  def print_good(msg = '')
    super("[#{ts_now}] #{msg}")
  end

  def print_error(msg = '')
    super("[#{ts_now}] #{msg}")
  end

  def vprint_status(msg = '')
    super("[#{ts_now}] #{msg}")
  end
  # ===========================================================================
  #

  # Simple "event" primitive (set/clear/wait with timeout)
  class SimpleEvent
    def initialize
      @mutex = Mutex.new
      @cond  = ConditionVariable.new
      @set   = false
    end

    def set
      @mutex.synchronize do
        @set = true
        @cond.broadcast
      end
    end

    def clear
      @mutex.synchronize do
        @set = false
      end
    end

    # Returns true if event was set, false on timeout
    def wait(timeout = nil)
      @mutex.synchronize do
        unless @set
          if timeout
            @cond.wait(@mutex, timeout)
          else
            @cond.wait(@mutex)
          end
        end
        @set
      end
    end
  end

  # Tracks one AT command until completion (OK/ERROR/SEND FAIL)
  class CmdWaiter
    attr_reader :cmd, :event, :buf
    attr_accessor :ok

    def initialize(cmd)
      @cmd   = cmd
      @event = SimpleEvent.new
      @buf   = []
      @ok    = false
    end
  end

  # Represents one opened modem socket (SID)
  class QuectelConnection
    attr_reader :sock_id, :recv_queue, :prompt_event, :ack_event
    attr_accessor :ack_ok, :open_event, :open_ok, :open_err, :prompt_ok, :closed_flag

    def initialize(modem, sock_id)
      @modem        = modem
      @sock_id      = sock_id
      @recv_queue   = Queue.new      # payload chunks or :closed sentinel
      @prompt_event = SimpleEvent.new
      @ack_event    = SimpleEvent.new
      @ack_ok       = false
      @prompt_ok    = true
      @closed_flag  = false
      @open_event   = SimpleEvent.new
      @open_ok      = false
      @open_err     = nil
    end

    # Send data over this modem socket via AT+QISEND
    def send(data)
      @modem.at_lock.synchronize do
        at = "AT+QISEND=#{@sock_id},#{data.bytesize}\r"

        @modem.mutex.synchronize do
          @prompt_ok = true
          @prompt_event.clear
          @ack_event.clear
          @modem.pending_send_sid = @sock_id
          @modem.serial.write(at)
        end

        # Wait for '>' prompt (or early reject)
        unless @prompt_event.wait(@modem.cfg[:prompt_timeout])
          @modem.pending_send_sid = nil
          raise ::Rex::RuntimeError, "[SID #{@sock_id}] No '>' prompt for QISEND"
        end
        @prompt_event.clear

        unless @prompt_ok
          @modem.pending_send_sid = nil
          raise ::Rex::RuntimeError, "[SID #{@sock_id}] QISEND rejected (no prompt)"
        end

        # Write payload + Ctrl-Z
        @modem.mutex.synchronize do
          @modem.serial.write(data)
          @modem.serial.write("\x1A")
        end

        # Wait for SEND OK/FAIL
        unless @ack_event.wait(@modem.cfg[:ack_timeout])
          @modem.pending_send_sid = nil
          raise ::Rex::RuntimeError, "[SID #{@sock_id}] No SEND OK/ERROR"
        end
        @ack_event.clear
        @modem.pending_send_sid = nil

        unless @ack_ok
          raise ::Rex::RuntimeError, "[SID #{@sock_id}] SEND ERROR"
        end
      end
    end

    # Non-blocking recv; returns:
    #   - bytes (String) when payload available
    #   - :closed when modem closed socket
    #   - nil when no data currently
    def recv_nonblock
      @recv_queue.pop(true)
    rescue ThreadError
      nil
    end

    def push_payload(data)
      @recv_queue << data
    end

    def mark_closed
      @closed_flag = true
      @recv_queue << :closed
    end
    # === v0.06.4 readiness/health helpers =====================================

    def modem_ready?
      @ready_mutex.synchronize { @modem_ready }
    end

    def set_modem_ready(val, reason: nil)
      changed = false
      @ready_mutex.synchronize do
        if @modem_ready != val
          @modem_ready = val
          changed = true
        end
      end
      return unless changed

      if val
        @mod.print_good("[MODEM] READY#{reason ? " (#{reason})" : ''}")
      else
        @mod.print_error("[MODEM] NOT READY#{reason ? " (#{reason})" : ''}")
      end
    end

    def startup_wait_for_ok(total_timeout_s, interval_s, probe_timeout_s)
      total_timeout_s = total_timeout_s.to_i
      interval_s = interval_s.to_f
      interval_s = 1.0 if interval_s <= 0

      # total_timeout_s == 0 means "no timeout" (wait indefinitely until AT returns OK)
      deadline = (total_timeout_s > 0) ? (::Time.now + total_timeout_s) : nil

      loop do
        if deadline && ::Time.now > deadline
          set_modem_ready(false, reason: 'startup probe timed out')
          raise ::Rex::TimeoutError, "Startup AT probe timed out after #{total_timeout_s}s"
        end

        begin
          send_at('AT', probe_timeout_s)
          set_modem_ready(true, reason: 'startup probe OK')
          return true
        rescue ::Rex::TimeoutError, ::Rex::RuntimeError
          # suppress spam unless verbose; send_at already logs to vprint_status
        rescue ::StandardError => e
          log_debug("startup AT probe error: #{e.class} #{e.message}")
        end

        ::Rex.sleep(interval_s)
      end
    end

    def start_health_watchdog
  @health_stop = false
  @health_thread = @mod.framework.threads.spawn('cellular_modem_health_watchdog', false) do
    loop do
      break if @health_stop
      begin
        # Probe modem liveness
        send_at('AT', @cfg[:healthcheck_timeout])
        @health_fail_count = 0

        # If we were previously NOT READY, run minimal re-init (echo off) after reboot
        unless modem_ready?
          reinitialize_after_reboot
          set_modem_ready(true, reason: 'health probe OK')
        end
      rescue ::Rex::TimeoutError, ::Rex::RuntimeError
        @health_fail_count += 1
        if @health_fail_count >= @cfg[:healthcheck_max_fails]
          set_modem_ready(false, reason: "health probe failed #{@health_fail_count}x")
        end
      rescue ::StandardError => e
        @health_fail_count += 1
        log_debug("health probe exception: #{e.class} #{e.message}")
        if @health_fail_count >= @cfg[:healthcheck_max_fails]
          set_modem_ready(false, reason: "health probe exception #{@health_fail_count}x")
        end
      end
      ::Rex.sleep(@cfg[:healthcheck_interval])
    end
  end
end

def reinitialize_after_reboot
  # After a power cycle, the module often resets settings like echo.
  # If echo is enabled, the modem will echo QISEND payload bytes back on the AT port,
  # which can look like "binary URCs" in the console. Re-assert ATE0 once we're back.
  begin
    send_at('ATE0', @cfg[:cmd_timeout])
  rescue ::StandardError => e
    log_debug("reinitialize_after_reboot: ATE0 failed: #{e.class} #{e.message}")
  end

  # Best-effort drain any buffered garbage that may have accumulated during reboot.
  begin
    loop do
      r, _w, _e = ::IO.select([@serial], nil, nil, 0)
      break unless r && r.include?(@serial)
      @serial.read_nonblock(4096)
    end
  rescue ::IO::WaitReadable, ::EOFError, ::IOError
  end
end
# ========================================================================



    def close
      begin
        # @modem.send_at("AT+QICLOSE=#{@sock_id},10", CMD_TIMEOUT)
        @modem.send_at("AT+QICLOSE=#{@sock_id},0", @modem.cfg[:cmd_timeout])
      rescue ::StandardError => e
        @modem.log_debug("[SID #{@sock_id}] QICLOSE error: #{e.class} #{e.message}")
      end
      @modem.release_id(@sock_id)
    end
  end

  # Encapsulates serial I/O and URC parsing for Quectel module
  class QuectelModem
    attr_reader :serial, :mutex, :cfg
    attr_accessor :pending_send_sid
    attr_reader :at_lock
    attr_reader :open_lock

    def initialize(mod, port, baud, framework, cfg)
      @mod        = mod          # reference to Metasploit module for print_* helpers
      @serial     = ::File.open(port, 'r+b')
      @serial.sync = true

      @cfg = cfg

      @mutex      = Mutex.new    # serialize direct writes/reads as needed
      @cmd_mutex  = Mutex.new
      @at_lock   = Mutex.new    # serialize all AT commands (prevents interleaving)
      @pending_cmds = []         # FIFO of CmdWaiter

      @line_buf   = ''.b
      @reader_stop = false
      @rdy_event  = SimpleEvent.new

      # Serialize QIOPEN operations (one open in-flight at a time)
      @open_lock  = Mutex.new
      @pending_send_sid = nil

      @free_ids   = (0...@cfg[:modem_sockets]).to_a
      @conns      = {}           # sid -> QuectelConnection

      @modem_ready = true
      @ready_mutex = Mutex.new
      @health_fail_count = 0
      @health_stop = false

      # Spawn dedicated reader thread
      @reader_thread = framework.threads.spawn('cellular_modem_reader', false) do
        reader_loop
      end

      # === startup readiness =========================================
      # Some modules may have already emitted RDY before we start listening.
      # Startup is therefore driven by "AT ... OK" polling.
      @mod.print_status('Probing modem with AT until OK…')
      startup_wait_for_ok(@cfg[:startup_ok_timeout], @cfg[:startup_ok_interval], @cfg[:healthcheck_timeout])
      @mod.print_good('Startup AT probe successful (OK).')

      # RDY is still useful context when seen; wait briefly/best-effort, but don't fail startup on it.
      @mod.print_status('Waiting briefly for RDY URC (best-effort)…')
      wait_for_rdy(5)
      # ======================================================================

      # Disable echo
      send_at('ATE0', @cfg[:cmd_timeout])

      # Start runtime health watchdog
      start_health_watchdog

    rescue ::Errno::ENOENT, ::Errno::EACCES => e
      @mod.print_error("Failed to open serial port #{port}: #{e.class} #{e.message}")
      raise
    end
    # ===  readiness/health helpers =====================================

    def modem_ready?
      @ready_mutex.synchronize { @modem_ready }
    end

    # Wait for modem_ready? to become true up to max_wait_s.
    # This does NOT toggle PDP or attempt attach; it simply waits for the health thread
    # to observe AT -> OK and mark the modem ready again.
    #
    # Returns true if ready, false on timeout.
    def wait_for_modem_ready(max_wait_s, poll_s)
      max_wait_s = max_wait_s.to_i
      return true if max_wait_s <= 0

      poll_s = poll_s.to_i
      poll_s = 1 if poll_s <= 0

      deadline = ::Time.now + max_wait_s
      while ::Time.now < deadline
        return true if modem_ready?
        ::Rex.sleep(poll_s)
      end
      false
    end

    def set_modem_ready(val, reason: nil)
      changed = false
      @ready_mutex.synchronize do
        if @modem_ready != val
          @modem_ready = val
          changed = true
        end
      end
      return unless changed

      if val
        @mod.print_good("[MODEM] READY#{reason ? " (#{reason})" : ''}")
      else
        @mod.print_error("[MODEM] NOT READY#{reason ? " (#{reason})" : ''}")
      end
    end

    def startup_wait_for_ok(total_timeout_s, interval_s, probe_timeout_s)
      total_timeout_s = total_timeout_s.to_i
      interval_s = interval_s.to_f
      interval_s = 1.0 if interval_s <= 0

      # total_timeout_s == 0 means "no timeout" (wait indefinitely until AT returns OK)
      deadline = (total_timeout_s > 0) ? (::Time.now + total_timeout_s) : nil

      loop do
        if deadline && ::Time.now > deadline
          set_modem_ready(false, reason: 'startup probe timed out')
          raise ::Rex::TimeoutError, "Startup AT probe timed out after #{total_timeout_s}s"
        end

        begin
          send_at('AT', probe_timeout_s)
          set_modem_ready(true, reason: 'startup probe OK')
          return true
        rescue ::Rex::TimeoutError, ::Rex::RuntimeError
          # suppress spam unless verbose; send_at already logs to vprint_status
        rescue ::StandardError => e
          log_debug("startup AT probe error: #{e.class} #{e.message}")
        end

        ::Rex.sleep(interval_s)
      end
    end

    def start_health_watchdog
  @health_stop = false
  @health_thread = @mod.framework.threads.spawn('cellular_modem_health_watchdog', false) do
    loop do
      break if @health_stop
      begin
        # Probe modem liveness
        send_at('AT', @cfg[:healthcheck_timeout])
        @health_fail_count = 0

        # If we were previously NOT READY, run minimal re-init (echo off) after reboot
        unless modem_ready?
          reinitialize_after_reboot
          set_modem_ready(true, reason: 'health probe OK')
        end
      rescue ::Rex::TimeoutError, ::Rex::RuntimeError
        @health_fail_count += 1
        if @health_fail_count >= @cfg[:healthcheck_max_fails]
          set_modem_ready(false, reason: "health probe failed #{@health_fail_count}x")
        end
      rescue ::StandardError => e
        @health_fail_count += 1
        log_debug("health probe exception: #{e.class} #{e.message}")
        if @health_fail_count >= @cfg[:healthcheck_max_fails]
          set_modem_ready(false, reason: "health probe exception #{@health_fail_count}x")
        end
      end
      ::Rex.sleep(@cfg[:healthcheck_interval])
    end
  end
end

def reinitialize_after_reboot
  # After a power cycle, the module often resets settings like echo.
  # If echo is enabled, the modem will echo QISEND payload bytes back on the AT port,
  # which can look like "binary URCs" in the console. Re-assert ATE0 once we're back.
  begin
    send_at('ATE0', @cfg[:cmd_timeout])
  rescue ::StandardError => e
    log_debug("reinitialize_after_reboot: ATE0 failed: #{e.class} #{e.message}")
  end

  # Best-effort drain any buffered garbage that may have accumulated during reboot.
  begin
    loop do
      r, _w, _e = ::IO.select([@serial], nil, nil, 0)
      break unless r && r.include?(@serial)
      @serial.read_nonblock(4096)
    end
  rescue ::IO::WaitReadable, ::EOFError, ::IOError
  end
end
# ========================================================================



    def close
      @health_stop = true
      @reader_stop = true
      begin
        @serial.close if @serial
      rescue ::IOError
      end
    end

    def log_debug(msg)
      @mod.vprint_status(msg)
    end

    # --- SID pool management ---

    def allocate_id
      sid = @free_ids.shift
      raise ::RuntimeError, 'No socket IDs available' unless sid
      sid
    end

    def release_id(sid)
      @free_ids << sid unless @free_ids.include?(sid)
      @conns.delete(sid)
    end

    # --- Public open API (QIOPEN flow) ---

    def open_connection(host, port)
      @open_lock.synchronize do
      sid = allocate_id
      conn = QuectelConnection.new(self, sid)
      @conns[sid] = conn

      begin
        cmd = %Q{AT+QIOPEN=1,#{sid},"TCP","#{host}",#{port},0,1}
        send_at(cmd, @cfg[:cmd_timeout])

        unless conn.open_event.wait(@cfg[:open_timeout])
          @mod.print_status("[SID #{sid}] QIOPEN timeout")
          release_id(sid)
          return nil
        end

        unless conn.open_ok
          @mod.print_status("[SID #{sid}] QIOPEN failed err=#{conn.open_err}")
          release_id(sid)
          return nil
        end

        conn
      rescue ::StandardError => e
        @mod.print_error("open_connection error (sid=#{sid}): #{e.class} #{e.message}")
        release_id(sid)
        nil
      end
      end
    end

    # --- AT helper with CmdWaiter ---

    def send_at(cmd, timeout = nil)
      timeout ||= @cfg[:cmd_timeout]
      @at_lock.synchronize do
        waiter = CmdWaiter.new(cmd)
        @cmd_mutex.synchronize do
          @pending_cmds << waiter
        end

        log_debug("→ AT #{cmd}")
        @mutex.synchronize do
          @serial.write("#{cmd}\r")
        end

        unless waiter.event.wait(timeout)
          @cmd_mutex.synchronize do
            @pending_cmds.delete(waiter)
          end
          raise ::Rex::TimeoutError, "AT cmd timeout: #{cmd}"
        end

        waiter.buf.each do |l|
          log_debug("← #{l}")
        end

        unless waiter.ok
          raise ::Rex::RuntimeError, "AT cmd error: #{cmd}"
        end

        waiter.buf.join("\n")
      end
    end

    # --- Reader loop and line handler ---

    def reader_loop
      loop do
        break if @reader_stop
        ch = nil
        begin
          ch = @serial.read(1)
        rescue ::EOFError, ::IOError => e
          @mod.print_error("serial read error: #{e.class} #{e.message}")
          break
        end
        next unless ch
        # QISEND '>' prompt (single char, no CRLF)
        if ch == '>'
          sid = @pending_send_sid
          if sid
            conn = @conns[sid]
            if conn
              conn.prompt_ok = true
              conn.prompt_event.set
            end
          end
          next
        end
        @line_buf << ch
        if @line_buf.end_with?("\r\n")
          line = @line_buf.strip
          @line_buf.clear
          handle_line(line)
        end
      end
    end

    def handle_line(line)
      # Avoid spewing raw binary to the console (can happen if echo is re-enabled after reboot)
      if line.bytes.any? { |b| b < 0x09 || (b > 0x0D && b < 0x20) || b == 0x7F }
        hex = line.bytes.first(32).map { |b| format('%02X', b) }.join(' ')
        log_debug("URC: [binary #{line.bytesize} bytes] #{hex}#{line.bytesize > 32 ? ' …' : '' }")
      else
        log_debug("URC: #{line}")
      end

      # Boot ready
      if line == 'RDY'
        @mod.print_status('[URC] RDY')
        @rdy_event.set
        return
      end

      if line =~ /(POWERED DOWN|POWER DOWN|NORMAL POWER DOWN)/i
        @mod.print_error("[URC] #{line}")
        set_modem_ready(false, reason: line)
        return
      end

      # First, feed pending command waiter if any
      @cmd_mutex.synchronize do
        if (waiter = @pending_cmds.first)
          case line
          when 'OK'
            waiter.buf << 'OK'
            waiter.ok  = true
            waiter.event.set
            @pending_cmds.shift
          when /^ERROR/, 'SEND FAIL'
            waiter.buf << line
            waiter.ok  = false
            waiter.event.set
            @pending_cmds.shift
          else
            waiter.buf << line
          end
        end
      end
      # +QIOPEN: sid,err
      if line.start_with?('+QIOPEN:')
        begin
          rest = line.split(':', 2)[1].strip
          parts = rest.split(',').map(&:strip)
          sid  = parts[0].to_i
          err  = parts[1].to_i
          if (conn = @conns[sid])
            conn.open_ok  = (err == 0)
            conn.open_err = err
            conn.open_event.set
          end
        rescue ::StandardError
        end
        return
      end

      # +QIURC: "recv",sid,len
      if line.start_with?('+QIURC: "recv"')
        begin
          parts = line.split(',')
          sid   = parts[1].to_i
          len   = parts[2].to_i
        rescue ::StandardError
          return
        end

        payload = ''.b
        while payload.bytesize < len
          begin
            chunk = @serial.read(len - payload.bytesize)
          rescue ::EOFError, ::IOError
            break
          end
          next unless chunk
          payload << chunk
        end

        if (conn = @conns[sid])
          conn.push_payload(payload)
        end
        return
      end

      # +QIURC: "closed",sid
      if line.start_with?('+QIURC: "closed"')
        begin
          sid = line.split(',')[1].to_i
        rescue ::StandardError
          return
        end
        if (conn = @conns[sid])
          conn.mark_closed
        end
        return
      end

      # QISEND results / early rejects mapped via pending_send_sid
      if ['SEND OK', 'SEND FAIL', 'ERROR'].include?(line)
        sid = @pending_send_sid
        if sid && (conn = @conns[sid])
          ok = (line == 'SEND OK')
          conn.ack_ok = ok
          conn.ack_event.set

          # If the modem rejects QISEND before issuing a '>' prompt, wake the sender
          # that's blocked waiting on prompt_event.
          if !ok && line == 'ERROR'
            conn.prompt_ok = false
            conn.prompt_event.set
          end
        end
        return
      end
    end

    def wait_for_rdy(timeout)
      @rdy_event.wait(timeout)
    end
  end

  # === Metasploit module proper ============================================

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Cell Module SOCKS5 Proxy (Serial AT, serialized AT transactions)',
      'Description' => %q{
        Cellular module socks5 proxy agent - These socks5 proxy allows for directing metasploit
        modules or external clients to redirect communication through a cellular module main UART port leveraging cellular
        module AT socket command

        Auxiliary/server module that opens a serial connection to a
        Cell Module (or similar) cellular module and exposes a SOCKS5 proxy
        on SRVHOST:SRVPORT (default 0.0.0.0:1080).
      },
      'Author'      => [ 'Deral Heiland' ],
      'License'     => MSF_LICENSE
    ))

    register_options(
      [
        OptString.new('SERIAL',  [ true, 'Serial device for Quectel modem', '/dev/ttyUSB0' ]),
        OptInt.new('BAUD',       [ true, 'Serial baud rate', 115200 ]),

        # Advanced performance knobs (tune as needed)
        OptInt.new('MODEM_SOCKETS', [ true, 'Number of Quectel socket IDs (SID pool size)', DEFAULT_MODEM_SOCKETS ]),
        OptInt.new('MAX_CHUNK_SIZE', [ true, 'Bytes per AT+QISEND chunk', DEFAULT_MAX_CHUNK_SIZE ]),
        OptInt.new('SELECT_TIMEOUT_MS', [ true, 'Relay loop poll interval (ms)', DEFAULT_SELECT_TIMEOUT_MS ]),
        OptInt.new('PROMPT_TIMEOUT_MS', [ true, "Timeout waiting for QISEND '>' prompt (ms)", DEFAULT_PROMPT_TIMEOUT_MS ]),
        OptInt.new('ACK_TIMEOUT_MS', [ true, 'Timeout waiting for SEND OK/FAIL (ms)', DEFAULT_ACK_TIMEOUT_MS ]),
        OptInt.new('OPEN_TIMEOUT_MS', [ true, 'Timeout waiting for +QIOPEN URC (ms)', DEFAULT_OPEN_TIMEOUT_MS ]),
        OptInt.new('CMD_TIMEOUT_MS', [ true, 'Timeout waiting for AT command OK/ERROR (ms)', DEFAULT_CMD_TIMEOUT_MS ]),

        # modem readiness / health watchdog
        OptInt.new('STARTUP_OK_TIMEOUT_S',   [ true, 'Startup: total seconds to wait for first AT OK (0 = no timeout)', DEFAULT_STARTUP_OK_TIMEOUT_S ]),
        OptInt.new('STARTUP_OK_INTERVAL_MS', [ true, 'Startup: delay between AT probes (ms)', DEFAULT_STARTUP_OK_INTERVAL_MS ]),
        OptInt.new('HEALTHCHECK_INTERVAL_S', [ true, 'Runtime: seconds between modem AT health probes', DEFAULT_HEALTHCHECK_INTERVAL_S ]),
        OptInt.new('HEALTHCHECK_TIMEOUT_MS', [ true, 'Runtime: AT health probe timeout (ms)', DEFAULT_HEALTHCHECK_TIMEOUT_MS ]),
        OptInt.new('HEALTHCHECK_MAX_FAILS',  [ true, 'Runtime: consecutive AT probe failures before marking modem NOT READY', DEFAULT_HEALTHCHECK_MAX_FAILS ]),
        OptInt.new('MODEM_BACKOFF_S',        [ true, 'Hold SOCKS CONNECT up to N seconds if modem not ready (AT!=OK). 0 disables.', 30 ]),
        OptInt.new('MODEM_BACKOFF_POLL_S',   [ true, 'Polling interval (seconds) while holding CONNECT waiting for modem readiness.', 1 ]),
        OptInt.new('RECV_DRAIN_MAX_CHUNKS', [ true, 'Max modem->client payload chunks per relay loop', DEFAULT_RECV_DRAIN_MAX_CHUNKS ]),
        OptInt.new('RECV_DRAIN_MAX_BYTES', [ true, 'Max modem->client bytes per relay loop', DEFAULT_RECV_DRAIN_MAX_BYTES ]),

        OptAddress.new('SRVHOST',[ true, 'Local host to listen on', '0.0.0.0' ]),
        OptPort.new('SRVPORT',   [ true, 'Local port to listen on (SOCKS5)', 1080 ])
      ]
    )

    @modem = nil
    @cfg = {}
  end

  def setup
    super
    dev  = datastore['SERIAL']
    baud = datastore['BAUD'].to_i

    # Build runtime config from datastore (keep everything in seconds/bytes internally)
    @cfg = {
      modem_sockets:        [datastore['MODEM_SOCKETS'].to_i, 1].max,
      max_chunk_size:       [datastore['MAX_CHUNK_SIZE'].to_i, 1].max,
      select_timeout:       [datastore['SELECT_TIMEOUT_MS'].to_i, 0].max / 1000.0,
      prompt_timeout:       [datastore['PROMPT_TIMEOUT_MS'].to_i, 0].max / 1000.0,
      ack_timeout:          [datastore['ACK_TIMEOUT_MS'].to_i, 0].max / 1000.0,
      open_timeout:         [datastore['OPEN_TIMEOUT_MS'].to_i, 0].max / 1000.0,
      cmd_timeout:          [datastore['CMD_TIMEOUT_MS'].to_i, 0].max / 1000.0,
      startup_ok_timeout:   [datastore['STARTUP_OK_TIMEOUT_S'].to_i, 0].max,
      startup_ok_interval:  [datastore['STARTUP_OK_INTERVAL_MS'].to_i, 0].max / 1000.0,
      healthcheck_interval: [datastore['HEALTHCHECK_INTERVAL_S'].to_i, 0].max,
      healthcheck_timeout:  [datastore['HEALTHCHECK_TIMEOUT_MS'].to_i, 0].max / 1000.0,
      healthcheck_max_fails:[datastore['HEALTHCHECK_MAX_FAILS'].to_i, 1].max,
      modem_backoff_s:      [datastore['MODEM_BACKOFF_S'].to_i, 0].max,
      modem_backoff_poll_s: [datastore['MODEM_BACKOFF_POLL_S'].to_i, 1].max,
      recv_drain_max_chunks:[datastore['RECV_DRAIN_MAX_CHUNKS'].to_i, 1].max,
      recv_drain_max_bytes: [datastore['RECV_DRAIN_MAX_BYTES'].to_i, 1].max
    }

    # Configure serial line discipline via stty
    print_status("Configuring serial port #{dev} to #{baud} via stty")
    stty_cmd = "stty -F #{dev} #{baud} cs8 -cstopb -parenb -ixon -ixoff -crtscts -echo raw"
    unless system(stty_cmd)
      print_error("Failed to run stty for #{dev}. Check permissions and device existence.")
    end

    # Initialize modem wrapper (opens serial, starts reader, waits RDY, sends ATE0)
    @modem = QuectelModem.new(self, dev, baud, framework, @cfg)
  end

  def cleanup
    @modem&.close
    super
  end

  def run
    host = datastore['SRVHOST'] || '0.0.0.0'
    port = datastore['SRVPORT'] || 1080

    print_status(" Quectel SOCKS5 proxy listening on #{host}:#{port} (sids=#{@cfg[:modem_sockets]}, chunk=#{@cfg[:max_chunk_size]}B)")
    start_service
    print_status(' listener started, waiting for SOCKS5 clients (Ctrl-C or jobs -k to stop)…')

    sleep
  end

  # === TcpServer hooks / SOCKS5 handling ====================================

  def on_client_connect(client)
    peer = "#{client.peerhost}:#{client.peerport}"
    print_status("Client connected from #{peer}")

    framework.threads.spawn("cellular_socks_client_msf_#{peer}", false) do
      begin
        handle_socks5_client(client)
      rescue ::StandardError => e
        print_error("Error handling client #{peer}: #{e.class} #{e.message}")
      ensure
        begin
          client.close
        rescue ::IOError, ::Errno::ENOTCONN
        end
      end
    end
  end

  def read_exact(cli, n)
    buf = ''.b
    while buf.bytesize < n
      chunk = cli.get_once(n - buf.bytesize)
      raise ::EOFError, 'SOCKS peer closed' if !chunk || chunk.empty?
      buf << chunk
    end
    buf
  end

  def handle_socks5_client(client)
    conn = nil
    begin
      # --- SOCKS5 greeting ---
      head = read_exact(client, 2)
      ver  = head.getbyte(0)
      nmethods = head.getbyte(1)
      return unless ver == 5
      _methods = read_exact(client, nmethods) # discard
      client.put("\x05\x00")                 # no-auth

      # --- SOCKS5 request (CONNECT only) ---
      hdr = read_exact(client, 4)
      _ver, cmd, _rsv, atyp = hdr.bytes
      unless _ver == 5
        return
      end
      unless cmd == 1  # CONNECT
        send_socks_reply(client, 7) # command not supported
        return
      end

      addr = nil
      case atyp
      when 1 # IPv4
        raw = read_exact(client, 4)
        addr = raw.bytes.join('.')
      when 3 # domain
        alen = read_exact(client, 1).getbyte(0)
        raw = read_exact(client, alen)
        addr = raw
      when 4 # IPv6
        raw = read_exact(client, 16)
        parts = raw.unpack('n8').map { |x| sprintf('%x', x) }
        addr  = parts.each_slice(2).map { |s| s.join(':') }.join(':')
      else
        send_socks_reply(client, 8) # address type not supported
        return
      end

      port_raw = read_exact(client, 2)
      port = port_raw.unpack('n').first

      peer = "#{client.peerhost}:#{client.peerport}"
      print_status("SOCKS5 CONNECT #{addr}:#{port} from #{peer}")

      # --- Backoff/Hold if modem not ready (AT!=OK) ---
      unless @modem.modem_ready?
        backoff_s = @cfg[:modem_backoff_s].to_i
        poll_s    = @cfg[:modem_backoff_poll_s].to_i

        if backoff_s > 0
          print_status("[HOLD] Modem not ready (AT!=OK). Holding CONNECT up to #{backoff_s}s for #{addr}:#{port}...")
          unless @modem.wait_for_modem_ready(backoff_s, poll_s)
            print_error("[HOLD] Modem still not ready after #{backoff_s}s. Failing CONNECT #{addr}:#{port}")
            send_socks_reply(client, 1) # general failure
            return
          end
          print_status("[HOLD] Modem ready again. Continuing CONNECT #{addr}:#{port}")
        else
          print_error("[HOLD] Modem not ready and backoff disabled. Failing CONNECT #{addr}:#{port}")
          send_socks_reply(client, 1) # general failure
          return
        end
      end


      # --- Open through modem ---
      conn = @modem.open_connection(addr, port)
      unless conn
        send_socks_reply(client, 1) # general failure
        return
      end

      # Success
      send_socks_reply(client, 0)

      # --- Relay loop ---
      loop do
        # Client -> Modem
        unless conn.closed_flag
          r, _w, _e = IO.select([client], nil, nil, @cfg[:select_timeout])
          if r && r.include?(client)
            data = client.get_once(4096)
            if !data || data.empty?
              print_status("Client closed connection for #{peer}")
              break
            end

            offset = 0
            while offset < data.bytesize
              chunk = data.byteslice(offset, @cfg[:max_chunk_size])
              offset += chunk.bytesize
              vprint_status("Client->Modem: #{chunk.bytesize} bytes for #{peer} (sid=#{conn.sock_id})")
              conn.send(chunk)
            end
          end
        end

        # Modem -> Client (drain queued payload)
        drained_chunks = 0
        drained_bytes  = 0
        loop do
          payload = conn.recv_nonblock
          break if payload.nil?

          if payload == :closed
            print_status("Modem->Client: modem reported socket #{conn.sock_id} closed for #{peer}")
            break
          end

          next if payload.empty?

          vprint_status("Modem->Client: #{payload.bytesize} bytes for #{peer} (sid=#{conn.sock_id})")
          begin
            client.put(payload)
            drained_chunks += 1
            drained_bytes  += payload.bytesize
          rescue ::IOError, ::Errno::EPIPE
            print_error("Modem->Client: write failed for #{peer}, closing")
            break
          end

          break if drained_chunks >= @cfg[:recv_drain_max_chunks]
          break if drained_bytes  >= @cfg[:recv_drain_max_bytes]
        end
      end

      print_status("Relay loop exiting for #{peer} (sid=#{conn.sock_id})")
    rescue ::EOFError
      # client closed early
    rescue ::StandardError => e
      print_error("handle_socks5_client error: #{e.class} #{e.message}")
    ensure
      begin
        conn&.close
      rescue ::StandardError
      end
    end
  end

  def send_socks_reply(client, rep)
    reply = [
      0x05,       # VER
      rep,        # REP
      0x00,       # RSV
      0x01,       # ATYP = IPv4
      0x00, 0x00, 0x00, 0x00, # BND.ADDR
      0x00, 0x00              # BND.PORT
    ].pack('C*')
    begin
      client.put(reply)
    rescue ::IOError, ::Errno::EPIPE
      # ignore
    end
  end
end
