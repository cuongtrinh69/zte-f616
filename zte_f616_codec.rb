#!/usr/bin/env ruby
# frozen_string_literal: true

require 'digest'
require 'openssl'
require 'optparse'
require 'zlib'

OUTER_MAGIC = "\x04\x03\x02\x01".b
INNER_MAGIC = "\x01\x02\x03\x04".b
SIGNATURE = 'F616'.b
PAYLOAD_TYPE = 5
OUTER_HEADER_SIZE = 0x58
OUTER_INNER_LEN_OFFSET = 0x4C
OUTER_CIPHER_LEN_OFFSET = 0x50
OUTER_MORE_OFFSET = 0x54
INNER_FIXED_HEADER_SIZE = 60
DEFAULT_CHUNK_SIZE = 65_536
AES_BLOCK_SIZE = 16


def read_file(path)
  File.binread(path)
end


def write_file(path, data)
  File.binwrite(path, data)
end


def u32be(data, offset)
  data.byteslice(offset, 4).unpack1('N')
end


def p32be(value)
  [value].pack('N')
end


def set_u32be!(data, offset, value)
  data[offset, 4] = p32be(value)
end


def derive_key_iv(key_string, iv_string)
  key = Digest::SHA256.digest(key_string.encode('UTF-8'))
  iv = Digest::SHA256.digest(iv_string.encode('UTF-8')).byteslice(0, 16)
  [key, iv]
end


def zero_pad(data)
  data + ("\x00".b * ((-data.bytesize) % AES_BLOCK_SIZE))
end


def aes_cbc_encrypt(data, key, iv)
  cipher = OpenSSL::Cipher.new('AES-256-CBC')
  cipher.encrypt
  cipher.padding = 0
  cipher.key = key
  cipher.iv = iv
  cipher.update(data) + cipher.final
end


def aes_cbc_decrypt(data, key, iv)
  cipher = OpenSSL::Cipher.new('AES-256-CBC')
  cipher.decrypt
  cipher.padding = 0
  cipher.key = key
  cipher.iv = iv
  cipher.update(data) + cipher.final
end


def parse_outer(data)
  raise 'File ngắn hơn header F616 0x58 byte' if data.bytesize < OUTER_HEADER_SIZE
  raise "Sai outer magic: #{data.byteslice(0, 4).unpack1('H*')}" unless data.byteslice(0, 4) == OUTER_MAGIC

  sig_len = u32be(data, 8)
  signature = data.byteslice(12, sig_len)
  raise "Chữ ký không phải F616: #{signature.inspect}" unless signature == SIGNATURE
  raise 'Thiếu payload magic 01 02 03 04 tại offset 0x10' unless data.byteslice(0x10, 4) == INNER_MAGIC

  payload_type = u32be(data, 0x14)
  raise "Payload type không phải 5: #{payload_type}" unless payload_type == PAYLOAD_TYPE

  inner_len = u32be(data, OUTER_INNER_LEN_OFFSET)
  cipher_len = u32be(data, OUTER_CIPHER_LEN_OFFSET)
  more = u32be(data, OUTER_MORE_OFFSET)

  expected = OUTER_HEADER_SIZE + cipher_len
  raise "Sai kích thước file: file=#{data.bytesize}, expected=#{expected}" unless data.bytesize == expected
  raise 'Ciphertext không chia hết cho 16' unless (cipher_len % AES_BLOCK_SIZE).zero?
  raise 'Inner length lớn hơn ciphertext' if inner_len > cipher_len

  {
    signature: signature,
    payload_type: payload_type,
    inner_len: inner_len,
    cipher_len: cipher_len,
    more: more
  }
end


def decrypt_inner(data, key, iv)
  meta = parse_outer(data)
  ciphertext = data.byteslice(OUTER_HEADER_SIZE, meta[:cipher_len])
  plain_padded = aes_cbc_decrypt(ciphertext, key, iv)
  inner = plain_padded.byteslice(0, meta[:inner_len])
  padding = plain_padded.byteslice(meta[:inner_len], plain_padded.bytesize - meta[:inner_len]) || ''.b
  raise 'Padding sau inner payload không phải toàn byte 0' unless padding.bytes.all?(&:zero?)

  inner
end


def parse_inner(inner)
  raise 'Inner payload quá ngắn' if inner.bytesize < INNER_FIXED_HEADER_SIZE
  raise "Sai inner magic: #{inner.byteslice(0, 4).unpack1('H*')}" unless inner.byteslice(0, 4) == INNER_MAGIC

  payload_type, xml_len, last_chunk_offset, chunk_size, payload_crc = inner.byteslice(4, 20).unpack('N5')
  raise "Inner payload type không phải 0: #{payload_type}" unless payload_type.zero?

  header_crc = u32be(inner, 24)
  calculated_header_crc = Zlib.crc32(inner.byteslice(0, 24))
  raise format('Sai header CRC: stored=0x%08x calc=0x%08x', header_crc, calculated_header_crc) unless header_crc == calculated_header_crc
  raise 'Reserved bytes trong inner header không bằng 0' unless inner.byteslice(28, 32).bytes.all?(&:zero?)

  pos = INNER_FIXED_HEADER_SIZE
  xml_parts = []
  compressed_crc = 0
  chunk_count = 0
  observed_last_chunk_offset = INNER_FIXED_HEADER_SIZE

  loop do
    raise 'Chunk header bị cắt' if pos + 12 > inner.bytesize

    chunk_start = pos
    uncompressed_len, compressed_len, next_offset = inner.byteslice(pos, 12).unpack('N3')
    pos += 12
    raise 'Dữ liệu zlib bị cắt' if pos + compressed_len > inner.bytesize

    compressed = inner.byteslice(pos, compressed_len)
    pos += compressed_len
    raw = Zlib::Inflate.inflate(compressed)
    raise "Sai độ dài chunk #{chunk_count}" unless raw.bytesize == uncompressed_len

    compressed_crc = Zlib.crc32(compressed, compressed_crc)
    xml_parts << raw
    chunk_count += 1

    if next_offset.zero?
      observed_last_chunk_offset = chunk_start
      break
    end

    raise "Sai next offset ở chunk #{chunk_count - 1}: declared=#{next_offset} actual=#{pos}" unless next_offset == pos
    pos = next_offset
  end

  raise "Có #{inner.bytesize - pos} byte dư trong inner payload" unless pos == inner.bytesize
  raise format('Sai payload CRC: stored=0x%08x calc=0x%08x', payload_crc, compressed_crc) unless payload_crc == compressed_crc

  xml = xml_parts.join
  raise "Sai XML length: declared=#{xml_len} actual=#{xml.bytesize}" unless xml.bytesize == xml_len
  if chunk_count > 1 && last_chunk_offset != observed_last_chunk_offset
    raise "Sai last chunk offset: declared=#{last_chunk_offset} actual=#{observed_last_chunk_offset}"
  end

  [xml, {
    inner_payload_type: payload_type,
    xml_len: xml_len,
    last_chunk_offset: last_chunk_offset,
    chunk_size: chunk_size,
    payload_crc: payload_crc,
    header_crc: header_crc,
    chunk_count: chunk_count
  }]
end


def build_inner(xml, chunk_size = DEFAULT_CHUNK_SIZE)
  chunks = []
  start = 0
  while start < xml.bytesize
    raw = xml.byteslice(start, [chunk_size, xml.bytesize - start].min)
    compressed = Zlib::Deflate.deflate(raw, Zlib::BEST_COMPRESSION)
    chunks << [raw, compressed]
    start += raw.bytesize
  end
  chunks << [''.b, Zlib::Deflate.deflate(''.b, Zlib::BEST_COMPRESSION)] if chunks.empty?

  body = ''.b
  payload_crc = 0
  last_chunk_offset = INNER_FIXED_HEADER_SIZE

  chunks.each_with_index do |(raw, compressed), index|
    chunk_start = INNER_FIXED_HEADER_SIZE + body.bytesize
    next_offset = index + 1 < chunks.length ? chunk_start + 12 + compressed.bytesize : 0
    body << [raw.bytesize, compressed.bytesize, next_offset].pack('N3')
    body << compressed
    payload_crc = Zlib.crc32(compressed, payload_crc)
    last_chunk_offset = chunk_start
  end

  header24 = [0x01020304, 0, xml.bytesize, last_chunk_offset, chunk_size, payload_crc].pack('N6')
  header_crc = Zlib.crc32(header24)
  header24 + p32be(header_crc) + ("\x00".b * 32) + body
end


def encode_file(template, xml, key, iv)
  parse_outer(template)
  inner = build_inner(xml)
  ciphertext = aes_cbc_encrypt(zero_pad(inner), key, iv)

  header = template.byteslice(0, OUTER_HEADER_SIZE).dup
  set_u32be!(header, OUTER_INNER_LEN_OFFSET, inner.bytesize)
  set_u32be!(header, OUTER_CIPHER_LEN_OFFSET, ciphertext.bytesize)
  set_u32be!(header, OUTER_MORE_OFFSET, 0)
  header + ciphertext
end


def first_difference(a, b)
  limit = [a.bytesize, b.bytesize].min
  (0...limit).each do |i|
    return [i, a.getbyte(i), b.getbyte(i)] if a.getbyte(i) != b.getbyte(i)
  end
  return nil if a.bytesize == b.bytesize

  [limit, nil, nil]
end


def command_roundtrip(bin_path, out_path, key_string, iv_string)
  original = read_file(bin_path)
  key, iv = derive_key_iv(key_string, iv_string)
  xml, = parse_inner(decrypt_inner(original, key, iv))
  rebuilt = encode_file(original, xml, key, iv)
  identical = rebuilt == original

  puts "Ruby:             #{RUBY_VERSION}"
  puts "Zlib:             #{Zlib.zlib_version}"
  puts "Original SHA-256: #{Digest::SHA256.hexdigest(original)}"
  puts "Rebuilt SHA-256:  #{Digest::SHA256.hexdigest(rebuilt)}"
  puts "Byte-identical:   #{identical ? 'YES' : 'NO'}"

  if out_path
    write_file(out_path, rebuilt)
    puts "Rebuilt file:     #{out_path}"
  end

  unless identical
    diff = first_difference(original, rebuilt)
    if diff
      offset, old_byte, new_byte = diff
      if old_byte && new_byte
        puts format('First difference: offset 0x%X, original=0x%02X, rebuilt=0x%02X', offset, old_byte, new_byte)
      else
        puts format('First difference: length diverges at offset 0x%X', offset)
      end
    end
    exit 2
  end
end


def command_decode(bin_path, out_path, key_string, iv_string)
  data = read_file(bin_path)
  key, iv = derive_key_iv(key_string, iv_string)
  xml, meta = parse_inner(decrypt_inner(data, key, iv))
  write_file(out_path, xml)
  puts "[+] Decoded: #{bin_path} -> #{out_path}"
  puts "[+] XML bytes: #{xml.bytesize}"
  puts "[+] Zlib chunks: #{meta[:chunk_count]}"
  puts "[+] XML SHA-256: #{Digest::SHA256.hexdigest(xml)}"
end


def command_encode(template_path, xml_path, out_path, key_string, iv_string)
  template = read_file(template_path)
  xml = read_file(xml_path)
  key, iv = derive_key_iv(key_string, iv_string)
  output = encode_file(template, xml, key, iv)
  write_file(out_path, output)

  decoded, = parse_inner(decrypt_inner(output, key, iv))
  raise 'Internal round-trip thất bại' unless decoded == xml

  puts "[+] Encoded: #{xml_path} -> #{out_path}"
  puts "[+] Output bytes: #{output.bytesize}"
  puts "[+] SHA-256: #{Digest::SHA256.hexdigest(output)}"
  puts '[+] Internal round-trip: OK'
  puts "[+] Byte-identical to template: #{output == template ? 'YES' : 'NO'}"
end


def command_inspect(bin_path, key_string, iv_string)
  data = read_file(bin_path)
  meta = parse_outer(data)
  puts "File size:         #{data.bytesize}"
  puts "SHA-256:           #{Digest::SHA256.hexdigest(data)}"
  puts "Signature:         #{meta[:signature]}"
  puts "Payload type:      #{meta[:payload_type]}"
  puts "Outer header size: #{OUTER_HEADER_SIZE}"
  puts "Inner length:      #{meta[:inner_len]}"
  puts "Cipher length:     #{meta[:cipher_len]}"

  return unless key_string && iv_string

  key, iv = derive_key_iv(key_string, iv_string)
  xml, imeta = parse_inner(decrypt_inner(data, key, iv))
  puts 'AES:               AES-256-CBC'
  puts 'Padding:           zero padding'
  puts "Zlib chunks:       #{imeta[:chunk_count]}"
  puts "Decoded XML size:  #{xml.bytesize}"
  puts "XML SHA-256:       #{Digest::SHA256.hexdigest(xml)}"
end


def usage!
  warn <<~TEXT
    Dùng:
      ruby zte_f616_codec.rb inspect FILE [--key-string KEY --iv-string IV]
      ruby zte_f616_codec.rb decode FILE OUT.xml --key-string KEY --iv-string IV
      ruby zte_f616_codec.rb encode --template FILE --xml FILE.xml --out OUT.bin --key-string KEY --iv-string IV
      ruby zte_f616_codec.rb roundtrip FILE [--out OUT.bin] --key-string KEY --iv-string IV
  TEXT
  exit 1
end

command = ARGV.shift || usage!
options = {}
parser = OptionParser.new do |opts|
  opts.on('--template PATH') { |v| options[:template] = v }
  opts.on('--xml PATH') { |v| options[:xml] = v }
  opts.on('--out PATH') { |v| options[:out] = v }
  opts.on('--key-string VALUE') { |v| options[:key_string] = v }
  opts.on('--iv-string VALUE') { |v| options[:iv_string] = v }
end
parser.parse!(ARGV)

case command
when 'inspect'
  bin_path = ARGV.shift || usage!
  command_inspect(bin_path, options[:key_string], options[:iv_string])
when 'decode'
  bin_path = ARGV.shift || usage!
  out_path = ARGV.shift || usage!
  usage! unless options[:key_string] && options[:iv_string]
  command_decode(bin_path, out_path, options[:key_string], options[:iv_string])
when 'encode'
  usage! unless options[:template] && options[:xml] && options[:out] && options[:key_string] && options[:iv_string]
  command_encode(options[:template], options[:xml], options[:out], options[:key_string], options[:iv_string])
when 'roundtrip'
  bin_path = ARGV.shift || usage!
  usage! unless options[:key_string] && options[:iv_string]
  command_roundtrip(bin_path, options[:out], options[:key_string], options[:iv_string])
else
  usage!
end
