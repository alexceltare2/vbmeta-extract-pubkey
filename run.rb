###############################################################################
#
# Ruby tool for extracting a public key in both PEM and fastboot/avb format
# directly from an existing vbmeta image.
#
# by Richard Lees
#
# notice:
# ANY ACTION TAKEN BY YOURSELF AS A RESULT OF USING THIS TOOL IS NOT MY
# RESPONSIBILITY. THIS TOOL HAS NOT BEEN WIDELY TESTED. USE ONLY IF YOU KNOW
# WHAT YOU ARE DOING AND AT YOUR OWN RISK.
#
###############################################################################
#
# Process mainly taken from avbtool.
# avbtool notice:
#
# Copyright 2016, The Android Open Source Project
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use, copy,
# modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
###############################################################################

require 'openssl'

###############################################################################

require_relative 'lib/AvbVBMetaFooter.rb'
require_relative 'lib/AvbVBMetaHeader.rb'

###############################################################################

def encode_long(bits, value)
  result = String.new
  bits.step(1, -8) do |pos|
    octet = (value >> (pos - 8)) & 255
    result = result + [ octet ].pack("C")
  end

  return result
end

###############################################################################

def modinv2(a, m)
  raise "NO INVERSE - #{a} and #{m} not coprime" unless a.gcd(m) == 1
  return m if m == 1
  m0, inv, x0 = m, 1, 0
  while a > 1
    inv -= (a / m) * x0
    a, m = m, a % m
    inv, x0 = x0, inv
  end
  inv += m0 if inv < 0
  inv
end

###############################################################################

abort("Exactly 2 arguments must be given. First argument must be a path to a valid VBMeta image. Second argument must be a string to name the output public keys.") unless ARGV.length == 2

vbmeta_image = ARGV[0]
output_name  = ARGV[1]

abort("VBMeta image name is not a string!") unless vbmeta_image.kind_of?(String)
abort("VBMeta image name is blank!") if vbmeta_image.empty?
abort("VBMeta image does not exist!") unless File.file?(vbmeta_image)

abort("Output public key name is not a string!") unless output_name.kind_of?(String)
abort("Output public key name is blank!") if output_name.empty?

public_key = OpenSSL::PKey::RSA.new

vbmeta_header_format_string = "I<S<4I<4"
vbmeta_header_length        = 14
vbmeta_image_size           = File.size(vbmeta_image)

puts("Opening VBMeta image: #{vbmeta_image}, size: #{vbmeta_image_size.to_s}...")
File.open(vbmeta_image, 'rb') do |f|
  header_bytes = f.read(vbmeta_header_length)

  begin
    header_array = header_bytes.unpack(vbmeta_header_format_string)
  rescue
    abort("Could not unpack VBMeta image file header.")
  end

  magic          = header_array[0]
  major_version  = header_array[1]
  minor_version  = header_array[2]
  file_hdr_size  = header_array[3]
  chunk_hdr_size = header_array[4]
  block_size     = header_array[5]
  total_blocks   = header_array[6]
  total_chunks   = header_array[7]

  puts("Magic            : #{magic.to_s}")
  puts("Major Version    : #{major_version.to_s}")
  puts("Minor Version    : #{minor_version.to_s}")
  puts("File Header Size : #{file_hdr_size.to_s}")
  puts("Chunk Header Size: #{chunk_hdr_size.to_s}")
  puts("Block Size       : #{block_size.to_s}")
  puts("Total Blocks     : #{total_blocks.to_s}")
  puts("Total Chunks     : #{total_chunks.to_s}")

  abort("Sparse images are not supported!") if magic == 3978755898

  header_offset = 0
  footer_offset = vbmeta_image_size - VBMETA_FOOTER_SIZE

  puts("Checking for footer at offset: #{footer_offset.to_s}")
  f.seek(footer_offset)
  footer = AvbVBMetaFooter.new(f.read(VBMETA_FOOTER_SIZE))

  if footer.magic == "AVBf" then
    puts("Magic              : #{footer.magic}")
    puts("Major Version      : #{footer.version_major.to_s}")
    puts("Minor Version      : #{footer.version_minor.to_s}")
    puts("Original Image Size: #{footer.original_image_size.to_s}")
    puts("VBMeta Offset      : #{footer.vbmeta_offset.to_s}")
    puts("VBMeta Size        : #{footer.vbmeta_size.to_s}")

    header_offset = footer.vbmeta_offset
  else
    puts("No footer found! Assuming header is at the beginning of the file.")
  end

  puts("Attempting to read header at offset: #{header_offset.to_s}")
  f.seek(header_offset)
  header = AvbVBMetaHeader.new(f.read(VBMETA_HEADER_SIZE))

  if header.magic == "AVB0" then
    puts("Magic                         : #{header.magic}")
    puts("Required Major Version        : #{header.required_libavb_version_major.to_s}")
    puts("Required Minor Version        : #{header.required_libavb_version_minor.to_s}")
    puts("Authentication Data Block Size: #{header.authentication_data_block_size.to_s}")
    puts("Auxiliary Data Block Size     : #{header.auxiliary_data_block_size.to_s}")
    puts("Algorithm Type                : #{header.algorithm_type.to_s}")
    puts("Hash Offset                   : #{header.hash_offset.to_s}")
    puts("Hash Size                     : #{header.hash_size.to_s}")
    puts("Signature Offset              : #{header.signature_offset.to_s}")
    puts("Signature Size                : #{header.signature_size.to_s}")
    puts("Public Key Offset             : #{header.public_key_offset.to_s}")
    puts("Public Key Size               : #{header.public_key_size.to_s}")
    puts("Public Key Metadata Offset    : #{header.public_key_metadata_offset.to_s}")
    puts("Public Key Metadata Size      : #{header.public_key_metadata_size.to_s}")
    puts("Descriptors Offset            : #{header.descriptors_offset.to_s}")
    puts("Descriptors Size              : #{header.descriptors_size.to_s}")
    puts("Rollback Index                : #{header.rollback_index.to_s}")
    puts("Flags                         : #{header.flags.to_s}")
    puts("Release                       : #{header.release_string}")
  else
    abort("Failed to read header: bad magic: #{header.magic}.")
  end

  abort("This VBMeta image appears to be unsigned, therefore has no public key to export!") if header.algorithm_type <= 0

  vbmeta_auth_offset = 256
  vbmeta_aux_offset  = vbmeta_auth_offset + header.authentication_data_block_size

  vbmeta_pubkey_offset = vbmeta_aux_offset + header.public_key_offset
  puts("Reading public key, size: #{header.public_key_size.to_s} at offset: #{vbmeta_pubkey_offset.to_s}...")
  f.seek(vbmeta_pubkey_offset)
  vbmeta_pubkey = f.read(header.public_key_size)

  puts("Finding public key bit length...")
  begin
    vbmeta_pubkey_bits = vbmeta_pubkey[0, 4].unpack("I>")[0]
    raise("Public key bits seems invalid: #{vbmeta_pubkey_bits.to_s}") unless vbmeta_pubkey_bits.kind_of?(Integer) and vbmeta_pubkey_bits > 0
  rescue
    abort("Failed to get public key length. Unexpected data!")
  end
  puts("Public key bit length: #{vbmeta_pubkey_bits.to_s}")

  puts("Reading modulus...")
  vbmeta_modulus = 0
  vbmeta_pubkey[8, (vbmeta_pubkey_bits / 8)].each_byte do |b|
    vbmeta_modulus *= 256
    vbmeta_modulus += b.to_i
  end

  public_key_seq = [
    OpenSSL::ASN1::Integer.new(vbmeta_modulus),
    OpenSSL::ASN1::Integer.new(65537)
  ]

  public_key_der = OpenSSL::ASN1::Sequence(public_key_seq).to_der
  public_key = OpenSSL::PKey::RSA.new(public_key_der)
end

puts("Writing out PEM public key...")

File.open("#{output_name}.pem", 'w') do |f|
  f.write(public_key.to_pem)
end

puts("Preparing key in fastboot format...")
b = 2 ** 32
n0inv = b - modinv2(public_key.n.to_i, b)
r = 2 ** public_key.n.num_bits
rrmodn = r * r % public_key.n.to_i

fastboot_key = [ public_key.n.num_bits, n0inv ].pack("I>2")
fastboot_key = fastboot_key + encode_long(public_key.n.num_bits, public_key.n.to_i)
fastboot_key = fastboot_key + encode_long(public_key.n.num_bits, rrmodn)

puts("Writing out fastboot public key...")

File.open("#{output_name}.img", 'wb') do |f|
  f.write(fastboot_key)
end

###############################################################################
