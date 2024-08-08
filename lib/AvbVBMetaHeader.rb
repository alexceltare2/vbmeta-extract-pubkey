###############################################################################

VBMETA_HEADER_SIZE = 256

###############################################################################

class AvbVBMetaHeader

  @@reserved  = 80
  @@reserved0 = 4

  attr_reader :magic
  attr_reader :required_libavb_version_major
  attr_reader :required_libavb_version_minor
  attr_reader :authentication_data_block_size
  attr_reader :auxiliary_data_block_size
  attr_reader :algorithm_type
  attr_reader :hash_offset
  attr_reader :hash_size
  attr_reader :signature_offset
  attr_reader :signature_size
  attr_reader :public_key_offset
  attr_reader :public_key_size
  attr_reader :public_key_metadata_offset
  attr_reader :public_key_metadata_size
  attr_reader :descriptors_offset
  attr_reader :descriptors_size
  attr_reader :rollback_index
  attr_reader :flags
  attr_reader :release_string

  def initialize(raw)
    format_array = [
      "a4L>2",                # Magic, 2x Version
      "Q>2",                  # 2x Block Size
      "L>",                   # Algorithm Type
      "Q>2",                  # Offset/Size Hash
      "Q>2",                  # Offset/Size Signature
      "Q>2",                  # Offset/Size Public Key
      "Q>2",                  # Offset/Size Public Key Metadata
      "Q>2",                  # Offset/Size Descriptors
      "Q>",                   # Rollback Index
      "L>",                   # Flags
      "x#{@@reserved0.to_s}", # Padding for 'reserved0' bytes
      "Z47",                  # Release String
      "x#{@@reserved.to_s}"   # Padding for 'reserved' bytes
    ]

    format_string = format_array.join("")

    unless raw.length == VBMETA_HEADER_SIZE then
      abort("Could not read VBMeta header: unexpected size. Header size: #{raw.length}, expected: #{VBMETA_HEADER_SIZE}.")
    end

    begin
      header_array = raw.unpack(format_string)
    rescue
      abort("Could not unpack VBMeta header.")
    end

    @magic                          = header_array[0]
    @required_libavb_version_major  = header_array[1]
    @required_libavb_version_minor  = header_array[2]
    @authentication_data_block_size = header_array[3]
    @auxiliary_data_block_size      = header_array[4]
    @algorithm_type                 = header_array[5]
    @hash_offset                    = header_array[6]
    @hash_size                      = header_array[7]
    @signature_offset               = header_array[8]
    @signature_size                 = header_array[9]
    @public_key_offset              = header_array[10]
    @public_key_size                = header_array[11]
    @public_key_metadata_offset     = header_array[12]
    @public_key_metadata_size       = header_array[13]
    @descriptors_offset             = header_array[14]
    @descriptors_size               = header_array[15]
    @rollback_index                 = header_array[16]
    @flags                          = header_array[17]
    @release_string                 = header_array[18]
  end

end

###############################################################################
