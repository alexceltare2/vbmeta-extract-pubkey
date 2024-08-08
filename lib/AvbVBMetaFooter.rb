###############################################################################

VBMETA_FOOTER_SIZE = 64

###############################################################################

class AvbVBMetaFooter

  @@reserved = 28

  attr_reader :magic
  attr_reader :version_major
  attr_reader :version_minor
  attr_reader :original_image_size
  attr_reader :vbmeta_offset
  attr_reader :vbmeta_size

  def initialize(raw)
    format_array = [
      "a4L>2",              # Magic, 2x Version
      "Q>",                 # Original Image Size
      "Q>",                 # Offset of VBMeta blob
      "Q>",                 # Size of VBMeta blob
      "#{@@reserved.to_s}x" # Padding for 'reserved' bytes
    ]

    format_string = format_array.join("")

    unless raw.length == VBMETA_FOOTER_SIZE then
      abort("Could not read VBMeta footer: unexpected size. Footer size: #{raw.length}, expected: #{VBMETA_FOOTER_SIZE}.")
    end

    begin
      footer_array = raw.unpack(format_string)
    rescue
      abort("Could not unpack VBMeta footer.")
    end

    @magic               = footer_array[0]
    @version_major       = footer_array[1]
    @version_minor       = footer_array[2]
    @original_image_size = footer_array[3]
    @vbmeta_offset       = footer_array[4]
    @vbmeta_size         = footer_array[5]
  end

  def size
    return @@size
  end
end

###############################################################################
