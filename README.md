# Vbmeta Extract Pubkey

## Dependencies

For this script to work you must have Ruby installed. Additionally, the Ruby
OpenSSL library must also be available.

## Notes

### Use this tool at your own risk!

I take absolutely no responsibility for any outcomes you incur from use of this
tool.

### Why not just use avbtool?

This was ported from `avbtool` which is a part of the Android Open Source
Project (AOSP). Instead of modifying it slightly to write out the public keys
to disk, I decided to create this Ruby version from scratch. `avbtool` seemed
to be dependant on Python 2 with some deprecated dependancies that can no
longer be installed on some distributions.

## Usage

The script takes two parameters, first is the path to the VBMeta image you
would like to extract the public key from. The second is the target path/name
of the extracted public keys.

```
ruby ./run.rb ./vbmeta.img output
```

This will extract the public keys from `./vbmeta.img` and create two files:
* `output.pem` containing the public key in PEM foramt
* `output.img` containing the public key in a format ready to directly flash to
the `avb_custom_key` partition with fastboot
