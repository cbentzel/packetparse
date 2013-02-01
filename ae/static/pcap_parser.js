// Streaming parser for a pcap file.
//
// The file format is described at 
// http://wiki.wireshark.org/Development/LibpcapFileFormat

var PcapParser = (function() {
  'use strict';

  var State = {
    INIT: 0,
    FILE_HEADER: 1,
    PACKET_HEADER: 2,
    PACKET_BODY: 3,
    ERROR_DONE: 4,
  };

  var FILE_HEADER_SIZE = 24;

  function PcapParser(onFileHeader, onPacket, onError) {
    this.error_ = undefined;
    this.data_ = [];
    this.totalByteCount_ = 0;
    this.state_ = State.INIT;
    this.onFileHeader = onFileHeader;
    this.onPacket = onPacket;
    this.onError = onError;
  };

  PcapParser.prototype = {
    // Returns an object representing the header, or undefined
    // if invalid.
    parseGlobalHeader_: function (buffer) {
      if (!buffer instanceof ArrayBuffer || buffer.byteLength < 24) {
        throw {name: 'BadBufferArg'};
      }
      
      var dv = new DataView(buffer);

      // Determine if this is a little-endian or big-endian file
      // using the magic number.
      var magicNumber = dv.getUint32(0);
      if (magicNumber == 0xa1b2c3d4) {
        var littleEndian = false;
      } else if (magicNumber == 0xd4c3b2a1) {
        var littleEndian = true;
      } else {
        // Invalid magic number.
        return;
      }

      var majorVersion = dv.getUint16(4, littleEndian);
      if (majorVersion != 2)
        return;
      var minorVersion = dv.getUint16(6, littleEndian);
      if (minorVersion != 2)
        return;
      
      var timeZone = dv.getInt32(8, littleEndian);
      var sigfigs = dv.getUint32(12, littleEndian);
      var snapLen = dv.getUint32(16, littleEndian);
      var networkNum = dv.getUint32(20, littleEndian);

      // Probably check network
      return {
        littleEndian: littleEndian,
        timeZone: timeZone,
        sigfigs: sigfigs,
        snapLen: snapLen,
        networkNum: networkNum,
      };
    },

    addData: function (data) {
      if (!(data instanceof ArrayBuffer)) {
        throw {name: 'BadDataArg'};
      }

      // We always accumulate data, regardless of the
      // state.
      this.data_.push(data)
      this.totalByteCount_ += data.byteLength;

      // Make sure that data is an ArrayBuffer.
      switch (this.state_) {
      case State.INIT:
        console.log('In INIT state');
        if (this.totalByteCount_ >= FILE_HEADER_SIZE) {
          console.log('Enough data');
          // Parse the header. We need to copy out x bytes of data.
          // Perhaps have a helper for that?
        }
        break;
      };
    },
  };
  
  return PcapParser;
})();
