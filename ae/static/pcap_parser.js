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
      
      var magicNumberView = new Uint32Array(buffer, 0, 1);
      var versionView = new Uint16Array(buffer, 4, 2);
      var timezoneView = new Int32Array(buffer, 8, 1);
      var extraView = new Uint32Array(buffer, 12, 3);
      
      var magicNumber = magicNumberView[0];
      if (magicNumber != 0xa1b2c3d4)
        return;
      
      var majorVersion = versionView[0];
      if (majorVersion != 2)
        return;
      
      var minorVersion = versionView[1];
      if (minorVersion != 4)
        return;
      
      // Probably check network
      return {
        zone: timezoneView[0],
        sigfigs: extraView[0],
        snaplen: extraView[1],
        network: extraView[2],
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
