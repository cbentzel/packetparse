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

  var GLOBAL_HEADER_SIZE = 24;
  var PACKET_HEADER_SIZE = 16;

  // Returns an object representing the header, or undefined
  // if invalid.
  function parseGlobalHeader(buffer) {
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
    if (minorVersion != 4)
      return;
    
    var timeZone = dv.getInt32(8, littleEndian);
    var sigfigs = dv.getUint32(12, littleEndian);
    var snapLen = dv.getUint32(16, littleEndian);

    // TODO(cbentzel): Convert network to a symbolic string?
    var networkNum = dv.getUint32(20, littleEndian);

    return {
      littleEndian: littleEndian,
      timeZone: timeZone,
      sigfigs: sigfigs,
      snapLen: snapLen,
      networkNum: networkNum,
    };
  };

  function PcapParser(onGlobalHeader, onPacket, onError) {
    this.error_ = undefined;
    this.data_ = [];
    this.globalHeader_ = undefined;
    this.totalByteCount_ = 0;
    this.unreadByteCunt_ = 0;
    this.state_ = State.INIT;
    this.onGlobalHeader = onGlobalHeader;
    this.onPacket = onPacket;
    this.onError = onError;
  };

  PcapParser.prototype = {
    getData_: function (byte_count) {
      if (byte_count > this.unreadByteCount_) {
        return undefined;
      }
      if (byte_count < this.data_[0].byteLength) {
        this.unreadByteCount_ -= byte_count;
        var retSlice = this.data_[0].slice(0, byte_count);
        this.data_[0] = this.data_[0].slice(byte_count);
        return retSlice;
      } else {
        // Not quite sure how we can create a new ArrayBuffer which
        // includes contents of other buffers - other than maybe using
        // Uint8Views and copying? Sounds horrible.
        throw {name: 'NotImplemented'};
      }
    },

    addData: function (data) {
      if (!(data instanceof ArrayBuffer)) {
        throw {name: 'BadDataArg'};
      }

      // We always accumulate data, regardless of the
      // state.
      this.data_.push(data)
      this.totalByteCount_ += data.byteLength;
      this.unreadByteCount_ += data.byteLength;

      while (true) {
        var oldState = this.state_;
        switch (this.state_) {
        case State.INIT:
          var globalHeaderData = this.getData_(GLOBAL_HEADER_SIZE);
          if (globalHeaderData) {
            var globalHeader = parseGlobalHeader(globalHeaderData);
            if (!globalHeader) {
              this.state_ = State.ERROR_DONE;
              if (this.onError) {
                this.onError(this);
              }
            } else {
              this.state_ = State.PACKET_HEADER;
              this.globalHeader_ = globalHeader;
              if (this.onGlobalHeader) {
                this.onGlobalHeader(this, globalHeader);
              }
            }
          }
          break;
        case State.PACKET_HEADER:
          var packetHeaderData = this.getData_(PACKET_HEADER_SIZE);
          if (packetHeaderData) {
            var packetHeader = this.parsePacketHeader_(packetHeaderData);
            if (!packetHeader) {
              this.state_ = State.ERROR_DONE;
              if (this.onError) {
                this.onError(this);
              }
            } else {
              this.state_ = State.PACKET_DATA;
              // I probably need to preserve the size;
            }
          }
        };
        console.log('From ' + oldState + ' to ' + this.state_);
        if (oldState == this.state_)
          break;
      }
    },
  };
  
  return PcapParser;
})();
