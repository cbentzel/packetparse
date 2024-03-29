// Streaming parser for a pcap file.
//
// The file format is described at 
// http://wiki.wireshark.org/Development/LibpcapFileFormat

var PcapParser = (function() {
  'use strict';

  var State = {
    FILE_HEADER: 0,
    PACKET_HEADER: 1,
    PACKET_BODY: 2,
    FILE_DONE: 3,
    ERROR_DONE: 4,
  };

  var GLOBAL_HEADER_SIZE = 24;
  var PACKET_HEADER_SIZE = 16;

  // Returns an object representing the header, or undefined
  // if invalid.
  function parseGlobalHeader(buffer) {
    if (!buffer instanceof ArrayBuffer || 
        buffer.byteLength < GLOBAL_HEADER_SIZE) {
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

  function parsePacketHeader(buffer, littleEndian) {
    if (!buffer instanceof ArrayBuffer || 
        buffer.byteLength < PACKET_HEADER_SIZE) {
      throw {name: 'BadBufferArg'};
    }
    
    var dv = new DataView(buffer);
    
    var secs = dv.getUint32(0, littleEndian);
    var usecs = dv.getUint32(4, littleEndian);
    var savedLen = dv.getUint32(8, littleEndian);
    var actualLen = dv.getUint32(12, littleEndian);
    
    return {
      secs: secs,
      usecs: usecs,
      savedLen: savedLen,
      actualLen: actualLen,
    };
  };

  function PcapParser(onGlobalHeader, onPacket, onDone, onError) {
    this.error_ = undefined;
    this.data_ = [];
    this.eof_ = false;
    this.totalByteCount_ = 0;
    this.unreadByteCount_ = 0;
    this.state_ = State.FILE_HEADER;
    this.packetHeader_ = undefined;
    this.littleEndian_ = true;
    this.onGlobalHeader = onGlobalHeader;
    this.onPacket = onPacket;
    this.onDone = onDone;
    this.onError = onError;
  };

  PcapParser.prototype = {
    atEof_: function () {
      return (this.eof_ && this.unreadByteCount_ == 0);
    },

    getData_: function (byte_count) {
      if (byte_count > this.unreadByteCount_) {
        if (this.eof_) {
          // File terminated abruptly.
          throw {name: 'UnexpectedEof'};
        } else {
          // Not enough data accumulated.
          return undefined;
        }
      }
      if (byte_count <= this.data_[0].byteLength) {
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

    runStateMachine_: function () {
      while (true) {
        var oldState = this.state_;
        switch (this.state_) {
        case State.FILE_HEADER:
          var globalHeaderData = this.getData_(GLOBAL_HEADER_SIZE);
          if (globalHeaderData) {
            var globalHeader = parseGlobalHeader(globalHeaderData);
            if (!globalHeader) {
              this.state_ = State.ERROR_DONE;
              if (this.onError) {
                this.onError(this);
              }
            } else {
              this.littleEndian_ = globalHeader.littleEndian;
              this.state_ = State.PACKET_HEADER;
              if (this.onGlobalHeader) {
                this.onGlobalHeader(this, globalHeader);
              }
            }
          }
          break;

        case State.PACKET_HEADER:
          // We may actually reach EOF here, need to handle that.
          if (this.atEof_()) {
            this.state_ = State.FILE_DONE;
            if (this.onDone) {
              this.onDone(this);
            }
          } else {
            var packetHeaderData = this.getData_(PACKET_HEADER_SIZE);
            if (packetHeaderData) {
              var packetHeader = parsePacketHeader(packetHeaderData, 
                                                   this.littleEndian_);
              if (!packetHeader) {
                this.state_ = State.ERROR_DONE;
                if (this.onError) {
                  this.onError(this);
                }
              } else {
                this.packetHeader_ = packetHeader;
                this.state_ = State.PACKET_BODY;
              }
            }
          }
          break;

        case State.PACKET_BODY:
          var packetData = this.getData_(this.packetHeader_.savedLen);
          if (packetData) {
            var packetHeader = this.packetHeader_;
            this.packetHeader_ = undefined;
            if (this.onPacket) {
              this.onPacket(packetHeader, packetData); 
            }
            this.state_ = State.PACKET_HEADER;
          }
          break;
        };
        console.log('From ' + oldState + ' to ' + this.state_);
        if (oldState == this.state_)
          break;
      }
    },

    // Add new data to be parsed, and runs state machine.
    addData: function (data) {
      if (!(data instanceof ArrayBuffer)) {
        throw {name: 'BadDataArg'};
      }
      if (this.eof_) {
        throw {name: 'BadState'};
      }

      this.data_.push(data)
      this.totalByteCount_ += data.byteLength;
      this.unreadByteCount_ += data.byteLength;

      this.runStateMachine_();
    },

    // Indicates that no more data exists (EOF, or XHR close, etc).
    finishData: function () {
      if (this.eof_) {
        throw {name: 'BadState'};
      }
      this.eof_ = true;
      this.runStateMachine_();
    },
  };
  
  return PcapParser;
})();
