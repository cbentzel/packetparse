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
