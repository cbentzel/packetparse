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
        this._error = undefined;
        this._data = [];
        this._state = State.INIT;
        this.onFileHeader = onFileHeader;
        this.onPacket = onPacket;
        this.onError = onError;
    };

    PcapParser.prototype = {
        addData: function (data) {
            switch (this._state) {
            case State.INIT:
                // Accumulate data.
                // If we have >= 
                console.log('In INIT state');
                break;
            };
        }
    };
    
    return PcapParser;
})();
