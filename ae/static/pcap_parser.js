// Streaming parser for a pcap file.
//
// The file format is described at 
// http://wiki.wireshark.org/Development/LibpcapFileFormat

function PcapParser() {
    this.error = undefined;
    this.data = [];

    var State = {
        INIT: 0,
        FILE_HEADER: 1,
        PACKET_HEADER: 2,
        PACKET_BODY: 3,
        ERROR_DONE: 4,
    };

    this.state = State.INIT;

    this.addData = function (data) {
    };

    // Users can override onError, onFileHeader
    // and onEntry
    this.onError = function (error) {
    }

    this.onFileHeader = function (headerDetails) {
    }

    this.onPacket = function (packetHeader, packetBody) {
    }
};
