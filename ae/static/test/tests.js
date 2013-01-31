// Simplest runner.
test( "hello test", function() {
  ok( 1 == "1", "Passed!" );
});

// Bad types of data for PcapParser
test("Bad addData calls", function() {
  var pcapParser = new PcapParser();
  throws(function() {pcapParser.addData(2)});
  throws(function() {pcapParser.addData('hi')});
  throws(function() {pcapParser.addData(function() {})});
});

// Tests what happens when this goes to a new state.
test("Pre-init addData calls", function() {
  var pcapParser = new PcapParser();
  equal(pcapParser.totalByteCount_, 0);
  equal(pcapParser.state_, 0);
  var arrayBuffer = new ArrayBuffer(10);
  pcapParser.addData(arrayBuffer);
  equal(pcapParser.totalByteCount_, 10);
  equal(pcapParser.state_, 0);
  var arrayBuffer2 = new ArrayBuffer(10);
  pcapParser.addData(arrayBuffer);
  equal(pcapParser.totalByteCount_, 20);
  equal(pcapParser.state_, 0);
});

// Tests what happens when this goes to a new state.
test("Post-init addData calls", function() {
  var pcapParser = new PcapParser();
  equal(pcapParser.totalByteCount_, 0);
  equal(pcapParser.state_, 0);
  var arrayBuffer = new ArrayBuffer(20);
  pcapParser.addData(arrayBuffer);
  equal(pcapParser.totalByteCount_, 20);
  equal(pcapParser.state_, 0);
  var arrayBuffer2 = new ArrayBuffer(20);
  pcapParser.addData(arrayBuffer);
  equal(pcapParser.totalByteCount_, 40);
  equal(pcapParser.state_, 1);
});
