import Foundation
import XCTest

@testable import FortixCore

/// ProtocolTests verifies interoperability and strict bounded frame parsing without a helper.
final class ProtocolTests: XCTestCase {
  /// TestSharedRequests verifies every fixture encodes equivalent inline fields after validation.
  func testSharedRequests() throws {
    for frame in try Fixtures.lines("protocol.requests.ndjson") {
      let request = try JSONDecoder().decode(HelperRequest.self, from: frame)
      let encoded = try HelperProtocol.encode(request)
      XCTAssertEqual(try StrictJSON.decode(encoded), try StrictJSON.decode(frame), request.id)
    }
  }

  /// TestSharedResultsAndEvents verifies all operation results, error codes, and notification shapes.
  func testSharedResultsAndEvents() throws {
    for frame in try Fixtures.lines("protocol.results.ndjson")
      + Fixtures.lines("protocol.events.ndjson")
    {
      _ = try HelperProtocol.decode(frame)
    }
  }

  /// TestMalformedFrames rejects ambiguity, incorrect case, null, invalid UTF-8, and missing fields.
  func testMalformedFrames() throws {
    let invalid = [
      "{\"type\":\"result\",\"id\":\"x\",\"ok\":true,\"ok\":false}\n",
      "{\"type\":\"result\",\"id\":\"x\",\"ok\":true,\"data\":{\"x\":1,\"\\u0078\":2}}\n",
      "{\"type\":\"result\",\"id\":\"x\",\"OK\":true}\n",
      "{\"type\":\"result\",\"id\":\"x\",\"ok\":true,\"data\":null}\n",
      "{\"type\":\"result\",\"id\":\"x\",\"ok\":false}\n",
      "{\"type\":\"result\",\"id\":\"x\",\"ok\":true,\"extra\":1}\n",
      "{\"type\":\"result\",\"id\":\"x\",\"ok\":true}\n{}\n",
      "{\"type\":\"state\",\"profile\":\"work\",\"attempt\":1}\n",
      "{\"type\":\"log\",\"profile\":\"work\",\"attempt\":1,\"line\":\"x\",\"state\":\"connected\"}\n",
      "{\"type\":\"result\",\"id\":\"x\",\"ok\":true}",
      "[1,2]\n",
    ]
    for text in invalid { XCTAssertThrowsError(try HelperProtocol.decode(Data(text.utf8))) }
    XCTAssertThrowsError(try HelperProtocol.decode(Data([0xff, 10])))
    let nested =
      "{\"type\":\"result\",\"id\":\"x\",\"ok\":true,\"data\":" + String(repeating: "[", count: 40)
      + "1" + String(repeating: "]", count: 40) + "}\n"
    XCTAssertThrowsError(try HelperProtocol.decode(Data(nested.utf8)))
  }

  /// TestFrameBounds includes the newline in the 64 KiB limit and rejects incomplete EOF.
  func testFrameBounds() throws {
    var framer = NDJSONFramer()
    XCTAssertEqual(try framer.append(Data("{\"type\":".utf8)).count, 0)
    XCTAssertTrue(framer.hasPartialRecord)
    let frames = try framer.append(Data("\"result\",\"id\":\"x\",\"ok\":true}\n{}\n".utf8))
    XCTAssertEqual(frames.count, 2)
    XCTAssertFalse(framer.hasPartialRecord)
    try framer.finish()
    var maximum = NDJSONFramer()
    XCTAssertEqual(
      try maximum.append(Data(repeating: 32, count: HelperProtocol.maxLine - 1)).count, 0)
    XCTAssertEqual(try maximum.append(Data([10])).first?.count, HelperProtocol.maxLine)
    var tooLarge = NDJSONFramer()
    XCTAssertThrowsError(try tooLarge.append(Data(repeating: 32, count: HelperProtocol.maxLine)))
    var truncated = NDJSONFramer()
    _ = try truncated.append(Data("{".utf8))
    XCTAssertThrowsError(try truncated.finish())
  }

  /// TestRequestValidation rejects operation mixing and escaped Assuan responses exceeding 997 bytes.
  func testRequestValidation() throws {
    XCTAssertThrowsError(
      try HelperProtocol.encode(
        HelperRequest(op: "up", id: "x", profile: "work", secret: "synthetic")))
    XCTAssertThrowsError(
      try HelperProtocol.encode(HelperRequest(op: "down", id: "x", profile: "work", all: true)))
    XCTAssertThrowsError(
      try HelperProtocol.encode(HelperRequest(op: "logs", id: "x", profile: "work", lines: 501)))
    XCTAssertThrowsError(
      try HelperProtocol.encode(
        HelperRequest(op: "profile.put", id: "x", profileJSON: .string("{}"))))
    XCTAssertThrowsError(
      try HelperProtocol.encode(
        HelperRequest(
          op: "answer", id: "x", challengeID: "c",
          secret: String(repeating: "%", count: 333))))
    _ = try HelperProtocol.encode(
      HelperRequest(op: "answer", id: "x", challengeID: "c", secret: ""))
    _ = try HelperProtocol.encode(
      HelperRequest(
        op: "answer", id: "x", challengeID: "c", secret: String(repeating: "a", count: 997)))
  }

  /// TestLargeAttempt retains full UInt64 generation values instead of losing precision as a double.
  func testLargeAttempt() throws {
    let frame = Data(
      "{\"type\":\"log\",\"profile\":\"work\",\"attempt\":18446744073709551615,\"line\":\"x\"}\n"
        .utf8)
    guard case .event(let event) = try HelperProtocol.decode(frame) else {
      return XCTFail("Expected event")
    }
    XCTAssertEqual(event.attempt, UInt64.max)
  }
}
