import Foundation

/// Format-generated loopback traffic; it is never sent and establishes no device behavior.
func generatedClassicPacketCapture(packetCount: Int) throws -> Data {
    guard (1...200_000).contains(packetCount) else { throw PacketFixtureError.invalidCount }
    let packet = generatedLoopbackUDPPacket()
    var data = Data([0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00])
    data.append(packetLittleEndian(UInt32(0)))
    data.append(packetLittleEndian(UInt32(0)))
    data.append(packetLittleEndian(UInt32(65_535)))
    data.append(packetLittleEndian(UInt32(101)))
    for frame in 0..<packetCount {
        data.append(packetLittleEndian(UInt32(1_791_428_448)))
        data.append(packetLittleEndian(UInt32(frame)))
        data.append(packetLittleEndian(UInt32(packet.count)))
        data.append(packetLittleEndian(UInt32(packet.count)))
        data.append(packet)
    }
    return data
}

/// Apple process-block options and nanosecond PCAPNG timestamps are format-generated.
/// The recorded maild label is synthetic metadata, not a captured iPhone process.
func generatedAppleMetadataPacketCapture() throws -> Data {
    var section = packetLittleEndian(UInt32(0x1a2b3c4d))
    section.append(packetLittleEndian(UInt16(1)))
    section.append(packetLittleEndian(UInt16(0)))
    section.append(packetLittleEndian(UInt64.max))
    var interface = packetLittleEndian(UInt16(101))
    interface.append(packetLittleEndian(UInt16(0)))
    interface.append(packetLittleEndian(UInt32(65_535)))
    interface.append(try packetPCAPNGOption(code: 2, value: Data("fixture0".utf8)))
    interface.append(try packetPCAPNGOption(code: 9, value: Data([9])))
    interface.append(try packetPCAPNGOption(code: 0, value: Data()))
    var process = packetLittleEndian(UInt32(343))
    process.append(try packetPCAPNGOption(code: 2, value: Data("maild".utf8)))
    process.append(try packetPCAPNGOption(code: 0, value: Data()))
    var result = try packetPCAPNGBlock(type: 0x0a0d0d0a, body: section)
    result.append(try packetPCAPNGBlock(type: 1, body: interface))
    result.append(try packetPCAPNGBlock(type: 0x80000001, body: process))
    let packet = generatedLoopbackUDPPacket()
    for epoch in [UInt64(1_791_428_448_590_385_001), UInt64(1_791_428_448_590_385_002)] {
        var body = packetLittleEndian(UInt32(0))
        body.append(packetLittleEndian(UInt32(epoch >> 32)))
        body.append(packetLittleEndian(UInt32(epoch & 0xffffffff)))
        body.append(packetLittleEndian(UInt32(packet.count)))
        body.append(packetLittleEndian(UInt32(packet.count)))
        body.append(packet)
        body.append(try packetPCAPNGOption(code: 0x8001, value: packetLittleEndian(UInt32(0))))
        body.append(try packetPCAPNGOption(code: 2, value: packetLittleEndian(UInt32(2))))
        body.append(try packetPCAPNGOption(code: 0, value: Data()))
        result.append(try packetPCAPNGBlock(type: 6, body: body))
    }
    return result
}

func generatedLoopbackUDPPacket() -> Data {
    Data([
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00,
        0x40, 0x11, 0x00, 0x00, 0x7f, 0x00, 0x00, 0x01,
        0x7f, 0x00, 0x00, 0x01, 0xd1, 0x1f, 0xd1, 0x20,
        0x00, 0x08, 0x00, 0x00
    ])
}

private func packetLittleEndian<Value: FixedWidthInteger>(_ value: Value) -> Data {
    var encoded = value.littleEndian
    return withUnsafeBytes(of: &encoded) { Data($0) }
}

private func packetPCAPNGOption(code: UInt16, value: Data) throws -> Data {
    guard let length = UInt16(exactly: value.count) else { throw PacketFixtureError.invalidBlock }
    var data = packetLittleEndian(code)
    data.append(packetLittleEndian(length))
    data.append(value)
    data.append(Data(repeating: 0, count: (4 - value.count % 4) % 4))
    return data
}

private func packetPCAPNGBlock(type: UInt32, body: Data) throws -> Data {
    guard body.count.isMultiple(of: 4), let length = UInt32(exactly: body.count + 12) else { throw PacketFixtureError.invalidBlock }
    var data = packetLittleEndian(type)
    data.append(packetLittleEndian(length))
    data.append(body)
    data.append(packetLittleEndian(length))
    return data
}

enum PacketFixtureError: Error { case invalidCount, invalidBlock, analysisTimedOut, resourceUsageFailed(code: Int32) }
