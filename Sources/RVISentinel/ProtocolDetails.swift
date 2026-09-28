import Foundation

struct ProtocolDetailDefinition: Equatable, Sendable {
    let protocolKind: ProtocolKind
    let category: String
    let label: String
}

func protocolDetailDefinition(field: TSharkField, observedProtocols: Set<ProtocolKind>) -> ProtocolDetailDefinition? {
    switch field {
    case .ethernetSource: detail(.ethernet, "Link layer", "Source MAC address")
    case .ethernetDestination: detail(.ethernet, "Link layer", "Destination MAC address")
    case .ethernetType: detail(.ethernet, "Link layer", "EtherType")
    case .vlanIdentifier: detail(.ethernet, "Link layer", "VLAN identifier")
    case .arpOpcode: detail(.arp, "Address resolution", "ARP operation")
    case .arpSourceIP: detail(.arp, "Address resolution", "Sender protocol address")
    case .arpDestinationIP: detail(.arp, "Address resolution", "Target protocol address")
    case .ipv4TTL: detail(.ipv4, "IP header", "Time to live")
    case .ipv4DSCP: detail(.ipv4, "IP header", "DSCP")
    case .ipv4ECN: detail(.ipv4, "IP header", "ECN")
    case .ipv4Protocol: detail(.ipv4, "IP header", "Encapsulated protocol")
    case .ipv4MoreFragments: detail(.ipv4, "Fragmentation", "More fragments flag")
    case .ipv4FragmentOffset: detail(.ipv4, "Fragmentation", "Fragment offset")
    case .ipv6HopLimit: detail(.ipv6, "IP header", "Hop limit")
    case .ipv6NextHeader: detail(.ipv6, "IP header", "Next header")
    case .icmpType: detail(.icmp, "Control message", "ICMP type")
    case .icmpCode: detail(.icmp, "Control message", "ICMP code")
    case .icmpv6Type: detail(.icmpv6, "Control message", "ICMPv6 type")
    case .icmpv6Code: detail(.icmpv6, "Control message", "ICMPv6 code")
    case .icmpv6NeighborSolicitationTarget: detail(.icmpv6, "Neighbor discovery", "Solicitation target")
    case .icmpv6NeighborAdvertisementTarget: detail(.icmpv6, "Neighbor discovery", "Advertisement target")
    case .icmpv6RouterLifetime: detail(.icmpv6, "Neighbor discovery", "Router lifetime")
    case .tcpFlags: detail(.tcp, "Transport", "TCP flags")
    case .tcpSequence: detail(.tcp, "Transport", "Relative sequence number")
    case .tcpAcknowledgment: detail(.tcp, "Transport", "Relative acknowledgment number")
    case .tcpPayloadLength: detail(.tcp, "Transport", "TCP payload length")
    case .tcpWindowSize: detail(.tcp, "Transport", "Advertised window")
    case .tcpReset: detail(.tcp, "Transport", "Reset flag")
    case .tcpStream: detail(.tcp, "Transport", "TShark stream index")
    case .tcpRTT: detail(.tcp, "Analysis", "Acknowledgment RTT")
    case .tcpRetransmission: detail(.tcp, "Analysis", "Retransmission marker")
    case .tcpDuplicateAck: detail(.tcp, "Analysis", "Duplicate ACK marker")
    case .tcpOutOfOrder: detail(.tcp, "Analysis", "Out-of-order marker")
    case .tcpZeroWindow: detail(.tcp, "Analysis", "Zero-window marker")
    case .udpLength: detail(.udp, "Transport", "UDP datagram length")
    case .udpStream: detail(.udp, "Transport", "TShark stream index")
    case .dnsQueryName: detail(nameProtocol(observedProtocols), "Name service", "Query name")
    case .dnsResponseName: detail(nameProtocol(observedProtocols), "Name service", "Response name")
    case .dnsA: detail(nameProtocol(observedProtocols), "Name service", "IPv4 answer")
    case .dnsAAAA: detail(nameProtocol(observedProtocols), "Name service", "IPv6 answer")
    case .dnsCNAME: detail(nameProtocol(observedProtocols), "Name service", "CNAME target")
    case .dnsPTR: detail(nameProtocol(observedProtocols), "Name service", "PTR target")
    case .dnsRecordType: detail(nameProtocol(observedProtocols), "Name service", "Record type")
    case .dnsResponseCode: detail(nameProtocol(observedProtocols), "Name service", "Response code")
    case .dnsTTL: detail(nameProtocol(observedProtocols), "Name service", "Answer TTL")
    case .dhcpMessageType: detail(.dhcp, "Network configuration", "DHCP message type")
    case .dhcpAssignedAddress: detail(.dhcp, "Network configuration", "Offered address")
    case .dhcpServerIdentifier: detail(.dhcp, "Network configuration", "Server identifier")
    case .dhcpv6MessageType: detail(.dhcpv6, "Network configuration", "DHCPv6 message type")
    case .dhcpv6ClientIdentifier: detail(.dhcpv6, "Network configuration", "Client DUID")
    case .tlsSNI: detail(.tls, "Handshake", "Server Name Indication")
    case .tlsVersion: detail(.tls, "Handshake", "TLS version")
    case .tlsCipherSuite: detail(.tls, "Handshake", "Cipher suite")
    case .tlsALPN: detail(.tls, "Handshake", "ALPN")
    case .certificateSubject: detail(.tls, "Certificate", "Subject value")
    case .certificateIssuer: detail(.tls, "Certificate", "Issuer value")
    case .certificateSerial: detail(.tls, "Certificate", "Serial number")
    case .certificateDNSName: detail(.tls, "Certificate", "DNS subject alternative name")
    case .httpHost: detail(.http, "Request", "Host")
    case .httpMethod: detail(.http, "Request", "Method")
    case .httpURI: detail(.http, "Request", "URI")
    case .httpStatus: detail(.http, "Response", "Status")
    case .httpContentType: detail(.http, "Response", "Content type")
    case .http2Authority: detail(.http2, "Headers", "Authority")
    case .http2Stream: detail(.http2, "Frame", "Stream identifier")
    case .http2Type: detail(.http2, "Frame", "Frame type")
    case .http2Method: detail(.http2, "Headers", "Method")
    case .http2Path: detail(.http2, "Headers", "Path")
    case .http2Status: detail(.http2, "Headers", "Status")
    case .quicVersion: detail(.quic, "Handshake", "QUIC version")
    case .quicDestinationConnectionID: detail(.quic, "Connection", "Destination connection ID")
    case .quicSourceConnectionID: detail(.quic, "Connection", "Source connection ID")
    case .quicPacketNumber: detail(.quic, "Packet", "Packet number")
    case .stunType: detail(.stun, "NAT traversal", "Message type")
    case .stunMappedAddress: detail(.stun, "NAT traversal", "Mapped IPv4 address")
    case .stunMappedIPv6Address: detail(.stun, "NAT traversal", "Mapped IPv6 address")
    case .stunUsername: detail(.stun, "NAT traversal", "Username fragment")
    case .turnChannelNumber: detail(.turn, "Relay", "Channel number")
    case .dtlsVersion: detail(.dtls, "Handshake", "DTLS version")
    case .dtlsCipherSuite: detail(.dtls, "Handshake", "Cipher suite")
    case .rtpSSRC: detail(.rtp, "Media", "Synchronization source")
    case .rtpSequence: detail(.rtp, "Media", "Sequence number")
    case .rtpTimestamp: detail(.rtp, "Media", "Timestamp")
    case .rtpPayloadType: detail(.rtp, "Media", "Payload type")
    case .rtcpType: detail(.rtcp, "Media control", "Packet type")
    case .rtcpSSRC: detail(.rtcp, "Media control", "Sender source")
    case .smbCommand: detail(.smb, "File sharing", "SMB command")
    case .smbFilename: detail(.smb, "File sharing", "Filename")
    case .sshProtocol: detail(.ssh, "Handshake", "SSH protocol")
    case .ntpReference: detail(.ntp, "Clock", "Reference identifier")
    case .ntpStratum: detail(.ntp, "Clock", "Stratum")
    case .espSPI: detail(.esp, "Encrypted tunnel", "Security Parameters Index")
    case .espSequence: detail(.esp, "Encrypted tunnel", "Sequence number")
    case .wireGuardMessageType: detail(.wireGuard, "Encrypted tunnel", "Message type")
    case .wireGuardReceiver: detail(.wireGuard, "Encrypted tunnel", "Receiver index")
    default: nil
    }
}

private func detail(_ protocolKind: ProtocolKind, _ category: String, _ label: String) -> ProtocolDetailDefinition {
    ProtocolDetailDefinition(protocolKind: protocolKind, category: category, label: label)
}

private func nameProtocol(_ protocols: Set<ProtocolKind>) -> ProtocolKind {
    if protocols.contains(.mdns) { return .mdns }
    if protocols.contains(.llmnr) { return .llmnr }
    if protocols.contains(.dnsSD) { return .dnsSD }
    return .dns
}

func protocolDetailEvidenceBoundary(protocolKind: ProtocolKind) -> String {
    switch protocolKind {
    case .tls, .quic, .dtls, .ssh, .esp, .wireGuard, .vpn:
        "Handshake or tunnel metadata is visible; encrypted application payloads remain protected."
    case .http, .http2, .http3, .smb:
        "Only fields decoded from visible or legitimately decrypted traffic are reported."
    default:
        "This value was decoded from the capture by the installed TShark field named in the report."
    }
}
