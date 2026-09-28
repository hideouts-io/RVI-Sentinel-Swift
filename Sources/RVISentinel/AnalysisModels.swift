import Foundation

enum ProtocolKind: String, CaseIterable, Codable, Identifiable, Sendable {
    case ethernet = "Ethernet"
    case arp = "ARP"
    case ipv4 = "IPv4"
    case ipv6 = "IPv6"
    case icmp = "ICMP"
    case icmpv6 = "ICMPv6"
    case tcp = "TCP"
    case udp = "UDP"
    case dns = "DNS"
    case mdns = "mDNS"
    case dnsSD = "DNS-SD"
    case dhcp = "DHCP"
    case dhcpv6 = "DHCPv6"
    case tls = "TLS"
    case http = "HTTP"
    case http2 = "HTTP/2"
    case http3 = "HTTP/3"
    case quic = "QUIC"
    case stun = "STUN"
    case turn = "TURN"
    case webRTC = "WebRTC"
    case dtls = "DTLS"
    case rtp = "RTP"
    case rtcp = "RTCP"
    case ssh = "SSH"
    case smb = "SMB"
    case ntp = "NTP"
    case ssdp = "SSDP"
    case upnp = "UPnP"
    case llmnr = "LLMNR"
    case esp = "ESP / IPsec"
    case wireGuard = "WireGuard heuristic"
    case vpn = "VPN metadata"
    case dot = "DNS over TLS metadata"
    case doh = "DNS over HTTPS metadata"
    case websocket = "WebSocket"
    case sctp = "SCTP"
    case gre = "GRE"
    case ipInIP = "IP-in-IP"
    case mqtt = "MQTT"
    case coap = "CoAP"
    case ocsp = "OCSP"
    case kerberos = "Kerberos"
    case ldap = "LDAP"
    case ftp = "FTP"
    case tftp = "TFTP"
    case sip = "SIP"
    case applePush = "Apple Push metadata"
    case unknown = "Unknown or unsupported"

    var id: String { rawValue }
}

enum TSharkField: String, CaseIterable, Codable, Sendable {
    case frameNumber = "frame.number"
    case frameTimeEpoch = "frame.time_epoch"
    case frameLength = "frame.len"
    case frameProtocols = "frame.protocols"
    case frameInterfaceName = "frame.interface_name"
    case ethernetSource = "eth.src"
    case ethernetDestination = "eth.dst"
    case ethernetType = "eth.type"
    case vlanIdentifier = "vlan.id"
    case arpOpcode = "arp.opcode"
    case arpSourceIP = "arp.src.proto_ipv4"
    case arpDestinationIP = "arp.dst.proto_ipv4"
    case ipv4Source = "ip.src"
    case ipv4Destination = "ip.dst"
    case ipv4TTL = "ip.ttl"
    case ipv4DSCP = "ip.dsfield.dscp"
    case ipv4ECN = "ip.dsfield.ecn"
    case ipv4Protocol = "ip.proto"
    case ipv4MoreFragments = "ip.flags.mf"
    case ipv4FragmentOffset = "ip.frag_offset"
    case ipv6Source = "ipv6.src"
    case ipv6Destination = "ipv6.dst"
    case ipv6HopLimit = "ipv6.hlim"
    case ipv6NextHeader = "ipv6.nxt"
    case tcpSourcePort = "tcp.srcport"
    case tcpDestinationPort = "tcp.dstport"
    case tcpFlags = "tcp.flags"
    case tcpStream = "tcp.stream"
    case tcpRTT = "tcp.analysis.ack_rtt"
    case tcpRetransmission = "tcp.analysis.retransmission"
    case tcpDuplicateAck = "tcp.analysis.duplicate_ack"
    case tcpOutOfOrder = "tcp.analysis.out_of_order"
    case tcpZeroWindow = "tcp.analysis.zero_window"
    case udpSourcePort = "udp.srcport"
    case udpDestinationPort = "udp.dstport"
    case udpStream = "udp.stream"
    case dnsQueryName = "dns.qry.name"
    case dnsResponseName = "dns.resp.name"
    case dnsA = "dns.a"
    case dnsAAAA = "dns.aaaa"
    case dnsCNAME = "dns.cname"
    case dnsPTR = "dns.ptr.domain_name"
    case dnsRecordType = "dns.qry.type"
    case dnsResponseCode = "dns.flags.rcode"
    case dnsTTL = "dns.resp.ttl"
    case tlsSNI = "tls.handshake.extensions_server_name"
    case tlsVersion = "tls.handshake.version"
    case tlsCipherSuite = "tls.handshake.ciphersuite"
    case tlsALPN = "tls.handshake.extensions_alpn_str"
    case certificateSubject = "x509sat.uTF8String"
    case certificateIssuer = "x509if.rdnSequence"
    case certificateSerial = "x509af.serialNumber"
    case httpHost = "http.host"
    case httpMethod = "http.request.method"
    case httpURI = "http.request.uri"
    case httpStatus = "http.response.code"
    case httpContentType = "http.content_type"
    case http2Authority = "http2.headers.authority"
    case http2Stream = "http2.streamid"
    case http2Type = "http2.type"
    case quicVersion = "quic.version"
    case quicDestinationConnectionID = "quic.dcid"
    case quicSourceConnectionID = "quic.scid"
    case stunType = "stun.type"
    case stunMappedAddress = "stun.att.ipv4"
    case dtlsVersion = "dtls.handshake.version"
    case rtpSSRC = "rtp.ssrc"
    case rtpSequence = "rtp.seq"
    case rtcpType = "rtcp.packet_type"
    case smbCommand = "smb2.cmd"
    case sshProtocol = "ssh.protocol"
    case ntpReference = "ntp.refid"
    case espSPI = "esp.spi"

    static let required: Set<TSharkField> = [.frameNumber, .frameTimeEpoch, .frameLength, .frameProtocols]
}

struct DecodedPacket: Sendable {
    let values: [TSharkField: [String]]

    func first(_ field: TSharkField) -> String? {
        values[field]?.first
    }

    func all(_ field: TSharkField) -> [String] {
        values[field] ?? []
    }
}

struct EndpointObservation: Identifiable, Codable, Equatable, Sendable {
    let address: String
    let version: String
    let classification: String
    let firstSeen: Date
    let lastSeen: Date
    let sourcePackets: Int
    let destinationPackets: Int
    let sourceBytes: Int64
    let destinationBytes: Int64
    let protocols: [ProtocolKind]
    let ports: [String]
    let processAttribution: ProcessAttribution

    var id: String { address }
}

struct ProtocolObservation: Identifiable, Codable, Equatable, Sendable {
    let protocolKind: ProtocolKind
    let packetCount: Int
    let byteCount: Int64
    let identification: String

    var id: ProtocolKind { protocolKind }
}

struct PortObservation: Identifiable, Codable, Equatable, Sendable {
    let transport: String
    let port: Int
    let packetCount: Int
    let standardService: String
    let explanation: String
    let evidenceBoundary: String

    var id: String { "\(transport)|\(port)" }
}

struct AnalysisCoverage: Codable, Equatable, Sendable {
    let tsharkVersion: String
    let supportedFields: [TSharkField]
    let unsupportedFields: [TSharkField]
    let activeResolutionEnabled: Bool
    let limitations: [String]
}

struct AnalysisSummary: Codable, Equatable, Sendable {
    let captureURL: URL
    let captureSHA256: String
    let packetCount: Int
    let byteCount: Int64
    let firstPacket: Date?
    let lastPacket: Date?
    let interfaces: [String]
}

struct NativeAnalysisResult: Codable, Equatable, Sendable {
    let summary: AnalysisSummary
    let endpoints: [EndpointObservation]
    let hostnames: [HostnameEvidence]
    let protocols: [ProtocolObservation]
    let ports: [PortObservation]
    let coverage: AnalysisCoverage
}

struct AnalysisProgress: Equatable, Sendable {
    let decodedPackets: Int
    let status: String
}

enum NativeAnalysisError: LocalizedError {
    case invalidCapture(String)
    case tsharkUnavailable
    case fieldCatalogFailed(String)
    case requiredFieldsMissing([String])
    case decodingFailed(String)
    case malformedRow(String)

    var errorDescription: String? {
        switch self {
        case let .invalidCapture(detail): "The selected capture is invalid: \(detail)"
        case .tsharkUnavailable: "Wireshark tshark was not found in a supported location."
        case let .fieldCatalogFailed(detail): "Could not read the installed TShark field catalog: \(detail)"
        case let .requiredFieldsMissing(fields): "The installed TShark is missing required fields: \(fields.joined(separator: ", "))."
        case let .decodingFailed(detail): "TShark decoding failed: \(detail)"
        case let .malformedRow(detail): "TShark returned a malformed row: \(detail)"
        }
    }
}
