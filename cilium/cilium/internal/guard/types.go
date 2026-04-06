package guard

import (
	"fmt"
	"time"
)

type HTTPRateConfig struct {
	SynLimitPerSec      uint32
	SynBlockThreshold   uint32
	AckLimitPerSec      uint32
	AckBlockThreshold   uint32
	FinLimitPerSec      uint32
	FinBlockThreshold   uint32
	PacketLimitPerSec   uint32
	PacketBlockThreshold uint32
	L7DataLimitPerSec   uint32
	L7DataBlockThreshold uint32
}

func DefaultHTTPRateConfig() HTTPRateConfig {
	return HTTPRateConfig{
		SynLimitPerSec:       12,
		SynBlockThreshold:    36,
		AckLimitPerSec:       140,
		AckBlockThreshold:    320,
		FinLimitPerSec:       28,
		FinBlockThreshold:    84,
		PacketLimitPerSec:    220,
		PacketBlockThreshold: 520,
		L7DataLimitPerSec:    160,
		L7DataBlockThreshold: 320,
	}
}

type Config struct {
	Interface        string
	ObjectPath       string
	Mode             string
	LogDrops         bool
	StatsInterval    time.Duration
	EnableCloudflare bool
	AllowIPs         []string
	AllowCIDRs       []string
	HTTPRate         HTTPRateConfig
}

type Stats struct {
	TotalPackets         uint64
	PassedPackets        uint64
	DroppedPackets       uint64
	AllowedByIP          uint64
	AllowedByCIDR        uint64
	DeniedByAllowlist    uint64
	DroppedBySynRate     uint64
	DroppedByAckRate     uint64
	DroppedByFinRate     uint64
	DroppedByPacketRate  uint64
	DroppedByL7Rate      uint64
}

func (s Stats) Delta(prev Stats) Stats {
	return Stats{
		TotalPackets:        s.TotalPackets - prev.TotalPackets,
		PassedPackets:       s.PassedPackets - prev.PassedPackets,
		DroppedPackets:      s.DroppedPackets - prev.DroppedPackets,
		AllowedByIP:         s.AllowedByIP - prev.AllowedByIP,
		AllowedByCIDR:       s.AllowedByCIDR - prev.AllowedByCIDR,
		DeniedByAllowlist:   s.DeniedByAllowlist - prev.DeniedByAllowlist,
		DroppedBySynRate:    s.DroppedBySynRate - prev.DroppedBySynRate,
		DroppedByAckRate:    s.DroppedByAckRate - prev.DroppedByAckRate,
		DroppedByFinRate:    s.DroppedByFinRate - prev.DroppedByFinRate,
		DroppedByPacketRate: s.DroppedByPacketRate - prev.DroppedByPacketRate,
		DroppedByL7Rate:     s.DroppedByL7Rate - prev.DroppedByL7Rate,
	}
}

type bpfStats struct {
	TotalPackets        uint64
	PassedPackets       uint64
	DroppedPackets      uint64
	AllowedByIP         uint64
	AllowedByCIDR       uint64
	DeniedByAllowlist   uint64
	DroppedBySynRate    uint64
	DroppedByAckRate    uint64
	DroppedByFinRate    uint64
	DroppedByPacketRate uint64
	DroppedByL7Rate     uint64
}

type bpfEvent struct {
	TsNS     uint64
	SrcIP    uint32
	DstIP    uint32
	SrcPort  uint16
	DstPort  uint16
	TCPFlags uint8
	Reason   uint8
	Pad      uint16
}

type lpmV4Key struct {
	PrefixLen uint32
	Addr      [4]byte
}

const (
	dropReasonSourceNotAllowed uint8 = 1
	dropReasonHTTPSynRate      uint8 = 2
	dropReasonHTTPAckRate      uint8 = 3
	dropReasonHTTPFinRate      uint8 = 4
	dropReasonHTTPPacketRate   uint8 = 5
	dropReasonHTTPL7Rate       uint8 = 6
)

func aggregateStats(values []bpfStats) Stats {
	var out Stats
	for _, value := range values {
		out.TotalPackets += value.TotalPackets
		out.PassedPackets += value.PassedPackets
		out.DroppedPackets += value.DroppedPackets
		out.AllowedByIP += value.AllowedByIP
		out.AllowedByCIDR += value.AllowedByCIDR
		out.DeniedByAllowlist += value.DeniedByAllowlist
		out.DroppedBySynRate += value.DroppedBySynRate
		out.DroppedByAckRate += value.DroppedByAckRate
		out.DroppedByFinRate += value.DroppedByFinRate
		out.DroppedByPacketRate += value.DroppedByPacketRate
		out.DroppedByL7Rate += value.DroppedByL7Rate
	}
	return out
}

func reasonString(reason uint8) string {
	switch reason {
	case dropReasonSourceNotAllowed:
		return "source_not_allowed"
	case dropReasonHTTPSynRate:
		return "http_syn_rate"
	case dropReasonHTTPAckRate:
		return "http_ack_rate"
	case dropReasonHTTPFinRate:
		return "http_fin_rate"
	case dropReasonHTTPPacketRate:
		return "http_packet_rate"
	case dropReasonHTTPL7Rate:
		return "http_l7_rate"
	default:
		return fmt.Sprintf("unknown(%d)", reason)
	}
}
