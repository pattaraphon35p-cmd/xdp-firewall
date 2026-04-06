//go:build linux

package guard

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type Loader struct {
	iface       *net.Interface
	objs        bpfObjects
	xdpLink     link.Link
	eventReader *ringbuf.Reader
	statsEvery  time.Duration
	closeOnce   sync.Once
	closeErr    error
}

type bpfObjects struct {
	XDPHTTPGuard   *ebpf.Program `ebpf:"xdp_http_guard"`
	HTTPAllowIPs   *ebpf.Map     `ebpf:"http_allow_ips"`
	HTTPAllowCIDRs *ebpf.Map     `ebpf:"http_allow_cidrs"`
	HTTPRateMap    *ebpf.Map     `ebpf:"http_rate_map"`
	HTTPL7Map      *ebpf.Map     `ebpf:"http_l7_map"`
	StatsMap       *ebpf.Map     `ebpf:"stats_map"`
	Events         *ebpf.Map     `ebpf:"events"`
}

func (o *bpfObjects) Close() error {
	var errs []error
	if o.XDPHTTPGuard != nil {
		errs = append(errs, o.XDPHTTPGuard.Close())
	}
	if o.HTTPAllowIPs != nil {
		errs = append(errs, o.HTTPAllowIPs.Close())
	}
	if o.HTTPAllowCIDRs != nil {
		errs = append(errs, o.HTTPAllowCIDRs.Close())
	}
	if o.HTTPRateMap != nil {
		errs = append(errs, o.HTTPRateMap.Close())
	}
	if o.HTTPL7Map != nil {
		errs = append(errs, o.HTTPL7Map.Close())
	}
	if o.StatsMap != nil {
		errs = append(errs, o.StatsMap.Close())
	}
	if o.Events != nil {
		errs = append(errs, o.Events.Close())
	}
	return errors.Join(errs...)
}

func New(cfg Config) (*Loader, error) {
	if cfg.Interface == "" {
		return nil, errors.New("interface is required")
	}
	if cfg.ObjectPath == "" {
		return nil, errors.New("object path is required")
	}
	if cfg.StatsInterval <= 0 {
		cfg.StatsInterval = 2 * time.Second
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock rlimit: %w", err)
	}

	iface, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		return nil, fmt.Errorf("lookup interface %q: %w", cfg.Interface, err)
	}

	spec, err := ebpf.LoadCollectionSpec(cfg.ObjectPath)
	if err != nil {
		return nil, fmt.Errorf("load collection spec %q: %w", cfg.ObjectPath, err)
	}

	if err := applyHTTPVariables(spec, cfg.HTTPRate); err != nil {
		return nil, err
	}

	var objs bpfObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("load BPF objects: %w", err)
	}

	loader := &Loader{
		iface:      iface,
		objs:       objs,
		statsEvery: cfg.StatsInterval,
	}

	if err := loader.bootstrapAllowlist(cfg); err != nil {
		_ = loader.Close()
		return nil, err
	}

	xdpFlags, err := xdpAttachFlags(cfg.Mode)
	if err != nil {
		_ = loader.Close()
		return nil, err
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XDPHTTPGuard,
		Interface: iface.Index,
		Flags:     xdpFlags,
	})
	if err != nil {
		_ = loader.Close()
		return nil, fmt.Errorf("attach XDP: %w", err)
	}
	loader.xdpLink = xdpLink

	if cfg.LogDrops {
		reader, err := ringbuf.NewReader(objs.Events)
		if err != nil {
			_ = loader.Close()
			return nil, fmt.Errorf("open ringbuf reader: %w", err)
		}
		loader.eventReader = reader
	}

	return loader, nil
}

func (l *Loader) Close() error {
	l.closeOnce.Do(func() {
		var errs []error
		if l.eventReader != nil {
			errs = append(errs, l.eventReader.Close())
		}
		if l.xdpLink != nil {
			errs = append(errs, l.xdpLink.Close())
		}
		errs = append(errs, l.objs.Close())
		l.closeErr = errors.Join(errs...)
	})
	return l.closeErr
}

func (l *Loader) Stats() (Stats, error) {
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		return Stats{}, fmt.Errorf("detect possible CPUs: %w", err)
	}

	values := make([]bpfStats, cpus)
	key := uint32(0)
	if err := l.objs.StatsMap.Lookup(&key, &values); err != nil {
		return Stats{}, fmt.Errorf("lookup stats map: %w", err)
	}

	return aggregateStats(values), nil
}

func (l *Loader) StatsLoop(ctx context.Context, out io.Writer) error {
	ticker := time.NewTicker(l.statsEvery)
	defer ticker.Stop()

	var previous Stats
	first := true

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			current, err := l.Stats()
			if err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return err
			}

			if first {
				first = false
				previous = current
				fmt.Fprintf(out,
					"[%s] totals pass=%d drop=%d allow_ip=%d allow_cidr=%d denied=%d syn=%d ack=%d fin=%d pkt=%d l7=%d\n",
					time.Now().Format(time.RFC3339),
					current.PassedPackets,
					current.DroppedPackets,
					current.AllowedByIP,
					current.AllowedByCIDR,
					current.DeniedByAllowlist,
					current.DroppedBySynRate,
					current.DroppedByAckRate,
					current.DroppedByFinRate,
					current.DroppedByPacketRate,
					current.DroppedByL7Rate,
				)
				continue
			}

			delta := current.Delta(previous)
			previous = current

			fmt.Fprintf(out,
				"[%s] delta total=%d pass=%d drop=%d allow_ip=%d allow_cidr=%d denied=%d syn=%d ack=%d fin=%d pkt=%d l7=%d\n",
				time.Now().Format(time.RFC3339),
				delta.TotalPackets,
				delta.PassedPackets,
				delta.DroppedPackets,
				delta.AllowedByIP,
				delta.AllowedByCIDR,
				delta.DeniedByAllowlist,
				delta.DroppedBySynRate,
				delta.DroppedByAckRate,
				delta.DroppedByFinRate,
				delta.DroppedByPacketRate,
				delta.DroppedByL7Rate,
			)
		}
	}
}

func (l *Loader) LogDropEvents(ctx context.Context, out io.Writer) error {
	if l.eventReader == nil {
		return nil
	}

	go func() {
		<-ctx.Done()
		_ = l.eventReader.Close()
	}()

	for {
		record, err := l.eventReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read ringbuf event: %w", err)
		}

		var event bpfEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			return fmt.Errorf("decode drop event: %w", err)
		}

		fmt.Fprintf(out,
			"[%s] drop reason=%s src=%s:%d dst=%s:%d flags=0x%02x ts_ns=%d\n",
			time.Now().Format(time.RFC3339),
			reasonString(event.Reason),
			hostOrderUint32ToIP(event.SrcIP),
			event.SrcPort,
			hostOrderUint32ToIP(event.DstIP),
			event.DstPort,
			event.TCPFlags,
			event.TsNS,
		)
	}
}

func (l *Loader) bootstrapAllowlist(cfg Config) error {
	cidrs := make([]string, 0, len(cfg.AllowCIDRs)+len(DefaultCloudflareIPv4CIDRs))
	if cfg.EnableCloudflare {
		cidrs = append(cidrs, DefaultCloudflareIPv4CIDRs...)
	}
	cidrs = append(cidrs, cfg.AllowCIDRs...)

	for _, cidr := range DedupeStrings(cidrs) {
		if err := insertCIDR(l.objs.HTTPAllowCIDRs, cidr); err != nil {
			return err
		}
	}

	for _, ip := range DedupeStrings(cfg.AllowIPs) {
		if err := insertIPv4(l.objs.HTTPAllowIPs, ip); err != nil {
			return err
		}
	}

	return nil
}

func applyHTTPVariables(spec *ebpf.CollectionSpec, cfg HTTPRateConfig) error {
	if err := setUint32Variable(spec, "http_syn_limit_per_sec", cfg.SynLimitPerSec); err != nil {
		return err
	}
	if err := setUint32Variable(spec, "http_syn_block_threshold", cfg.SynBlockThreshold); err != nil {
		return err
	}
	if err := setUint32Variable(spec, "http_ack_limit_per_sec", cfg.AckLimitPerSec); err != nil {
		return err
	}
	if err := setUint32Variable(spec, "http_ack_block_threshold", cfg.AckBlockThreshold); err != nil {
		return err
	}
	if err := setUint32Variable(spec, "http_fin_limit_per_sec", cfg.FinLimitPerSec); err != nil {
		return err
	}
	if err := setUint32Variable(spec, "http_fin_block_threshold", cfg.FinBlockThreshold); err != nil {
		return err
	}
	if err := setUint32Variable(spec, "http_packet_limit_per_sec", cfg.PacketLimitPerSec); err != nil {
		return err
	}
	if err := setUint32Variable(spec, "http_packet_block_threshold", cfg.PacketBlockThreshold); err != nil {
		return err
	}
	if err := setUint32Variable(spec, "http_l7_data_limit_per_sec", cfg.L7DataLimitPerSec); err != nil {
		return err
	}
	if err := setUint32Variable(spec, "http_l7_data_block_threshold", cfg.L7DataBlockThreshold); err != nil {
		return err
	}
	return nil
}

func setUint32Variable(spec *ebpf.CollectionSpec, name string, value uint32) error {
	variable := spec.Variables[name]
	if variable == nil {
		return fmt.Errorf("missing BPF variable %q in collection spec", name)
	}
	if err := variable.Set(value); err != nil {
		return fmt.Errorf("set BPF variable %q: %w", name, err)
	}
	return nil
}

func insertIPv4(m *ebpf.Map, raw string) error {
	ip := net.ParseIP(strings.TrimSpace(raw)).To4()
	if ip == nil {
		return fmt.Errorf("invalid IPv4 address %q", raw)
	}

	key := binary.BigEndian.Uint32(ip)
	value := uint8(1)
	if err := m.Update(key, value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("insert allow IP %q: %w", raw, err)
	}
	return nil
}

func insertCIDR(m *ebpf.Map, raw string) error {
	_, network, err := net.ParseCIDR(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("invalid allow CIDR %q: %w", raw, err)
	}

	ip := network.IP.To4()
	if ip == nil {
		return fmt.Errorf("CIDR %q is not IPv4", raw)
	}

	ones, _ := network.Mask.Size()
	var addr [4]byte
	copy(addr[:], ip)
	key := lpmV4Key{
		PrefixLen: uint32(ones),
		Addr:      addr,
	}
	value := uint8(1)
	if err := m.Update(key, value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("insert allow CIDR %q: %w", raw, err)
	}
	return nil
}

func xdpAttachFlags(mode string) (link.XDPAttachFlags, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "auto":
		return 0, nil
	case "driver", "native":
		return link.XDPDriverMode, nil
	case "generic":
		return link.XDPGenericMode, nil
	case "offload":
		return link.XDPOffloadMode, nil
	default:
		return 0, fmt.Errorf("unsupported XDP mode %q", mode)
	}
}

func hostOrderUint32ToIP(value uint32) string {
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], value)
	return net.IP(raw[:]).String()
}
