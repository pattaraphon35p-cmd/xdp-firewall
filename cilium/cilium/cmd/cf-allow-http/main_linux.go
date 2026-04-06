//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"cf-allow-http/cilium/internal/guard"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	cfg, err := parseConfig()
	if err != nil {
		log.Fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	loader, err := guard.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer loader.Close()

	log.Printf("attached xdp_http_guard to %s mode=%s", cfg.Interface, normalizeMode(cfg.Mode))
	log.Printf("cloudflare=%t allow_ips=%d allow_cidrs=%d obj=%s",
		cfg.EnableCloudflare,
		len(cfg.AllowIPs),
		len(cfg.AllowCIDRs),
		cfg.ObjectPath,
	)
	log.Printf("http limits syn=%d/%d ack=%d/%d fin=%d/%d packet=%d/%d l7=%d/%d",
		cfg.HTTPRate.SynLimitPerSec,
		cfg.HTTPRate.SynBlockThreshold,
		cfg.HTTPRate.AckLimitPerSec,
		cfg.HTTPRate.AckBlockThreshold,
		cfg.HTTPRate.FinLimitPerSec,
		cfg.HTTPRate.FinBlockThreshold,
		cfg.HTTPRate.PacketLimitPerSec,
		cfg.HTTPRate.PacketBlockThreshold,
		cfg.HTTPRate.L7DataLimitPerSec,
		cfg.HTTPRate.L7DataBlockThreshold,
	)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := loader.StatsLoop(ctx, os.Stdout); err != nil {
			log.Printf("stats loop error: %v", err)
			stop()
		}
	}()

	if cfg.LogDrops {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := loader.LogDropEvents(ctx, os.Stdout); err != nil && !errors.Is(err, context.Canceled) {
				log.Printf("drop event loop error: %v", err)
				stop()
			}
		}()
	}

	<-ctx.Done()
	log.Printf("shutting down")
	_ = loader.Close()
	wg.Wait()
}

func parseConfig() (guard.Config, error) {
	defaultRates := guard.DefaultHTTPRateConfig()

	var (
		iface         = flag.String("iface", "", "Interface to attach XDP to")
		objPath       = flag.String("obj", "dist/http_guard_xdp.o", "Path to compiled eBPF object")
		mode          = flag.String("mode", "auto", "XDP attach mode: auto|driver|native|generic|offload")
		cloudflare    = flag.Bool("cloudflare", true, "Preload the official Cloudflare IPv4 ranges into the allowlist")
		allowIP       = flag.String("allow-ip", "", "Comma-separated IPv4 addresses to allow explicitly")
		allowCIDR     = flag.String("allow-cidr", "", "Comma-separated IPv4 CIDRs to allow explicitly")
		allowFile     = flag.String("allow-file", "", "Optional file with IPv4/CIDR entries, one per line")
		logDrops      = flag.Bool("log-drops", true, "Stream drop events from the ring buffer")
		statsInterval = flag.Duration("stats-interval", 2*time.Second, "Stats print interval")
		synLimit      = flag.Uint("http-syn-limit", uint(defaultRates.SynLimitPerSec), "HTTP SYN drop threshold per IP per second")
		synBlock      = flag.Uint("http-syn-block", uint(defaultRates.SynBlockThreshold), "HTTP SYN hard threshold per IP per second")
		ackLimit      = flag.Uint("http-ack-limit", uint(defaultRates.AckLimitPerSec), "HTTP ACK drop threshold per IP per second")
		ackBlock      = flag.Uint("http-ack-block", uint(defaultRates.AckBlockThreshold), "HTTP ACK hard threshold per IP per second")
		finLimit      = flag.Uint("http-fin-limit", uint(defaultRates.FinLimitPerSec), "HTTP FIN drop threshold per IP per second")
		finBlock      = flag.Uint("http-fin-block", uint(defaultRates.FinBlockThreshold), "HTTP FIN hard threshold per IP per second")
		packetLimit   = flag.Uint("http-packet-limit", uint(defaultRates.PacketLimitPerSec), "HTTP packet drop threshold per IP per second")
		packetBlock   = flag.Uint("http-packet-block", uint(defaultRates.PacketBlockThreshold), "HTTP packet hard threshold per IP per second")
		l7Limit       = flag.Uint("http-l7-limit", uint(defaultRates.L7DataLimitPerSec), "HTTP payload packet drop threshold per IP per second")
		l7Block       = flag.Uint("http-l7-block", uint(defaultRates.L7DataBlockThreshold), "HTTP payload packet hard threshold per IP per second")
	)
	flag.Parse()

	if strings.TrimSpace(*iface) == "" {
		return guard.Config{}, errors.New("-iface is required")
	}

	ips, cidrs, err := guard.SplitAllowEntries(splitCSV(*allowIP))
	if err != nil {
		return guard.Config{}, err
	}
	extraIPs, extraCIDRs, err := guard.SplitAllowEntries(splitCSV(*allowCIDR))
	if err != nil {
		return guard.Config{}, err
	}
	ips = append(ips, extraIPs...)
	cidrs = append(cidrs, extraCIDRs...)

	if strings.TrimSpace(*allowFile) != "" {
		fileIPs, fileCIDRs, err := guard.LoadAllowlistFile(*allowFile)
		if err != nil {
			return guard.Config{}, err
		}
		ips = append(ips, fileIPs...)
		cidrs = append(cidrs, fileCIDRs...)
	}

	return guard.Config{
		Interface:        strings.TrimSpace(*iface),
		ObjectPath:       strings.TrimSpace(*objPath),
		Mode:             strings.TrimSpace(*mode),
		LogDrops:         *logDrops,
		StatsInterval:    *statsInterval,
		EnableCloudflare: *cloudflare,
		AllowIPs:         guard.DedupeStrings(ips),
		AllowCIDRs:       guard.DedupeStrings(cidrs),
		HTTPRate: guard.HTTPRateConfig{
			SynLimitPerSec:       uint32(*synLimit),
			SynBlockThreshold:    uint32(*synBlock),
			AckLimitPerSec:       uint32(*ackLimit),
			AckBlockThreshold:    uint32(*ackBlock),
			FinLimitPerSec:       uint32(*finLimit),
			FinBlockThreshold:    uint32(*finBlock),
			PacketLimitPerSec:    uint32(*packetLimit),
			PacketBlockThreshold: uint32(*packetBlock),
			L7DataLimitPerSec:    uint32(*l7Limit),
			L7DataBlockThreshold: uint32(*l7Block),
		},
	}, nil
}

func splitCSV(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	return strings.Split(raw, ",")
}

func normalizeMode(mode string) string {
	mode = strings.TrimSpace(mode)
	if mode == "" {
		return "auto"
	}
	return mode
}
