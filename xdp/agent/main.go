// D3 Step 2/3 — XDP 사이드카: 커널 map(src_ip_stats)을 주기 폴링해 소스 IP별 SYN 윈도우 레이트를
// 계산하고, 임계 초과 시 PIP에 rate.l4 신호를 POST한다(Step 2). -enforce가 켜져 있으면 PIP ack에
// 실려 온 enforcement 지시(deny+TTL)를 커널 deny map(rate_enforce.c)에 기록해 스택 진입 전
// 드랍으로 잇고, 만료된 엔트리를 걷어내며 드랍 수를 보고한다(Step 3).
//
// 역할 분담(설계):
//   - 커널(XDP): 센다(per-IP 누적 pkts/syns) + deny map에 적힌 결정을 집행한다(TTL 내 드랍). 판단 없음.
//   - 에이전트(여기): 윈도우 차분으로 레이트를 만들고 "임계 초과" 판정, PIP 지시의 커널 번역(deny map 기록).
//     PIP는 mTLS로 잠긴 데이터 포트라 발신자(에이전트)를 신뢰하고, 받은 IP를 hold 동안 플래그한다.
//   - PIP: 판단 주체 — 주체 재평가(기존 D1 경로: rate-l4 가중 → epoch bump → 능동 무효화) +
//     에지 차단 지시(enforcement)를 ack로 반환. 즉 "판단(PIP) → 트래픽 제어(XDP)"의 결정권은 PIP에 있다.
//
// L7 레이트(게이트웨이 관측 rate.l7)와 신호 타입을 분리한다 — L4는 "연결 시도 수"라서
// 토큰 없는 SYN 플러드처럼 L7에 절대 안 잡히는 폭주를 본다(관측 지점 하강의 이유).
//
// 실행(root 필요 — BPF map 접근): step2-e2e.sh가 attach 후 기동한다.
//   go build -o agent . && sudo ./agent -pip-url https://localhost:8083 \
//     -cert pdp.crt.pem -key pdp.key.pem -ca ca.crt -syn-threshold 20
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// rate_observe.c의 struct ip_stats와 메모리 배치가 일치해야 한다(u64 두 개, 패딩 없음).
type ipStats struct {
	Pkts uint64
	Syns uint64
}

// 한 폴링 시점의 map 전체 스냅샷. 커널 카운터는 누적이므로 레이트는 스냅샷 간 차분으로 만든다.
type snapshot struct {
	at    time.Time
	stats map[[4]byte]ipStats
}

type rateL4Signal struct {
	SourceIP        string `json:"sourceIp"`
	SynsInWindow    uint64 `json:"synsInWindow"`
	PacketsInWindow uint64 `json:"packetsInWindow"`
	WindowSeconds   int    `json:"windowSeconds"`
}

// PIP ack — 재평가 결과와 (Step 3) 에지 차단 지시. enforcement가 없으면(구 PIP) 관측 전용으로 동작.
type pipAck struct {
	SourceIP           string                `json:"sourceIp"`
	ReassessedSubjects []string              `json:"reassessedSubjects"`
	Enforcement        *enforcementDirective `json:"enforcement"`
}

type enforcementDirective struct {
	Action     string `json:"action"`
	TTLSeconds int64  `json:"ttlSeconds"`
}

// rate_enforce.c의 struct deny_entry와 메모리 배치 일치(u64 두 개).
type denyEntry struct {
	ExpiresAtNs uint64
	Drops       uint64
}

func main() {
	mapName := flag.String("map-name", "src_ip_stats", "polling 대상 BPF map 이름(rate_observe.c/rate_enforce.c)")
	denyMapName := flag.String("deny-map-name", "deny_ips", "enforcement 대상 BPF deny map 이름(rate_enforce.c)")
	enforce := flag.Bool("enforce", false, "PIP ack의 enforcement 지시를 deny map에 기록(Step 3)")
	pipURL := flag.String("pip-url", "https://localhost:8083", "PIP base URL")
	certFile := flag.String("cert", "", "mTLS 클라이언트 인증서(PEM). 비우면 평문 HTTP")
	keyFile := flag.String("key", "", "mTLS 클라이언트 키(PEM)")
	caFile := flag.String("ca", "", "PIP 서버 인증서 검증용 CA(PEM)")
	interval := flag.Duration("interval", 1*time.Second, "map 폴링 주기")
	window := flag.Duration("window", 5*time.Second, "레이트 계산 윈도우")
	synThreshold := flag.Uint64("syn-threshold", 20, "윈도우 내 SYN 수 임계(초과 시 신호)")
	cooldown := flag.Duration("cooldown", 10*time.Second, "같은 IP 재신호 최소 간격(신호 폭주 방지)")
	flag.Parse()

	client, err := httpClient(*certFile, *keyFile, *caFile)
	if err != nil {
		log.Fatalf("http client: %v", err)
	}

	m, err := findMapByName(*mapName)
	if err != nil {
		log.Fatalf("find map %q: %v (XDP attach가 먼저인지 확인)", *mapName, err)
	}
	defer m.Close()
	log.Printf("polling map %q every %v, window %v, syn-threshold %d", *mapName, *interval, *window, *synThreshold)

	// enforcement는 deny map이 있는 커널 프로그램(rate_enforce.c)을 요구한다 — 없으면 기동 시 fail-fast.
	var denyMap *ebpf.Map
	if *enforce {
		denyMap, err = findMapByName(*denyMapName)
		if err != nil {
			log.Fatalf("find deny map %q: %v (rate_enforce.o attach가 먼저 — 관측 전용 rate_observe.o에는 없다)", *denyMapName, err)
		}
		defer denyMap.Close()
		log.Printf("enforcement ON: PIP 지시를 deny map %q에 기록", *denyMapName)
	}

	// 윈도우를 폴링 주기로 나눈 만큼 스냅샷을 유지한다. 가장 오래된 것이 "윈도우 전" 기준(baseline)이
	// 되고, 히스토리가 찰 때까지는 판정하지 않는다 — 폭주 중에 기동해도 누적치를 레이트로 오인하지 않는다.
	depth := int(*window / *interval)
	if depth < 1 {
		depth = 1
	}
	history := make([]snapshot, 0, depth+1)
	lastSignal := map[[4]byte]time.Time{}

	for {
		cur, err := readMap(m)
		if err != nil {
			log.Fatalf("read map: %v (detach 후라면 종료가 정상)", err)
		}
		history = append(history, cur)
		if len(history) > depth+1 {
			history = history[1:]
		}
		if len(history) == depth+1 {
			base := history[0]
			for key, now := range cur.stats {
				// baseline에 없던 IP는 카운터 0에서 시작한 것 — 윈도우 안에 다 도착했으므로 차분 그대로.
				prev := base.stats[key]
				synsInWindow := now.Syns - prev.Syns
				if synsInWindow <= *synThreshold {
					continue
				}
				if since, seen := lastSignal[key]; seen && cur.at.Sub(since) < *cooldown {
					continue
				}
				lastSignal[key] = cur.at
				sig := rateL4Signal{
					SourceIP:        netip.AddrFrom4(key).String(),
					SynsInWindow:    synsInWindow,
					PacketsInWindow: now.Pkts - prev.Pkts,
					WindowSeconds:   int(window.Seconds()),
				}
				ack, err := postSignal(client, *pipURL, sig)
				if err != nil {
					// 신호 실패는 치명 아님(다음 윈도우에 재시도) — PIP 쪽 백스톱(TTL)도 있다.
					log.Printf("signal %s FAILED: %v", sig.SourceIP, err)
				} else if denyMap != nil && ack.Enforcement != nil && ack.Enforcement.Action == "deny" {
					// 판단(PIP)의 커널 번역: 이 순간부터 TTL 동안 해당 IP 패킷은 스택 진입 전 드랍.
					if err := applyDeny(denyMap, key, ack.Enforcement.TTLSeconds); err != nil {
						log.Printf("ENFORCE %s FAILED: %v", sig.SourceIP, err)
					} else {
						log.Printf("ENFORCE deny %s ttl=%ds (kernel drop until expiry)", sig.SourceIP, ack.Enforcement.TTLSeconds)
					}
				}
			}
		}
		if denyMap != nil {
			sweepExpiredDenies(denyMap)
		}
		time.Sleep(*interval)
	}
}

// PIP의 deny 지시를 deny map에 기록한다. 만료는 커널과 같은 시계(CLOCK_MONOTONIC =
// bpf_ktime_get_ns)로 계산 — 벽시계 점프에 안전. 재지시는 만료를 연장하되 드랍 카운트(집행 증거)는 보존.
func applyDeny(denyMap *ebpf.Map, key [4]byte, ttlSeconds int64) error {
	now, err := monotonicNowNs()
	if err != nil {
		return err
	}
	entry := denyEntry{ExpiresAtNs: now + uint64(ttlSeconds)*uint64(time.Second)}
	var prev denyEntry
	if err := denyMap.Lookup(key, &prev); err == nil {
		entry.Drops = prev.Drops
	}
	return denyMap.Update(key, entry, ebpf.UpdateAny)
}

// 만료 엔트리 정리(위생) — 통과 판정 자체는 커널이 하므로 지연돼도 무해하다. 삭제 시 그 차단
// 구간의 드랍 수를 로그로 남긴다(집행됐음의 증거 + 해제 시점 가시화).
func sweepExpiredDenies(denyMap *ebpf.Map) {
	now, err := monotonicNowNs()
	if err != nil {
		return
	}
	type expired struct {
		key   [4]byte
		drops uint64
	}
	var gone []expired // 순회 중 삭제는 hash 순회를 흔들 수 있어 수집 후 삭제
	var key [4]byte
	var val denyEntry
	it := denyMap.Iterate()
	for it.Next(&key, &val) {
		if now >= val.ExpiresAtNs {
			gone = append(gone, expired{key, val.Drops})
		}
	}
	for _, e := range gone {
		if err := denyMap.Delete(e.key); err == nil {
			log.Printf("RELEASE %s (deny expired, kernel dropped %d packets)", netip.AddrFrom4(e.key), e.drops)
		}
	}
}

func monotonicNowNs() (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, err
	}
	return uint64(ts.Nano()), nil
}

// 이름으로 로드된 BPF map을 찾는다. attach 스크립트(ip link set ... obj)는 아무것도 핀하지 않으므로
// bpffs 경로 대신 커널의 map ID 공간을 순회한다(호스트 netns에서 전역 가시 — Step 0에서 확인한 성질).
func findMapByName(name string) (*ebpf.Map, error) {
	var id ebpf.MapID
	for {
		next, err := ebpf.MapGetNextID(id)
		if err != nil {
			return nil, fmt.Errorf("map %q not found", name)
		}
		id = next
		m, err := ebpf.NewMapFromID(id)
		if err != nil {
			continue // 순회 중 사라진 map — 무시하고 계속
		}
		info, err := m.Info()
		if err == nil && info.Name == name {
			return m, nil
		}
		m.Close()
	}
}

func readMap(m *ebpf.Map) (snapshot, error) {
	snap := snapshot{at: time.Now(), stats: map[[4]byte]ipStats{}}
	var key [4]byte // __u32 saddr, network byte order → 바이트 그대로 받아 netip로 변환(엔디안 함정 회피)
	var val ipStats
	it := m.Iterate()
	for it.Next(&key, &val) {
		snap.stats[key] = val
	}
	return snap, it.Err()
}

func postSignal(client *http.Client, baseURL string, sig rateL4Signal) (*pipAck, error) {
	body, err := json.Marshal(sig)
	if err != nil {
		return nil, err
	}
	resp, err := client.Post(baseURL+"/pip/signals/rate-l4", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("PIP %d: %s", resp.StatusCode, raw)
	}
	log.Printf("signal %s syns=%d/%ds -> PIP ack %s", sig.SourceIP, sig.SynsInWindow, sig.WindowSeconds, raw)
	var ack pipAck
	if err := json.Unmarshal(raw, &ack); err != nil {
		return nil, fmt.Errorf("ack parse: %w (body: %s)", err, raw)
	}
	return &ack, nil
}

// cert가 주어지면 mTLS 클라이언트(PIP 데이터 포트=client-auth need), 아니면 평문(로컬 bootRun 대비).
func httpClient(certFile, keyFile, caFile string) (*http.Client, error) {
	if certFile == "" {
		return &http.Client{Timeout: 3 * time.Second}, nil
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("invalid CA PEM: " + caFile)
	}
	return &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool},
		},
	}, nil
}
