// D3 Step 2 — XDP 관측 사이드카: 커널 map(src_ip_stats, rate_observe.c가 집계)을 주기 폴링해
// 소스 IP별 SYN 윈도우 레이트를 계산하고, 임계 초과 시 PIP에 rate.l4 신호를 POST한다.
//
// 역할 분담(설계):
//   - 커널(XDP): 세기만 한다(per-IP 누적 pkts/syns). 판단 없음 — 항상 XDP_PASS.
//   - 에이전트(여기): 누적 카운터의 윈도우 차분으로 레이트를 만들고 "임계 초과" 판정까지 한다.
//     PIP는 mTLS로 잠긴 데이터 포트라 발신자(에이전트)를 신뢰하고, 받은 IP를 hold 동안 플래그한다.
//   - PIP 이후는 기존 D1 경로 재사용: rate-l4 가중 → 점수 변화 → epoch bump → 능동 무효화(fan-out).
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

func main() {
	mapName := flag.String("map-name", "src_ip_stats", "polling 대상 BPF map 이름(rate_observe.c)")
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
				if err := postSignal(client, *pipURL, sig); err != nil {
					// 신호 실패는 치명 아님(다음 윈도우에 재시도) — PIP 쪽 백스톱(TTL)도 있다.
					log.Printf("signal %s FAILED: %v", sig.SourceIP, err)
				}
			}
		}
		time.Sleep(*interval)
	}
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

func postSignal(client *http.Client, baseURL string, sig rateL4Signal) error {
	body, err := json.Marshal(sig)
	if err != nil {
		return err
	}
	resp, err := client.Post(baseURL+"/pip/signals/rate-l4", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	ack, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("PIP %d: %s", resp.StatusCode, ack)
	}
	log.Printf("signal %s syns=%d/%ds -> PIP ack %s", sig.SourceIP, sig.SynsInWindow, sig.WindowSeconds, ack)
	return nil
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
