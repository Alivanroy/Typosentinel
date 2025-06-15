package performance

import (
    "os/exec"
    "testing"
    "time"
    "github.com/shirou/gopsutil/v3/process"
)

func TestMemoryLeak(t *testing.T) {
    cmd := exec.Command("go", "run", "./cmd/server", "serve")
    if err := cmd.Start(); err != nil { t.Fatal(err) }
    proc, _ := process.NewProcess(int32(cmd.Process.Pid))
    baseline, _ := proc.MemoryInfo()
    ticker := time.NewTicker(time.Minute)
    for i := 0; i < 72; i++ {
        <-ticker.C
        cur, _ := proc.MemoryInfo()
        if float64(cur.RSS-baseline.RSS)/float64(baseline.RSS) > 0.05 {
            t.Fatalf("memory increased >5%% in %d minutes", i)
        }
    }
    _ = cmd.Process.Kill()
}