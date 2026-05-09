#!/usr/bin/env python3
"""
analyze-metrics.py

Анализирует metrics.log от xray-metrics.sh.
Формат строк:
  ISO_TS|fd=N|mem_mb=N|cpu=F|conn_est=N|syn_recv=N|time_wait=N|close_wait=N|
  fin_wait=N|load=F|steal=F|up_mb=N|down_mb=N

Использование:
    ./analyze-metrics.py /path/to/metrics.log
    ./analyze-metrics.py /path/to/metrics.log --hours 6   # только последние 6 часов
    ./analyze-metrics.py /path/to/metrics.log --plot      # ASCII график тренда fd
"""

from __future__ import annotations

import argparse
import statistics
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path


@dataclass
class Snapshot:
    ts: datetime
    fd: int
    mem_mb: int
    cpu: float
    conn_est: int
    syn_recv: int
    time_wait: int
    close_wait: int
    fin_wait: int
    load: float
    steal: float
    up_mb: int
    down_mb: int


def parse_line(line: str) -> Snapshot | None:
    """Парсим строку формата: ISO_TS|fd=N|...|down_mb=N"""
    parts = line.strip().split("|")
    if len(parts) < 2:
        return None

    try:
        ts = datetime.fromisoformat(parts[0].replace("Z", "+00:00"))
    except ValueError:
        return None

    # Если xray не запущен — будет 'XRAY_NOT_RUNNING' вместо метрик
    if any("NOT_RUNNING" in p for p in parts):
        return None

    fields: dict[str, str] = {}
    for p in parts[1:]:
        if "=" in p:
            k, v = p.split("=", 1)
            fields[k] = v

    def i(key: str) -> int:
        try:
            return int(float(fields.get(key, "0")))
        except ValueError:
            return 0

    def f(key: str) -> float:
        try:
            return float(fields.get(key, "0"))
        except ValueError:
            return 0.0

    return Snapshot(
        ts=ts,
        fd=i("fd"),
        mem_mb=i("mem_mb"),
        cpu=f("cpu"),
        conn_est=i("conn_est"),
        syn_recv=i("syn_recv"),
        time_wait=i("time_wait"),
        close_wait=i("close_wait"),
        fin_wait=i("fin_wait"),
        load=f("load"),
        steal=f("steal"),
        up_mb=i("up_mb"),
        down_mb=i("down_mb"),
    )


def load_snapshots(path: Path, hours: int | None = None) -> list[Snapshot]:
    snapshots: list[Snapshot] = []
    cutoff = (
        datetime.now(timezone.utc) - timedelta(hours=hours) if hours else None
    )

    for line in path.read_text().splitlines():
        snap = parse_line(line)
        if not snap:
            continue
        if cutoff and snap.ts < cutoff:
            continue
        snapshots.append(snap)

    return snapshots


def fmt_stat(values: list[float], unit: str = "") -> str:
    """avg=X max=Y min=Z p95=W"""
    if not values:
        return "—"
    sv = sorted(values)
    p95 = sv[int(len(sv) * 0.95)] if len(sv) > 1 else sv[0]
    avg = statistics.mean(values)
    return (
        f"avg={avg:.1f}{unit} "
        f"min={min(values):.0f}{unit} "
        f"p95={p95:.0f}{unit} "
        f"max={max(values):.0f}{unit}"
    )


def print_summary(snaps: list[Snapshot]) -> None:
    if not snaps:
        print("(нет данных в указанном диапазоне)")
        return

    period_start = snaps[0].ts
    period_end = snaps[-1].ts
    period_hours = (period_end - period_start).total_seconds() / 3600

    print("=" * 70)
    print(f"Период: {period_start} → {period_end}")
    print(f"        ({period_hours:.1f} часов, {len(snaps)} snapshot'ов)")
    print("=" * 70)

    print("\n--- РЕСУРСЫ XRAY ---")
    print(f"  fd:        {fmt_stat([s.fd for s in snaps])}")
    print(f"  memory MB: {fmt_stat([s.mem_mb for s in snaps])}")
    print(f"  cpu %:     {fmt_stat([s.cpu for s in snaps], '%')}")

    print("\n--- TCP СОЕДИНЕНИЯ ---")
    print(f"  established: {fmt_stat([s.conn_est for s in snaps])}")
    print(f"  syn_recv:    {fmt_stat([s.syn_recv for s in snaps])}")
    print(f"  time_wait:   {fmt_stat([s.time_wait for s in snaps])}")
    print(f"  close_wait:  {fmt_stat([s.close_wait for s in snaps])}")
    print(f"  fin_wait:    {fmt_stat([s.fin_wait for s in snaps])}")

    print("\n--- НАГРУЗКА ХОСТА ---")
    print(f"  load:    {fmt_stat([s.load for s in snaps])}")
    print(f"  steal %: {fmt_stat([s.steal for s in snaps], '%')}")

    print("\n--- ТРАФИК (cumulative с старта xray) ---")
    last = snaps[-1]
    print(f"  uplink:   {last.up_mb} MB")
    print(f"  downlink: {last.down_mb} MB")


def detect_anomalies(snaps: list[Snapshot]) -> None:
    """Ищем интересные события — рестарты xray, скачки fd, пики стыла."""
    if len(snaps) < 2:
        return

    print("\n--- АНОМАЛИИ И СОБЫТИЯ ---")
    found = False

    # Рестарты xray — счётчики (fd, up_mb, down_mb) сбрасываются
    for prev, cur in zip(snaps, snaps[1:]):
        if cur.up_mb < prev.up_mb * 0.5 and prev.up_mb > 100:
            print(f"  [{cur.ts}] возможный рестарт xray "
                  f"(up_mb {prev.up_mb} → {cur.up_mb})")
            found = True

    # Скачки fd — рост >2x за один шаг
    for prev, cur in zip(snaps, snaps[1:]):
        if cur.fd > prev.fd * 2 and cur.fd > 1000:
            jump = cur.fd - prev.fd
            print(f"  [{cur.ts}] скачок fd: {prev.fd} → {cur.fd} (+{jump})")
            found = True

    # Пики steal >30%
    high_steal = [s for s in snaps if s.steal > 30]
    if high_steal:
        worst = max(high_steal, key=lambda s: s.steal)
        print(f"  high steal: {len(high_steal)} раз > 30%, "
              f"максимум {worst.steal:.1f}% в {worst.ts}")
        found = True

    # Пики fd >5000
    high_fd = [s for s in snaps if s.fd > 5000]
    if high_fd:
        worst = max(high_fd, key=lambda s: s.fd)
        print(f"  high fd: {len(high_fd)} раз > 5000, "
              f"максимум {worst.fd} в {worst.ts}")
        found = True

    # Memory > 350M (близко к лимиту 400M)
    high_mem = [s for s in snaps if s.mem_mb > 350]
    if high_mem:
        worst = max(high_mem, key=lambda s: s.mem_mb)
        print(f"  high memory: {len(high_mem)} раз > 350MB, "
              f"максимум {worst.mem_mb}MB в {worst.ts}")
        found = True

    # close_wait > 100 — приложение не закрывает соединения вовремя
    high_cw = [s for s in snaps if s.close_wait > 100]
    if high_cw:
        worst = max(high_cw, key=lambda s: s.close_wait)
        print(f"  high close_wait: {len(high_cw)} раз > 100, "
              f"максимум {worst.close_wait} в {worst.ts}")
        print("    → приложение не вовремя закрывает сокеты, "
              "признак leak в xray")
        found = True

    # syn_recv > 50 — возможный SYN flood
    high_sr = [s for s in snaps if s.syn_recv > 50]
    if high_sr:
        worst = max(high_sr, key=lambda s: s.syn_recv)
        print(f"  high syn_recv: {len(high_sr)} раз > 50, "
              f"максимум {worst.syn_recv} в {worst.ts}")
        print("    → возможный SYN flood / активные сканеры")
        found = True

    if not found:
        print("  (всё в норме)")


def detect_growth_pattern(snaps: list[Snapshot]) -> None:
    """Линейный ли рост fd между рестартами — указывает на leak."""
    if len(snaps) < 3:
        return

    # Найдём сегменты между рестартами (рестарт = up_mb упал)
    segments: list[list[Snapshot]] = []
    current: list[Snapshot] = [snaps[0]]
    for prev, cur in zip(snaps, snaps[1:]):
        if cur.up_mb < prev.up_mb * 0.5 and prev.up_mb > 100:
            if len(current) > 1:
                segments.append(current)
            current = [cur]
        else:
            current.append(cur)
    if len(current) > 1:
        segments.append(current)

    if not segments:
        return

    print("\n--- ПАТТЕРН РОСТА FD (между рестартами xray) ---")
    for i, seg in enumerate(segments, 1):
        if len(seg) < 3:
            continue
        duration_h = (seg[-1].ts - seg[0].ts).total_seconds() / 3600
        fd_start = seg[0].fd
        fd_end = seg[-1].fd
        fd_max = max(s.fd for s in seg)

        if duration_h < 0.1:
            continue

        # Скорость роста fd в час
        rate = (fd_end - fd_start) / duration_h if duration_h else 0

        print(f"  segment {i}: {seg[0].ts} → {seg[-1].ts} "
              f"({duration_h:.1f}h)")
        print(f"    fd: {fd_start} → {fd_end} (max {fd_max}), "
              f"rate ≈ {rate:+.0f}/час")
        if rate > 100:
            print(f"    → рост >100/час — это leak")
        elif rate > 50:
            print(f"    → умеренный рост, возможна утечка")
        else:
            print(f"    → стабильно")


def hourly_breakdown(snaps: list[Snapshot]) -> None:
    """По часам суток — когда нагрузка пиковая."""
    if not snaps:
        return

    print("\n--- ПО ЧАСАМ СУТОК (UTC) ---")
    print("  hour |   fd_avg   conn_avg   cpu_avg   syn_recv_avg")
    print("  -----+--------------------------------------------")

    by_hour: dict[int, list[Snapshot]] = {}
    for s in snaps:
        by_hour.setdefault(s.ts.hour, []).append(s)

    for hour in sorted(by_hour):
        bucket = by_hour[hour]
        fd = statistics.mean(s.fd for s in bucket)
        conn = statistics.mean(s.conn_est for s in bucket)
        cpu = statistics.mean(s.cpu for s in bucket)
        sr = statistics.mean(s.syn_recv for s in bucket)
        print(f"   {hour:02d}  | {fd:8.0f}  {conn:8.0f}  "
              f"{cpu:8.1f}%  {sr:8.1f}")


def ascii_plot(snaps: list[Snapshot], field: str = "fd",
               width: int = 70, height: int = 15) -> None:
    """Простой ASCII-график одного поля во времени."""
    if not snaps:
        return

    values = [getattr(s, field) for s in snaps]
    if not values:
        return

    print(f"\n--- ГРАФИК: {field} ---")

    vmin, vmax = min(values), max(values)
    if vmax == vmin:
        vmax = vmin + 1

    # Семплируем width значений
    step = max(1, len(values) // width)
    sampled = values[::step][:width]

    # Шкала: каждое значение → row 0..height-1
    grid = [[" "] * len(sampled) for _ in range(height)]
    for col, v in enumerate(sampled):
        row = int((v - vmin) / (vmax - vmin) * (height - 1))
        row = height - 1 - row  # инвертируем (макс сверху)
        grid[row][col] = "#"

    for i, line in enumerate(grid):
        # подпись по Y
        v_at_row = vmax - (vmax - vmin) * i / (height - 1)
        print(f"  {v_at_row:8.0f} | {''.join(line)}")
    print(f"           +{'-' * len(sampled)}")
    print(f"           {snaps[0].ts.strftime('%m-%d %H:%M')}"
          f"{' ' * (len(sampled) - 16)}{snaps[-1].ts.strftime('%H:%M')}")


def main() -> None:
    parser = argparse.ArgumentParser(description="analyze xray-monitor metrics.log")
    parser.add_argument("logfile", type=Path, help="path to metrics.log")
    parser.add_argument("--hours", type=int, default=None,
                        help="последние N часов")
    parser.add_argument("--plot", action="store_true",
                        help="ASCII график по fd")
    parser.add_argument("--plot-field", default="fd",
                        help="поле для графика (fd, mem_mb, cpu, conn_est, ...)")
    args = parser.parse_args()

    if not args.logfile.exists():
        print(f"error: файл не найден — {args.logfile}", file=sys.stderr)
        sys.exit(1)

    snaps = load_snapshots(args.logfile, args.hours)
    if not snaps:
        print("(пусто) — лог пустой или формат не распознан")
        sys.exit(1)

    print_summary(snaps)
    detect_anomalies(snaps)
    detect_growth_pattern(snaps)
    hourly_breakdown(snaps)

    if args.plot:
        ascii_plot(snaps, field=args.plot_field)


if __name__ == "__main__":
    main()
