/* SPDX-License-Identifier: Apache-2.0 */
/*
 * NvtTouchTracker.h — Pure C11 finger-touch centroid & Hungarian tracker
 * calibrated specifically for Xiaomi Pad 7S Pro (violin / o81a, 3200x2136,
 * 40x60 NT36536 THP matrix) using factory violin_nova_thp_config.ini tables.
 *
 * Algorithm structure adapted from UniXNU/ShengNovatekTouch (Apache-2.0).
 */
#ifndef NVT_TOUCH_TRACKER_H
#define NVT_TOUCH_TRACKER_H

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define VTOUCH_ROWS             40
#define VTOUCH_COLS             60
#define VTOUCH_NODES            (VTOUCH_ROWS * VTOUCH_COLS)
#define VTOUCH_SUPER_RES        10
#define VTOUCH_LONG_MAX         32000 /* 3200 * 10 */
#define VTOUCH_SHORT_MAX        21360 /* 2136 * 10 */
#define VTOUCH_SLOTS            10
#define VTOUCH_MAX_PEAKS        24
#define VTOUCH_STARTUP_FRAMES   24
#define VTOUCH_FRAME_HZ         120

/* Factory violin_nova_thp_config.ini thresholds */
#define VTOUCH_NOISE_THD        100
#define VTOUCH_PEAK_THD         220
#define VTOUCH_DOWN_THD         300
#define VTOUCH_UP_THD           220
#define VTOUCH_COORD_REDUCE     35
#define VTOUCH_CENTROID_FLOOR   30
#define VTOUCH_PALM_MIN_NODES   60
#define VTOUCH_MIN_ONSET_AREA   2
#define VTOUCH_MERGE_SPAN       2
#define VTOUCH_HOLD_FRAMES      3
#define VTOUCH_REF_RATE         32
#define VTOUCH_REF_SETTLE       8
#define VTOUCH_FUZZ             60
#define VTOUCH_TRACK_RADIUS     (VTOUCH_SUPER_RES * 54 * 4)
#define VTOUCH_REJOIN_RADIUS    (4 * VTOUCH_FUZZ)
#define VTOUCH_MIN_CUTOFF_MHZ   1000L
#define VTOUCH_CUTOFF_PER_SPEED 3L
#define VTOUCH_SPEED_CUTOFF_MHZ 1000L
#define VTOUCH_AXIS_BASE        2700
#define VTOUCH_AXIS_EDGE        600
#define VTOUCH_AXIS_GAIN        4350

/* Factory default_mapping_x (40 rows, short axis 0..2135) */
static const int kViolinRowMap[VTOUCH_ROWS] = {
    28, 82, 136, 190, 244, 298, 352, 406, 460, 514,
    568, 622, 676, 730, 784, 838, 892, 946, 1000, 1054,
    1108, 1162, 1216, 1270, 1324, 1378, 1432, 1486, 1539, 1591,
    1643, 1695, 1747, 1799, 1851, 1903, 1955, 2007, 2059, 2111,
};

/* Factory default_mapping_y (60 cols, long axis 0..3199) */
static const int kViolinColMap[VTOUCH_COLS] = {
    25, 77, 129, 181, 233, 286, 340, 394, 448, 502,
    556, 610, 664, 718, 772, 826, 880, 934, 988, 1042,
    1096, 1150, 1204, 1258, 1312, 1365, 1417, 1469, 1521, 1573,
    1625, 1677, 1729, 1781, 1833, 1886, 1940, 1994, 2048, 2102,
    2156, 2210, 2264, 2318, 2372, 2426, 2480, 2534, 2588, 2642,
    2696, 2750, 2804, 2858, 2912, 2965, 3017, 3069, 3121, 3173,
};

struct VTouchContact {
    int slot;
    int tracking_id;
    int x; /* long axis 0..31999 */
    int y; /* short axis 0..21359 */
    int peak;
    int area;
};

struct VTouchSlot {
    int active, tracking_id, age, x, y;
    int rx, ry;
    long fx, fy, vx, vy;
    int dx, dy;
    int missed;
};

struct VTouchTracker {
    int16_t reference[VTOUCH_NODES];
    int have_reference;
    unsigned startup_count;
    int32_t startup_sum[VTOUCH_NODES]; /* mean reference: zero 345 KB startup array overhead */
    unsigned quiet_frames;
    unsigned long frames_processed;
    struct VTouchSlot slots[VTOUCH_SLOTS];
    int delta[VTOUCH_NODES];
    int label[VTOUCH_NODES];
};

static inline void vtouch_reset(struct VTouchTracker *t)
{
    memset(t, 0, sizeof(*t));
}

static inline int vtouch_map_edge_axis(int value, int maximum, int low_bias)
{
    if (value < VTOUCH_AXIS_EDGE) {
        int mapped = VTOUCH_AXIS_GAIN * (VTOUCH_AXIS_EDGE - value) / VTOUCH_AXIS_BASE;
        if (mapped > VTOUCH_AXIS_EDGE - 1) mapped = VTOUCH_AXIS_EDGE - 1;
        int r = VTOUCH_AXIS_EDGE - mapped - (low_bias ? 1 : 0);
        return r < 0 ? 0 : r;
    }
    int edge_start = maximum - VTOUCH_AXIS_EDGE;
    if (value > edge_start) {
        int mapped = VTOUCH_AXIS_GAIN * (value - edge_start) / VTOUCH_AXIS_BASE;
        if (mapped > VTOUCH_AXIS_EDGE - 1) mapped = VTOUCH_AXIS_EDGE - 1;
        int r = edge_start + mapped;
        return r >= maximum ? maximum - 1 : r;
    }
    return value;
}

static inline int vtouch_free_id(const struct VTouchTracker *t)
{
    for (int id = 1; id <= VTOUCH_SLOTS; ++id) {
        int taken = 0;
        for (int s = 0; s < VTOUCH_SLOTS && !taken; ++s) {
            taken = t->slots[s].active && t->slots[s].tracking_id == id;
        }
        if (!taken) return id;
    }
    return VTOUCH_SLOTS;
}

static inline long vtouch_alpha(long cutoff_mhz)
{
    const long w = cutoff_mhz * 411775L / (1000L * VTOUCH_FRAME_HZ);
    return w * 65536L / (65536L + w);
}

static inline void vtouch_follow(struct VTouchSlot *slot, int x, int y, int weak)
{
    if (weak) return;
    const long sx = ((long)x * 16L - slot->fx) * VTOUCH_FRAME_HZ / 16L;
    const long sy = ((long)y * 16L - slot->fy) * VTOUCH_FRAME_HZ / 16L;
    const long sa = vtouch_alpha(VTOUCH_SPEED_CUTOFF_MHZ);
    slot->vx += (sx - slot->vx) * sa / 65536L;
    slot->vy += (sy - slot->vy) * sa / 65536L;
    const long spd = (slot->vx < 0 ? -slot->vx : slot->vx) + (slot->vy < 0 ? -slot->vy : slot->vy);
    const long alpha = vtouch_alpha(VTOUCH_MIN_CUTOFF_MHZ + spd * VTOUCH_CUTOFF_PER_SPEED / 2L);
    slot->fx += ((long)x * 16L - slot->fx) * alpha / 65536L;
    slot->fy += ((long)y * 16L - slot->fy) * alpha / 65536L;
    slot->rx = (int)((slot->fx + 8L) / 16L);
    slot->ry = (int)((slot->fy + 8L) / 16L);
}

static inline long vtouch_cost(const struct VTouchSlot *slot, const struct VTouchContact *found,
                               int nfound, int j, int predict)
{
    const long r2 = (long)VTOUCH_TRACK_RADIUS * (long)VTOUCH_TRACK_RADIUS;
    if (j >= nfound) return r2;
    if (found[j].peak < VTOUCH_UP_THD) return 4L * r2;
    const int steps = predict ? (slot->missed + 1) : 0;
    const long px = slot->x + (long)slot->dx * steps;
    const long py = slot->y + (long)slot->dy * steps;
    const long dx = found[j].x - px, dy = found[j].y - py;
    const long d = dx * dx + dy * dy;
    const long limit = slot->missed ? ((long)VTOUCH_REJOIN_RADIUS * VTOUCH_REJOIN_RADIUS) : r2;
    return d <= limit ? d : 4L * r2;
}

static inline void vtouch_assign(const struct VTouchTracker *t, const struct VTouchContact *found,
                                 int nfound, int *match)
{
    enum { COLS = VTOUCH_MAX_PEAKS + VTOUCH_SLOTS };
    int rows[VTOUCH_SLOTS + 1], n = 0;
    for (int s = 0; s < VTOUCH_SLOTS; ++s) {
        match[s] = -1;
        if (t->slots[s].active) rows[++n] = s;
    }
    if (!n) return;
    const int predict = (n <= 3);
    const int m = nfound + n;
    long u[VTOUCH_SLOTS + 1] = {0}, v[COLS + 1] = {0}, minv[COLS + 1];
    int p[COLS + 1] = {0}, way[COLS + 1] = {0};
    char used[COLS + 1];
    for (int i = 1; i <= n; ++i) {
        p[0] = i;
        int j0 = 0;
        for (int j = 0; j <= m; ++j) { minv[j] = LONG_MAX; used[j] = 0; }
        do {
            used[j0] = 1;
            const int i0 = p[j0];
            long delta = LONG_MAX;
            int j1 = 0;
            for (int j = 1; j <= m; ++j) {
                if (used[j]) continue;
                const long cur = vtouch_cost(&t->slots[rows[i0]], found, nfound, j - 1, predict) - u[i0] - v[j];
                if (cur < minv[j]) { minv[j] = cur; way[j] = j0; }
                if (minv[j] < delta) { delta = minv[j]; j1 = j; }
            }
            for (int j = 0; j <= m; ++j) {
                if (used[j]) { u[p[j]] += delta; v[j] -= delta; }
                else minv[j] -= delta;
            }
            j0 = j1;
        } while (p[j0]);
        do { int j1 = way[j0]; p[j0] = p[j1]; j0 = j1; } while (j0);
    }
    const long r2 = (long)VTOUCH_TRACK_RADIUS * (long)VTOUCH_TRACK_RADIUS;
    for (int j = 1; j <= nfound; ++j) {
        if (!p[j]) continue;
        const int s = rows[p[j]];
        if (vtouch_cost(&t->slots[s], found, nfound, j - 1, predict) <= r2) match[s] = j - 1;
    }
}

/* Feed one 40x60 int16 matrix. Returns visible contact count, or -1 during baseline warmup. */
static inline int vtouch_process(struct VTouchTracker *t, const int16_t *matrix, unsigned scan_mode,
                                 struct VTouchContact *out, int max_out)
{
    if (!t || !matrix || !out || max_out <= 0) return 0;
    if (scan_mode == 2u && !t->have_reference) {
        memcpy(t->reference, matrix, sizeof(t->reference));
        t->have_reference = 1;
        t->startup_count = 0u;
        return -1;
    }
    if (!t->have_reference) {
        for (int i = 0; i < VTOUCH_NODES; ++i) t->startup_sum[i] += (int32_t)matrix[i];
        if (++t->startup_count < VTOUCH_STARTUP_FRAMES) return -1;
        for (int i = 0; i < VTOUCH_NODES; ++i) {
            t->reference[i] = (int16_t)(t->startup_sum[i] / (int32_t)VTOUCH_STARTUP_FRAMES);
        }
        t->have_reference = 1;
        return -1;
    }
    ++t->frames_processed;

    int *delta = t->delta;
    int *label = t->label;
    for (int i = 0; i < VTOUCH_NODES; ++i) {
        delta[i] = (int)matrix[i] - (int)t->reference[i];
        label[i] = -1;
    }

    struct { int idx, val; } peaks[VTOUCH_MAX_PEAKS];
    int replaced[VTOUCH_MAX_PEAKS];
    int npeaks = 0;

    for (int i = 0; i < VTOUCH_NODES; ++i) {
        if (delta[i] < VTOUCH_NOISE_THD) continue;
        int cur = i;
        for (;;) {
            int best = cur, bv = delta[cur], r = cur / VTOUCH_COLS, c = cur % VTOUCH_COLS;
            for (int dr = -1; dr <= 1; ++dr) {
                for (int dc = -1; dc <= 1; ++dc) {
                    if (!dr && !dc) continue;
                    int rr = r + dr, cc = c + dc;
                    if (rr < 0 || rr >= VTOUCH_ROWS || cc < 0 || cc >= VTOUCH_COLS) continue;
                    int nb = rr * VTOUCH_COLS + cc;
                    if (delta[nb] > bv || (delta[nb] == bv && nb > best && delta[nb] > delta[cur])) {
                        bv = delta[nb]; best = nb;
                    }
                }
            }
            if (best == cur) break;
            cur = best;
        }
        int fi = -1;
        for (int p = 0; p < npeaks; ++p) if (peaks[p].idx == cur) { fi = p; break; }
        if (fi < 0) {
            if (npeaks == VTOUCH_MAX_PEAKS) {
                int wk = 0;
                for (int p = 1; p < npeaks; ++p) if (peaks[p].val < peaks[wk].val) wk = p;
                if (peaks[wk].val >= delta[cur]) continue;
                peaks[wk].idx = cur; peaks[wk].val = delta[cur]; ++replaced[wk]; fi = wk;
            } else {
                replaced[npeaks] = 0; peaks[npeaks].idx = cur; peaks[npeaks].val = delta[cur]; fi = npeaks++;
            }
        }
        label[i] = fi | (replaced[fi] << 8);
    }
    for (int i = 0; i < VTOUCH_NODES; ++i) {
        if (label[i] >= 0) label[i] = ((label[i] >> 8) == replaced[label[i] & 0xFF]) ? (label[i] & 0xFF) : -1;
    }

    /* Fold ridges within VTOUCH_MERGE_SPAN */
    int into[VTOUCH_MAX_PEAKS];
    for (int p = 0; p < npeaks; ++p) {
        into[p] = p;
        int pr = peaks[p].idx / VTOUCH_COLS, pc = peaks[p].idx % VTOUCH_COLS;
        for (int q = 0; q < npeaks; ++q) {
            if (q == p) continue;
            int dr = peaks[q].idx / VTOUCH_COLS - pr, dc = peaks[q].idx % VTOUCH_COLS - pc;
            if (dr < -VTOUCH_MERGE_SPAN || dr > VTOUCH_MERGE_SPAN ||
                dc < -VTOUCH_MERGE_SPAN || dc > VTOUCH_MERGE_SPAN) continue;
            int best = into[p];
            if (peaks[q].val > peaks[best].val || (peaks[q].val == peaks[best].val && q < best)) into[p] = q;
        }
    }
    for (int p = 0; p < npeaks; ++p) {
        int r = p;
        while (into[r] != r) r = into[r];
        into[p] = r;
    }
    for (int i = 0; i < VTOUCH_NODES; ++i) if (label[i] >= 0) label[i] = into[label[i]];

    struct { long sw, sr, sc; int peak, area; } blobs[VTOUCH_MAX_PEAKS];
    for (int p = 0; p < npeaks; ++p) { memset(&blobs[p], 0, sizeof(blobs[p])); blobs[p].peak = peaks[p].val; }
    for (int i = 0; i < VTOUCH_NODES; ++i) {
        if (label[i] < 0) continue;
        int fl = peaks[label[i]].val * VTOUCH_CENTROID_FLOOR / 100;
        if (fl < VTOUCH_COORD_REDUCE) fl = VTOUCH_COORD_REDUCE;
        int w = delta[i] - fl;
        if (w < 0) w = 0;
        blobs[label[i]].sw += w;
        blobs[label[i]].sr += (long)w * kViolinRowMap[i / VTOUCH_COLS] * VTOUCH_SUPER_RES;
        blobs[label[i]].sc += (long)w * kViolinColMap[i % VTOUCH_COLS] * VTOUCH_SUPER_RES;
        ++blobs[label[i]].area;
    }

    struct VTouchContact found[VTOUCH_MAX_PEAKS];
    int nfound = 0, palm_touch = 0;
    for (int p = 0; p < npeaks; ++p) {
        if (!blobs[p].sw) continue;
        if (blobs[p].area >= VTOUCH_PALM_MIN_NODES) {
            if (blobs[p].peak >= VTOUCH_PEAK_THD) palm_touch = 1;
            continue;
        }
        int x = (int)((blobs[p].sc + blobs[p].sw / 2) / blobs[p].sw);
        int y = (int)((blobs[p].sr + blobs[p].sw / 2) / blobs[p].sw);
        if (x < 0) x = 0;
        if (x >= VTOUCH_LONG_MAX) x = VTOUCH_LONG_MAX - 1;
        if (y < 0) y = 0;
        if (y >= VTOUCH_SHORT_MAX) y = VTOUCH_SHORT_MAX - 1;
        x = vtouch_map_edge_axis(x, VTOUCH_LONG_MAX, 0);
        y = vtouch_map_edge_axis(y, VTOUCH_SHORT_MAX, 1);
        found[nfound].slot = -1; found[nfound].tracking_id = 0;
        found[nfound].x = x; found[nfound].y = y;
        found[nfound].peak = blobs[p].peak; found[nfound].area = blobs[p].area;
        ++nfound;
    }

    int match[VTOUCH_SLOTS], used_c[VTOUCH_MAX_PEAKS] = {0};
    vtouch_assign(t, found, nfound, match);
    int matched_any = 0;
    for (int s = 0; s < VTOUCH_SLOTS; ++s) if (match[s] >= 0) { used_c[match[s]] = 1; matched_any = 1; }

    for (int s = 0; s < VTOUCH_SLOTS; ++s) {
        struct VTouchSlot *slot = &t->slots[s];
        if (!slot->active) continue;
        int best = match[s];
        if (best < 0) {
            ++slot->missed;
            if ((matched_any || palm_touch) && slot->age >= 2 && slot->missed <= VTOUCH_HOLD_FRAMES) continue;
            slot->active = 0;
            continue;
        }
        slot->dx = (found[best].x - slot->x) / (slot->missed + 1);
        slot->dy = (found[best].y - slot->y) / (slot->missed + 1);
        slot->missed = 0;
        found[best].slot = s;
        found[best].tracking_id = slot->tracking_id;
        int px = slot->rx, py = slot->ry;
        slot->x = found[best].x; slot->y = found[best].y; ++slot->age;
        vtouch_follow(slot, found[best].x, found[best].y, found[best].peak < VTOUCH_DOWN_THD);
        if (slot->age == 2) { slot->rx = px; slot->ry = py; }
        found[best].x = slot->rx; found[best].y = slot->ry;
    }

    for (int c = 0; c < nfound; ++c) {
        if (used_c[c] || found[c].peak < VTOUCH_DOWN_THD || found[c].area < VTOUCH_MIN_ONSET_AREA) continue;
        for (int s = 0; s < VTOUCH_SLOTS; ++s) {
            if (t->slots[s].active) continue;
            struct VTouchSlot *slot = &t->slots[s];
            slot->active = 1; slot->tracking_id = vtouch_free_id(t); slot->age = 1; slot->missed = 0;
            slot->x = slot->rx = found[c].x; slot->y = slot->ry = found[c].y;
            slot->fx = (long)found[c].x * 16L; slot->fy = (long)found[c].y * 16L;
            slot->vx = slot->vy = 0; slot->dx = slot->dy = 0;
            found[c].slot = s; found[c].tracking_id = slot->tracking_id; used_c[c] = 1;
            break;
        }
    }

    int touching = palm_touch;
    for (int s = 0; s < VTOUCH_SLOTS && !touching; ++s) touching = t->slots[s].active;
    if (touching) {
        t->quiet_frames = 0u;
    } else if (t->quiet_frames < VTOUCH_REF_SETTLE) {
        ++t->quiet_frames;
    } else {
        for (int i = 0; i < VTOUCH_NODES; ++i) {
            int step = delta[i] / VTOUCH_REF_RATE;
            t->reference[i] = (int16_t)(t->reference[i] + (step ? step : (delta[i] > 0 ? 1 : (delta[i] < 0 ? -1 : 0))));
        }
    }

    int count = 0;
    for (int c = 0; c < nfound && count < max_out; ++c) {
        if (found[c].slot < 0 || t->slots[found[c].slot].age < 2) continue;
        out[count++] = found[c];
    }
    for (int s = 0; s < VTOUCH_SLOTS && count < max_out; ++s) {
        const struct VTouchSlot *slot = &t->slots[s];
        if (!slot->active || !slot->missed || slot->age < 2) continue;
        out[count].slot = s; out[count].tracking_id = slot->tracking_id;
        out[count].x = slot->rx; out[count].y = slot->ry;
        out[count].peak = 0; out[count].area = 0;
        ++count;
    }
    return count;
}

/* Normalize (x in 0..31999, y in 0..21359) to HID 0..32767 with runtime orient bitmask:
 *   bit 0: swap x/y, bit 1: flip x, bit 2: flip y */
static inline void vtouch_to_hid_xy(int raw_x, int raw_y, unsigned orient, int *hx, int *hy)
{
    int nx = (int)((long)raw_x * 32767L / (VTOUCH_LONG_MAX - 1));
    int ny = (int)((long)raw_y * 32767L / (VTOUCH_SHORT_MAX - 1));
    if (nx < 0) nx = 0;
    if (nx > 32767) nx = 32767;
    if (ny < 0) ny = 0;
    if (ny > 32767) ny = 32767;
    if (orient & 1u) { int tmp = nx; nx = ny; ny = tmp; }
    if (orient & 2u) nx = 32767 - nx;
    if (orient & 4u) ny = 32767 - ny;
    *hx = nx;
    *hy = ny;
}

#endif /* NVT_TOUCH_TRACKER_H */
