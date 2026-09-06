/*
 * Analytics dashboard.
 *
 * Every panel reads the page's own query string, so the date picker is the single
 * control for the whole page and a shared link reproduces exactly what the sender
 * saw. Axis labels come pre-formatted from the server in the admin's selected
 * calendar — the browser never formats a date here, which is what keeps the
 * calendar switcher honest.
 */
(function () {
  'use strict';

  var search = location.search;
  var charts = {};

  // --- theming ------------------------------------------------------------
  // Colors are read from daisyUI's CSS variables rather than hardcoded, so the
  // charts stay legible on a light theme instead of vanishing into the
  // background.
  //
  // daisyUI stores its palette as bare colour *components* with no function
  // around them, and which function they belong to depends on the release:
  // daisyUI 4's earlier builds are HSL ("259 94% 51%"), the current ones OKLCH
  // ("65.69% 0.196 275.75"). Guessing wrong yields an invalid colour that
  // Chart.js silently renders as default grey, which is exactly what happened
  // here. So: try each wrapper, let the browser say which one it accepts, then
  // paint the result and read the pixel back as rgba() — the one syntax
  // Chart.js's own colour parser understands whatever the source format was.
  var probe = document.createElement('canvas');
  probe.width = probe.height = 1;
  var probeCtx = probe.getContext('2d', { willReadFrequently: true });

  function themeColor(name, a, fallback) {
    var raw = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    if (!raw || !probeCtx) return fallback;

    var candidates = raw.indexOf('(') === -1
      ? ['oklch(' + raw + ')', 'hsl(' + raw + ')']
      : [raw];

    for (var i = 0; i < candidates.length; i++) {
      try {
        // An invalid value leaves fillStyle untouched, so a sentinel that no
        // candidate could equal tells us whether the assignment took.
        probeCtx.fillStyle = '#010203';
        probeCtx.fillStyle = candidates[i];
        if (probeCtx.fillStyle === '#010203') continue;

        probeCtx.clearRect(0, 0, 1, 1);
        probeCtx.fillRect(0, 0, 1, 1);
        var px = probeCtx.getImageData(0, 0, 1, 1).data;
        return 'rgba(' + px[0] + ',' + px[1] + ',' + px[2] + ',' + a + ')';
      } catch (e) {
        // Canvas readback can be unavailable; fall through to the next candidate.
      }
    }
    return fallback;
  }

  function alpha(name, a, fallback) {
    return themeColor(name, a, fallback);
  }

  var theme = {
    primary: themeColor('--p', 1, '#3b82f6'),
    primarySoft: themeColor('--p', 0.25, 'rgba(59,130,246,0.25)'),
    success: themeColor('--su', 1, '#22c55e'),
    successSoft: themeColor('--su', 0.25, 'rgba(34,197,94,0.25)'),
    info: themeColor('--in', 1, '#0ea5e9'),
    warning: themeColor('--wa', 1, '#f59e0b'),
    text: themeColor('--bc', 0.7, 'rgba(120,120,120,0.9)'),
    grid: themeColor('--bc', 0.15, 'rgba(120,120,120,0.15)')
  };

  function baseOptions(stacked) {
    return {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      scales: {
        x: {
          stacked: !!stacked,
          ticks: { autoSkip: true, maxTicksLimit: 12, maxRotation: 0, color: theme.text },
          grid: { display: false }
        },
        y: {
          stacked: !!stacked,
          beginAtZero: true,
          ticks: { precision: 0, color: theme.text },
          grid: { color: theme.grid }
        }
      },
      plugins: {
        legend: { rtl: true, labels: { color: theme.text, boxWidth: 12, font: { size: 11 } } },
        tooltip: { rtl: true, textDirection: 'rtl', padding: 10, cornerRadius: 8 }
      }
    };
  }

  // --- fetching -----------------------------------------------------------
  // The admin auth middleware redirects unauthenticated requests to /login, so a
  // 200 carrying HTML means the session expired. Detected explicitly rather than
  // letting JSON.parse fail into an empty panel that looks like "no data".
  function load(path) {
    return fetch(path + search, { credentials: 'same-origin' }).then(function (r) {
      if (r.redirected || (r.headers.get('content-type') || '').indexOf('json') === -1) {
        throw new Error('session');
      }
      if (!r.ok) throw new Error('http ' + r.status);
      return r.json();
    });
  }

  function fail(el, err) {
    if (!el) return;
    el.textContent = err && err.message === 'session'
      ? 'نشست منقضی شده — دوباره وارد شوید'
      : 'خطا در دریافت اطلاعات';
    el.className = 'text-xs text-error py-4 text-center';
  }

  // --- live counters ------------------------------------------------------
  function refreshCounters() {
    var ids = { m5: 'statM5', m30: 'statM30', h24: 'statH24' };
    fetch('/admin/metrics/online-stats', { credentials: 'same-origin' })
      .then(function (r) { return r.ok ? r.json() : Promise.reject(); })
      .then(function (data) {
        Object.keys(ids).forEach(function (k) {
          var el = document.getElementById(ids[k]);
          if (el && typeof data[k] === 'number') el.textContent = data[k].toLocaleString('fa-IR');
        });
      })
      .catch(function () {
        Object.keys(ids).forEach(function (k) {
          var el = document.getElementById(ids[k]);
          if (el) el.textContent = '—';
        });
      });
  }

  // --- KPI row ------------------------------------------------------------
  function renderSummary() {
    load('/admin/metrics/summary').then(function (data) {
      var current = data.current || {};
      document.querySelectorAll('[data-kpi]').forEach(function (el) {
        var key = el.getAttribute('data-kpi');
        var value = current[key];
        if (typeof value !== 'number') { el.textContent = '—'; return; }
        el.textContent = key === 'stickiness'
          ? value.toFixed(1) + '٪'
          : Math.round(value).toLocaleString('fa-IR');
      });

      document.querySelectorAll('[data-delta]').forEach(function (el) {
        var key = el.getAttribute('data-delta');
        var delta = data.delta ? data.delta[key] : null;
        if (!data.compare) { el.textContent = ''; return; }
        // A null delta means the previous period was zero — growth from nothing
        // has no percentage, so say so instead of printing a fake number.
        if (delta === null || delta === undefined) {
          el.textContent = 'دورهٔ قبل: بدون داده';
          el.className = 'text-[11px] opacity-50';
          return;
        }
        var up = delta >= 0;
        el.textContent = (up ? '▲ ' : '▼ ') + Math.abs(delta).toFixed(1) + '٪ نسبت به دورهٔ قبل';
        el.className = 'text-[11px] ' + (up ? 'text-success' : 'text-error');
      });
    }).catch(function () {
      document.querySelectorAll('[data-kpi]').forEach(function (el) { el.textContent = '—'; });
    });
  }

  // --- daily / opens charts ----------------------------------------------
  var dailyType = 'bar';

  function renderDaily() {
    load('/admin/metrics/daily').then(function (data) {
      var points = data.points || [];
      var labels = points.map(function (p) { return p.label; });

      draw('dailyChart', {
        type: dailyType,
        data: {
          labels: labels,
          datasets: [
            {
              label: 'بازگشتی',
              data: points.map(function (p) { return p.returning; }),
              backgroundColor: theme.primarySoft,
              borderColor: theme.primary,
              borderWidth: dailyType === 'line' ? 2 : 0,
              fill: dailyType === 'line',
              tension: 0.3,
              pointRadius: 0
            },
            {
              // new_active, not new: the stack must add up to the bucket's active
              // users, and `new` counts registrations including people who never
              // opened the app. Total signups are in the KPI row instead.
              label: 'تازه‌وارد فعال',
              data: points.map(function (p) { return p.new_active; }),
              backgroundColor: theme.successSoft,
              borderColor: theme.success,
              borderWidth: dailyType === 'line' ? 2 : 0,
              fill: dailyType === 'line',
              tension: 0.3,
              pointRadius: 0
            }
          ]
        },
        // Stacked only as bars: two stacked filled lines read as one shape and
        // hide which series moved.
        options: baseOptions(dailyType === 'bar')
      });

      draw('opensChart', {
        type: 'bar',
        data: {
          labels: labels,
          datasets: [{
            label: 'باز کردن اپ',
            data: points.map(function (p) { return p.opens; }),
            backgroundColor: alpha('--in', 0.5, 'rgba(14,165,233,0.5)'),
            borderColor: theme.info,
            borderWidth: 0
          }]
        },
        options: baseOptions(false)
      });
    }).catch(function (err) { fail(document.getElementById('dailyChart').parentNode, err); });
  }

  function renderOnline() {
    load('/admin/metrics/online-history').then(function (data) {
      var points = data.points || [];
      draw('onlineChart', {
        type: 'line',
        data: {
          labels: points.map(function (p) { return p.label; }),
          datasets: [
            {
              label: 'بیشینه همزمان',
              data: points.map(function (p) { return p.max; }),
              borderColor: theme.success,
              backgroundColor: theme.successSoft,
              borderWidth: 2, tension: 0.3, fill: true, pointRadius: 0
            },
            {
              label: 'میانگین',
              data: points.map(function (p) { return Math.round(p.avg * 10) / 10; }),
              borderColor: theme.warning,
              borderWidth: 2, tension: 0.3, fill: false, pointRadius: 0, borderDash: [4, 4]
            }
          ]
        },
        options: baseOptions(false)
      });
    }).catch(function (err) { fail(document.getElementById('onlineChart').parentNode, err); });
  }

  function draw(id, config) {
    var canvas = document.getElementById(id);
    if (!canvas) return;
    if (charts[id]) charts[id].destroy();
    charts[id] = new Chart(canvas.getContext('2d'), config);
  }

  // --- heatmap ------------------------------------------------------------
  // Built from divs rather than a Chart.js matrix plugin: 168 cells of flat color
  // need no chart engine, and a CSS grid inherits the page's RTL direction for free.
  function renderHeatmap() {
    var host = document.getElementById('heatmap');
    load('/admin/metrics/heatmap').then(function (data) {
      var cells = data.cells || [];
      var max = data.max || 0;
      var names = data.weekdays || [];
      var offset = data.week_start_offset || 0;

      var html = '<div class="grid gap-0.5" style="grid-template-columns: 2.5rem repeat(24, minmax(0.9rem, 1fr));">';
      html += '<div></div>';
      for (var h = 0; h < 24; h++) {
        html += '<div class="text-[9px] opacity-50 text-center">' + (h % 3 === 0 ? h : '') + '</div>';
      }

      for (var row = 0; row < 7; row++) {
        // Rotate so the week opens on the calendar's own first day while the data
        // stays indexed 0=Sunday the way Postgres produced it.
        var dow = (row + offset) % 7;
        html += '<div class="text-[10px] opacity-60 leading-4 pe-1">' + (names[row] || dow) + '</div>';
        for (var hour = 0; hour < 24; hour++) {
          var n = (cells[dow] && cells[dow][hour]) || 0;
          var intensity = max > 0 ? n / max : 0;
          var bg = intensity === 0 ? 'transparent' : alpha('--p', 0.12 + intensity * 0.78, 'rgba(59,130,246,0.5)');
          html += '<div class="h-4 rounded-sm border border-base-300/40" title="' + n +
                  '" style="background:' + bg + '"></div>';
        }
      }
      html += '</div>';
      host.innerHTML = html;
    }).catch(function (err) { fail(host, err); });
  }

  // --- cohorts ------------------------------------------------------------
  function renderCohorts() {
    var table = document.getElementById('cohortTable');
    load('/admin/metrics/cohorts').then(function (data) {
      var rows = data.rows || [];
      var offsets = data.offsets || [];
      if (!rows.length) {
        table.innerHTML = '<tbody><tr><td class="text-xs opacity-60 text-center py-4">داده‌ای نیست</td></tr></tbody>';
        return;
      }

      var html = '<thead><tr><th>هفتهٔ ثبت‌نام</th><th>تعداد</th>';
      offsets.forEach(function (o) {
        html += '<th>' + (o === 0 ? 'همان هفته' : 'هفتهٔ ' + o) + '</th>';
      });
      html += '</tr></thead><tbody>';

      rows.forEach(function (row) {
        html += '<tr><td class="whitespace-nowrap">' + row.week + '</td><td>' + row.size + '</td>';
        row.percent.forEach(function (pct) {
          var bg = pct > 0 ? alpha('--su', 0.1 + (pct / 100) * 0.6, 'rgba(34,197,94,0.4)') : 'transparent';
          html += '<td style="background:' + bg + '">' + (pct > 0 ? pct.toFixed(0) + '٪' : '—') + '</td>';
        });
        html += '</tr>';
      });
      table.innerHTML = html + '</tbody>';
    }).catch(function (err) { fail(table, err); });
  }

  // --- churn risk ---------------------------------------------------------
  function renderAtRisk() {
    var table = document.getElementById('atRiskTable');
    var days = document.getElementById('atRiskDays').value;
    fetch('/admin/metrics/at-risk?days=' + days + '&limit=20', { credentials: 'same-origin' })
      .then(function (r) { return r.ok ? r.json() : Promise.reject(new Error('http')); })
      .then(function (data) {
        var users = data.users || [];
        if (!users.length) {
          table.innerHTML = '<tbody><tr><td class="text-xs opacity-60 text-center py-4">کسی در این بازه غایب نیست</td></tr></tbody>';
          return;
        }
        var html = '<thead><tr><th>کاربر</th><th>آخرین بازدید</th><th>روز غیبت</th></tr></thead><tbody>';
        users.forEach(function (u) {
          html += '<tr><td><a class="link link-hover" href="/admin/users/' + u.id + '">' + u.username + '</a></td>' +
                  '<td class="text-xs opacity-70">' + u.last_seen + '</td>' +
                  '<td><span class="badge badge-warning badge-outline badge-sm">' + u.inactive_days + '</span></td></tr>';
        });
        table.innerHTML = html + '</tbody>';
      })
      .catch(function (err) { fail(table, err); });
  }

  // --- wiring -------------------------------------------------------------
  document.querySelectorAll('[data-chart-type]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      dailyType = btn.getAttribute('data-chart-type');
      document.querySelectorAll('[data-chart-type]').forEach(function (b) { b.classList.remove('btn-active'); });
      btn.classList.add('btn-active');
      renderDaily();
    });
  });

  document.getElementById('atRiskDays').addEventListener('change', renderAtRisk);

  function renderAll() {
    renderSummary();
    renderDaily();
    renderOnline();
    renderHeatmap();
    renderCohorts();
    renderAtRisk();
  }

  document.getElementById('refreshAll').addEventListener('click', function () {
    refreshCounters();
    renderAll();
  });

  refreshCounters();
  renderAll();
  // Only the live counters poll. The range-bound panels are stable until the
  // admin changes the range, and re-fetching them every ten seconds was what made
  // the old page heavy for no gain.
  setInterval(refreshCounters, 10000);
})();
