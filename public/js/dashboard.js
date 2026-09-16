document.addEventListener('DOMContentLoaded', () => {
  const el = document.getElementById('chartData');
  if (!el || typeof Chart === 'undefined') return;

  const parse = (attr) => { try { return JSON.parse(el.getAttribute(attr)); } catch (e) { return []; } };

  Chart.defaults.color = '#b6bfcc';
  Chart.defaults.borderColor = '#232a36';

  const SEVERITY_COLORS = {
    CRITICAL: '#dc3545', HIGH: '#fd7e14', MEDIUM: '#ffc107', LOW: '#0d6efd', INFO: '#6c757d',
  };

  // Events timeline
  const tl = document.getElementById('timelineChart');
  if (tl) {
    new Chart(tl, {
      type: 'line',
      data: {
        labels: parse('data-timeline-labels'),
        datasets: [{
          label: 'Events',
          data: parse('data-timeline-values'),
          borderColor: '#dc3545',
          backgroundColor: 'rgba(220,53,69,0.15)',
          fill: true,
          tension: 0.3,
        }],
      },
      options: { plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true } } },
    });
  }

  // Alert severity doughnut
  const sev = parse('data-severity');
  const sevEl = document.getElementById('severityChart');
  if (sevEl) {
    new Chart(sevEl, {
      type: 'doughnut',
      data: {
        labels: sev.map((s) => s.severity),
        datasets: [{
          data: sev.map((s) => s.count),
          backgroundColor: sev.map((s) => SEVERITY_COLORS[s.severity] || '#6c757d'),
        }],
      },
      options: { plugins: { legend: { position: 'bottom' } } },
    });
  }

  // Event sources
  const src = parse('data-sources');
  const srcEl = document.getElementById('sourcesChart');
  if (srcEl) {
    new Chart(srcEl, {
      type: 'doughnut',
      data: {
        labels: src.map((s) => s.source),
        datasets: [{ data: src.map((s) => s.count), backgroundColor: ['#0d6efd', '#20c997', '#fd7e14', '#6f42c1', '#6c757d'] }],
      },
      options: { plugins: { legend: { position: 'bottom' } } },
    });
  }

  // Top IPs
  const ips = parse('data-topips');
  const ipsEl = document.getElementById('ipsChart');
  if (ipsEl) {
    new Chart(ipsEl, {
      type: 'bar',
      data: {
        labels: ips.map((i) => i.source_ip),
        datasets: [{ label: 'Alerts', data: ips.map((i) => i.count), backgroundColor: '#dc3545' }],
      },
      options: { indexAxis: 'y', plugins: { legend: { display: false } }, scales: { x: { beginAtZero: true } } },
    });
  }

  // Top rules
  const rules = parse('data-toprules');
  const rulesEl = document.getElementById('rulesChart');
  if (rulesEl) {
    new Chart(rulesEl, {
      type: 'bar',
      data: {
        labels: rules.map((r) => r.rule_name),
        datasets: [{ label: 'Alerts', data: rules.map((r) => r.count), backgroundColor: '#fd7e14' }],
      },
      options: { indexAxis: 'y', plugins: { legend: { display: false } }, scales: { x: { beginAtZero: true } } },
    });
  }
});
