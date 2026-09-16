document.addEventListener('DOMContentLoaded', () => {
  if (typeof io === 'undefined') return; // socket.io client script didn't load, fail quietly

  const socket = io();
  window.socDashboardSocket = socket;

  // ---- Toast notifications (shown on every page) ----
  const toastContainer = document.getElementById('liveToastContainer');

  function showToast(title, body, variant) {
    if (!toastContainer) return;
    const toastEl = document.createElement('div');
    toastEl.className = `toast align-items-center text-bg-${variant || 'danger'} border-0`;
    toastEl.setAttribute('role', 'alert');
    toastEl.innerHTML = `
      <div class="d-flex">
        <div class="toast-body">
          <strong>${title}</strong><br>${body}
        </div>
        <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
      </div>
    `;
    toastContainer.appendChild(toastEl);
    const toast = new bootstrap.Toast(toastEl, { delay: 6000 });
    toast.show();
    toastEl.addEventListener('hidden.bs.toast', () => toastEl.remove());
  }

  const SEVERITY_VARIANT = {
    CRITICAL: 'danger',
    HIGH: 'warning',
    MEDIUM: 'secondary',
    LOW: 'primary',
  };

  socket.on('new_alert', (alert) => {
    showToast(
      `New Alert: ${alert.title}`,
      `${alert.severity} · Risk ${alert.risk_score} · ${alert.source_ip || 'N/A'}`,
      SEVERITY_VARIANT[alert.severity] || 'danger'
    );

    // ---- Live dashboard stat card updates (only present on / ) ----
    const criticalEl = document.getElementById('stat-critical-alerts');
    const highEl = document.getElementById('stat-high-alerts');
    if (alert.severity === 'CRITICAL' && criticalEl) {
      criticalEl.textContent = parseInt(criticalEl.textContent, 10) + 1;
    }
    if (alert.severity === 'HIGH' && highEl) {
      highEl.textContent = parseInt(highEl.textContent, 10) + 1;
    }

    // ---- Live alerts table prepend (only present on /alerts) ----
    const alertsBody = document.getElementById('alertsTableBody');
    if (alertsBody) {
      const badgeClass = {
        CRITICAL: 'badge-critical',
        HIGH: 'badge-high',
        MEDIUM: 'badge-medium',
        LOW: 'badge-low',
      }[alert.severity] || 'badge-info';

      const row = document.createElement('tr');
      row.style.cursor = 'pointer';
      row.className = 'table-active';
      row.onclick = () => { window.location = `/alerts/${alert.id}`; };
      row.innerHTML = `
        <td class="small text-secondary">#${alert.id}</td>
        <td class="small">${alert.title}</td>
        <td><span class="badge ${badgeClass}">${alert.severity}</span></td>
        <td class="small fw-bold">${alert.risk_score}</td>
        <td class="small">${alert.source_ip || '—'}</td>
        <td class="small">${alert.hostname || '—'}</td>
        <td class="small">${alert.rule_name}</td>
        <td class="small">${alert.mitre_id || '—'}</td>
        <td><span class="badge bg-secondary">${alert.status}</span></td>
        <td class="small text-secondary">just now</td>
      `;
      const emptyRow = alertsBody.querySelector('td[colspan]');
      if (emptyRow) emptyRow.closest('tr').remove();
      alertsBody.prepend(row);
    }
  });

  socket.on('new_log', (log) => {
    // ---- Live event counter on dashboard ----
    const totalEl = document.getElementById('stat-total-events');
    if (totalEl) {
      totalEl.textContent = parseInt(totalEl.textContent, 10) + 1;
    }

    // ---- Live logs table prepend (only present on /logs) ----
    const logsBody = document.getElementById('logsTableBody');
    if (logsBody) {
      const badgeClass = {
        CRITICAL: 'badge-critical',
        HIGH: 'badge-high',
        MEDIUM: 'badge-medium',
        LOW: 'badge-low',
        INFO: 'badge-info',
      }[log.severity] || 'badge-info';

      const row = document.createElement('tr');
      row.className = 'table-active';
      row.innerHTML = `
        <td class="small text-secondary">just now</td>
        <td>${log.source}</td>
        <td class="small">${log.event_type}</td>
        <td><span class="badge ${badgeClass}">${log.severity}</span></td>
        <td class="small">${log.username || '—'}</td>
        <td class="small">${log.source_ip || '—'}</td>
        <td class="small">${log.hostname || '—'}</td>
        <td class="small" style="max-width: 320px;">${log.message}</td>
      `;
      const emptyRow = logsBody.querySelector('td[colspan]');
      if (emptyRow) emptyRow.closest('tr').remove();
      logsBody.prepend(row);
    }
  });

  socket.on('data_cleared', () => {
    const alertsBody = document.getElementById('alertsTableBody');
    const logsBody = document.getElementById('logsTableBody');
    if (alertsBody || logsBody) {
      showToast('Data Cleared', 'All simulated logs and alerts were cleared. Refresh to see the empty state.', 'secondary');
    }
  });
});
