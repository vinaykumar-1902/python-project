(function () {
  const menuBtn = document.getElementById('menuBtn');
  const sidebar = document.getElementById('sidebar');
  if (menuBtn && sidebar) {
    menuBtn.addEventListener('click', () => sidebar.classList.toggle('open'));
  }

  document.querySelectorAll('a, button').forEach((el) => {
    el.addEventListener('pointerdown', () => el.style.transform = 'scale(.98)');
    el.addEventListener('pointerup', () => el.style.transform = '');
    el.addEventListener('pointerleave', () => el.style.transform = '');
  });
})();

function drawBarChart(canvas, labels, values, options = {}) {
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  canvas.width = rect.width * dpr;
  canvas.height = rect.height * dpr;
  ctx.scale(dpr, dpr);
  const width = rect.width;
  const height = rect.height;
  ctx.clearRect(0, 0, width, height);

  const padding = { top: 20, right: 18, bottom: 42, left: 48 };
  const plotW = width - padding.left - padding.right;
  const plotH = height - padding.top - padding.bottom;
  const max = Math.max(...values, 1);
  const gap = 8;
  const barW = Math.max(8, (plotW / Math.max(values.length, 1)) - gap);

  ctx.strokeStyle = 'rgba(255,255,255,.1)';
  ctx.lineWidth = 1;
  ctx.font = '12px system-ui';
  ctx.fillStyle = 'rgba(238,245,255,.65)';
  for (let i = 0; i <= 4; i++) {
    const y = padding.top + (plotH / 4) * i;
    ctx.beginPath();
    ctx.moveTo(padding.left, y);
    ctx.lineTo(width - padding.right, y);
    ctx.stroke();
    const val = Math.round(max - (max / 4) * i);
    ctx.fillText(String(val), 6, y + 4);
  }

  values.forEach((value, i) => {
    const x = padding.left + i * (barW + gap) + gap / 2;
    const barH = (value / max) * plotH;
    const y = padding.top + plotH - barH;
    const grad = ctx.createLinearGradient(0, y, 0, padding.top + plotH);
    grad.addColorStop(0, 'rgba(103,232,249,.95)');
    grad.addColorStop(1, 'rgba(139,92,246,.9)');
    ctx.fillStyle = grad;
    roundRect(ctx, x, y, barW, barH, 8);
    ctx.fill();

    if (labels.length <= 18 || i % Math.ceil(labels.length / 12) === 0) {
      ctx.save();
      ctx.translate(x + barW / 2, height - 18);
      ctx.rotate(-0.45);
      ctx.fillStyle = 'rgba(238,245,255,.65)';
      ctx.fillText(labels[i] || '', -8, 0);
      ctx.restore();
    }
  });

  if (!values.length) {
    ctx.fillStyle = 'rgba(238,245,255,.55)';
    ctx.textAlign = 'center';
    ctx.fillText('No data yet', width / 2, height / 2);
  }
}

function drawDonutLike(canvas, labels, values) {
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  canvas.width = rect.width * dpr;
  canvas.height = rect.height * dpr;
  ctx.scale(dpr, dpr);
  const width = rect.width;
  const height = rect.height;
  ctx.clearRect(0, 0, width, height);
  const total = values.reduce((a, b) => a + b, 0);
  const cx = Math.min(width * .35, 180);
  const cy = height / 2;
  const radius = Math.min(height * .34, width * .23);
  const palette = ['#67e8f9', '#8b5cf6', '#3ee78d', '#fbbf24', '#fb7185', '#38bdf8', '#a78bfa'];
  let start = -Math.PI / 2;

  if (!total) {
    ctx.strokeStyle = 'rgba(255,255,255,.14)';
    ctx.lineWidth = 28;
    ctx.beginPath(); ctx.arc(cx, cy, radius, 0, Math.PI * 2); ctx.stroke();
    ctx.fillStyle = 'rgba(238,245,255,.55)'; ctx.textAlign = 'center'; ctx.fillText('No data', cx, cy + 4);
    return;
  }

  values.forEach((value, i) => {
    const angle = (value / total) * Math.PI * 2;
    ctx.strokeStyle = palette[i % palette.length];
    ctx.lineWidth = 28;
    ctx.lineCap = 'round';
    ctx.beginPath();
    ctx.arc(cx, cy, radius, start, start + angle - 0.025);
    ctx.stroke();
    start += angle;
  });

  ctx.fillStyle = 'rgba(238,245,255,.95)';
  ctx.font = '800 22px system-ui';
  ctx.textAlign = 'center';
  ctx.fillText('₹' + Math.round(total), cx, cy + 7);

  ctx.textAlign = 'left';
  ctx.font = '13px system-ui';
  labels.forEach((label, i) => {
    const y = 32 + i * 28;
    ctx.fillStyle = palette[i % palette.length];
    roundRect(ctx, width * .62, y - 10, 12, 12, 4); ctx.fill();
    ctx.fillStyle = 'rgba(238,245,255,.76)';
    ctx.fillText(`${label} - ₹${Math.round(values[i])}`, width * .62 + 20, y);
  });
}

function roundRect(ctx, x, y, w, h, r) {
  const radius = Math.min(r, Math.abs(w) / 2, Math.abs(h) / 2);
  ctx.beginPath();
  ctx.moveTo(x + radius, y);
  ctx.arcTo(x + w, y, x + w, y + h, radius);
  ctx.arcTo(x + w, y + h, x, y + h, radius);
  ctx.arcTo(x, y + h, x, y, radius);
  ctx.arcTo(x, y, x + w, y, radius);
  ctx.closePath();
}

window.FinVaultCharts = function () {
  const daily = document.getElementById('dailyChart');
  const cat = document.getElementById('categoryChart');
  const render = () => {
    if (daily) drawBarChart(daily, JSON.parse(daily.dataset.labels || '[]'), JSON.parse(daily.dataset.values || '[]'));
    if (cat) drawDonutLike(cat, JSON.parse(cat.dataset.labels || '[]'), JSON.parse(cat.dataset.values || '[]'));
  };
  render();
  window.addEventListener('resize', render);
};
