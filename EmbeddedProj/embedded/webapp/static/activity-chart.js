(() => {
  const chart = document.querySelector("[data-activity-chart]");
  if (!chart) return;

  const status = chart.querySelector("[data-chart-status]");
  const colors = {
    "Successful login": "#4f8cff",
    Logout: "#f3a847",
    "OTP verified": "#21c7a8",
  };
  const names = {
    "Successful login": "Successful logins",
    Logout: "Sign-outs",
    "OTP verified": "OTP verifications",
  };
  const svgNode = (name, attributes = {}, text = "") => {
    const node = document.createElementNS("http://www.w3.org/2000/svg", name);
    Object.entries(attributes).forEach(([key, value]) => node.setAttribute(key, value));
    if (text) node.textContent = text;
    return node;
  };

  function renderDonut(events) {
    const keys = Object.keys(colors);
    const counts = keys.map((key) => Number(events[key]?.count) || 0);
    const total = counts.reduce((sum, value) => sum + value, 0);
    let position = 0;
    const stops = keys.map((key, index) => {
      const next = total ? position + (counts[index] / total) * 100 : position;
      const stop = `${colors[key]} ${position}% ${next}%`;
      position = next;
      return stop;
    });
    const donut = chart.querySelector("[data-donut]");
    donut.style.background = total
      ? `conic-gradient(${stops.join(", ")})`
      : "conic-gradient(#28364b 0% 100%)";
    donut.setAttribute("aria-label", `${total} authentication events: ${keys.map((key, i) => `${names[key]} ${counts[i]}`).join(", ")}`);
    chart.querySelector("[data-total-events]").textContent = total.toLocaleString();

    keys.forEach((key) => {
      const item = chart.querySelector(`[data-legend-event="${key}"]`);
      item.querySelector("b").textContent = counts[keys.indexOf(key)].toLocaleString();
    });
  }

  function renderBars(days) {
    const svg = chart.querySelector("[data-activity-bars]");
    svg.replaceChildren();
    const keys = Object.keys(colors);
    const width = 700;
    const left = 48;
    const right = 14;
    const top = 18;
    const bottom = 42;
    const plotHeight = 160;
    const plotWidth = width - left - right;
    const maximum = Math.max(1, ...days.flatMap((day) => keys.map((key) => Number(day.counts[key]) || 0)));
    const scaleMax = Math.max(4, Math.ceil(maximum / 4) * 4);

    for (let tick = 0; tick <= 4; tick += 1) {
      const value = (scaleMax / 4) * tick;
      const y = top + plotHeight - (value / scaleMax) * plotHeight;
      svg.append(svgNode("line", { x1: left, x2: width - right, y1: y, y2: y, class: "activity-gridline" }));
      svg.append(svgNode("text", { x: left - 9, y: y + 4, "text-anchor": "end", class: "activity-axis-label" }, String(Math.round(value))));
    }

    const step = plotWidth / Math.max(days.length, 1);
    const barWidth = Math.min(17, step * 0.19);
    const barGap = 3;
    const groupWidth = keys.length * barWidth + (keys.length - 1) * barGap;
    days.forEach((day, dayIndex) => {
      const center = left + step * (dayIndex + 0.5);
      keys.forEach((key, seriesIndex) => {
        const value = Number(day.counts[key]) || 0;
        const height = (value / scaleMax) * plotHeight;
        const x = center - groupWidth / 2 + seriesIndex * (barWidth + barGap);
        const y = top + plotHeight - height;
        const rect = svgNode("rect", {
          x,
          y,
          width: barWidth,
          height: Math.max(value ? 2 : 0, height),
          rx: 4,
          fill: colors[key],
          class: "activity-svg-bar",
        });
        rect.append(svgNode("title", {}, `${day.date}: ${names[key]} ${value}`));
        svg.append(rect);
      });
      const date = new Date(`${day.date}T00:00:00Z`);
      const label = new Intl.DateTimeFormat("en-IN", { day: "2-digit", month: "short", timeZone: "UTC" }).format(date);
      svg.append(svgNode("text", {
        x: center,
        y: top + plotHeight + 25,
        "text-anchor": "middle",
        class: "activity-axis-label activity-date-label",
      }, label));
    });
  }

  async function refresh() {
    try {
      const response = await fetch(chart.dataset.endpoint, {
        headers: { Accept: "application/json" },
        cache: "no-store",
        credentials: "same-origin",
      });
      if (!response.ok) throw new Error("Activity refresh failed");
      const snapshot = await response.json();
      renderDonut(snapshot.events || {});
      renderBars(snapshot.days || []);
      if (status) status.textContent = "LIVE | updated just now";
    } catch {
      if (status) status.textContent = "LIVE | reconnecting";
    }
  }

  refresh();
  window.setInterval(refresh, 5000);
})();
