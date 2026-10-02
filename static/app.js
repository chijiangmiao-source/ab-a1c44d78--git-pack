"use strict";

const form = document.getElementById("verify-form");
const b64El = document.getElementById("pack-b64");
const offEl = document.getElementById("offset");
const btn = document.getElementById("submit-btn");
const busyPanel = document.getElementById("busy-panel");
const errPanel = document.getElementById("error-panel");
const errMsg = document.getElementById("error-msg");
const errOff = document.getElementById("error-offset");
const resultPanel = document.getElementById("result-panel");

function hideAllPanels() {
  errPanel.hidden = true;
  errPanel.classList.add("hidden");
  busyPanel.hidden = true;
  busyPanel.classList.add("hidden");
  resultPanel.hidden = true;
  resultPanel.classList.add("hidden");
}

function showError(message, offset, detailOffset) {
  hideAllPanels();
  errMsg.textContent = message || "未知错误";
  let text;
  if (offset === null || offset === undefined) {
    text = "首个失败字节偏移：不可定位";
  } else {
    text =
      `首个失败字节偏移：0x${Number(offset).toString(16)}（十进制 ${offset}，pack 绝对偏移）`;
  }
  if (detailOffset !== null && detailOffset !== undefined) {
    text +=
      `；该对象解压数据内偏移：0x${Number(detailOffset).toString(16)}` +
      `（十进制 ${detailOffset}）`;
  }
  errOff.textContent = text;
  errPanel.hidden = false;
  errPanel.classList.remove("hidden");
}

function hexPreview(hex, maxBytes = 64) {
  // hex 为每字节两字符；超长则截断展示。
  const maxChars = maxBytes * 2;
  if (hex.length <= maxChars) return hex || "（空）";
  return `${hex.slice(0, maxChars)}… 共 ${hex.length / 2} 字节`;
}

function renderChain(offsets, targetOffset) {
  const box = document.getElementById("r-chain");
  box.innerHTML = "";
  offsets.forEach((off, i) => {
    const node = document.createElement("span");
    node.className = "node" + (off === targetOffset ? " target" : "");
    node.textContent =
      (i === offsets.length - 1 ? "🎯 " : "") +
      (i === 0 ? "根 " : "") +
      `0x${off.toString(16)} (${off})`;
    box.appendChild(node);
    if (i < offsets.length - 1) {
      const arrow = document.createElement("span");
      arrow.className = "arrow";
      arrow.textContent = "→";
      box.appendChild(arrow);
    }
  });
}

function renderLayers(layers) {
  const wrap = document.getElementById("r-layers");
  wrap.innerHTML = "";
  if (!layers.length) {
    wrap.innerHTML =
      '<p class="small mono">目标本身即根 blob，无差分层。</p>';
    return;
  }
  layers.forEach((layer, idx) => {
    const sec = document.createElement("div");
    sec.className = "layer-meta";

    const baseOk = layer.base_size_declared === layer.base_size_actual;
    const resOk = layer.result_size_declared === layer.result_size_actual;

    sec.innerHTML = `
      <div><strong>层 ${idx + 1}</strong>：delta
        <span class="mono">0x${layer.delta_offset.toString(16)}</span>
        基于 <span class="mono">0x${layer.base_offset.toString(16)}</span>
        <span class="ok">✔ 长度声明全部一致</span>
      </div>
      <div>源长度 声明 <span class="mono">${layer.base_size_declared}</span>
        / 实际 <span class="mono">${layer.base_size_actual}</span>
        ${baseOk ? "✔" : "✘"}；
        目标长度 声明 <span class="mono">${layer.result_size_declared}</span>
        / 实际 <span class="mono">${layer.result_size_actual}</span>
        ${resOk ? "✔" : "✘"}；
        产物 SHA-1 <span class="mono break">${layer.result_sha1}</span>
      </div>`;
    wrap.appendChild(sec);

    const table = document.createElement("table");
    table.innerHTML = `
      <thead><tr>
        <th>#</th><th>指令</th><th>指令偏移</th><th>源偏移</th>
        <th>长度</th><th>写入位置</th><th>实际字节（hex 证据）</th>
      </tr></thead>`;
    const tbody = document.createElement("tbody");
    layer.steps.forEach((step, i) => {
      const tr = document.createElement("tr");
      const isCopy = step.kind === "copy";
      tr.innerHTML = `
        <td>${i + 1}</td>
        <td>${isCopy ? "复制 COPY" : "插入 INSERT"}</td>
        <td class="mono">0x${step.cmd_offset.toString(16)}</td>
        <td class="mono">${isCopy ? "0x" + step.src_offset.toString(16) : "—"}</td>
        <td class="mono">${step.length}</td>
        <td class="mono">0x${step.dst_offset.toString(16)}</td>
        <td class="hex mono">${hexPreview(step.bytes_hex)}</td>`;
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    wrap.appendChild(table);
  });
}

function showResult(r) {
  hideAllPanels();
  document.getElementById("r-type").textContent = r.target.type;
  document.getElementById("r-offset").textContent =
    `0x${r.target.offset.toString(16)} (${r.target.offset})`;
  document.getElementById("r-length").textContent = String(r.target.inflated_length);
  document.getElementById("r-sha1").textContent = r.target.sha1;
  document.getElementById("r-count").textContent = String(r.object_count);
  document.getElementById("r-packs").textContent = `${r.pack_size} 字节`;
  document.getElementById("r-packsha").textContent = r.pack_sha1;
  document.getElementById("r-root").textContent =
    `根 blob @0x${r.root_blob.offset.toString(16)}：` +
    `头声明 ${r.root_blob.declared_size} 字节，` +
    `实际解压 ${r.root_blob.actual_size} 字节，` +
    `最终复原 ${r.final_length} 字节，最终 SHA-1 ${r.final_sha1}`;
  renderChain(r.base_chain_offsets, r.target.offset);
  renderLayers(r.layers);
  resultPanel.hidden = false;
  resultPanel.classList.remove("hidden");
}

form.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  hideAllPanels();
  const b64 = b64El.value.trim();
  const offset = Number(offEl.value);
  if (!b64) {
    showError("请粘贴 Base64 Pack 数据", null);
    return;
  }
  if (!Number.isInteger(offset) || offset < 0) {
    showError("目标对象偏移必须为非负整数", null);
    return;
  }
  btn.disabled = true;
  busyPanel.hidden = false;
  busyPanel.classList.remove("hidden");
  try {
    const resp = await fetch("/api/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ pack_base64: b64, offset }),
    });
    let data;
    try {
      data = await resp.json();
    } catch (e) {
      showError(`API 返回非 JSON（HTTP ${resp.status}）`, null);
      return;
    }
    if (data.ok) {
      showResult(data);
    } else {
      // 失败时清除旧成功证据（showError 会隐藏结果面板）。
      showError(data.error || "校验失败", data.offset, data.detail_offset);
    }
  } catch (e) {
    showError(`请求 API 失败：${e.message}`, null);
  } finally {
    btn.disabled = false;
  }
});
