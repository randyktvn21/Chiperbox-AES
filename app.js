(function () {
  "use strict";

  const A = window.AES128;

  const els = {
    mode: document.getElementById("mode"),
    inputFormat: document.getElementById("inputFormat"),
    dataInput: document.getElementById("dataInput"),
    inputLabel: document.getElementById("inputLabel"),
    inputHint: document.getElementById("inputHint"),
    keyInput: document.getElementById("keyInput"),
    runBtn: document.getElementById("runBtn"),
    resetBtn: document.getElementById("resetBtn"),
    toggleDetailBtn: document.getElementById("toggleDetailBtn"),
    loadVectorBtn: document.getElementById("loadVectorBtn"),
    exampleHexBtn: document.getElementById("exampleHexBtn"),
    exampleTextBtn: document.getElementById("exampleTextBtn"),
    message: document.getElementById("message"),
    summary: document.getElementById("summary"),
    visualization: document.getElementById("visualization"),
    roundNav: document.getElementById("roundNav"),
    navCounter: document.getElementById("navCounter"),
    constantTables: document.getElementById("constantTables")
  };

  let detailVisible = true;
  let lastTrace = null;

  function escapeHtml(value) {
    return String(value).replace(/[&<>'"]/g, c => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      "'": "&#39;",
      '"': "&quot;"
    }[c]));
  }

  function showMessage(type, text) {
    els.message.classList.remove("hidden");
    const classes = {
      error: "border-rose-400/35 bg-rose-400/10 text-rose-100",
      success: "border-emerald-400/35 bg-emerald-400/10 text-emerald-100",
      info: "border-amber-300/35 bg-amber-300/10 text-amber-100"
    };
    els.message.className = `mt-5 rounded-2xl border px-4 py-3 text-sm ${classes[type] || classes.info}`;
    els.message.textContent = text;
  }

  function clearMessage() {
    els.message.classList.add("hidden");
    els.message.textContent = "";
  }

  function parseInputBlock() {
    const modeLabel = els.mode.value === "encrypt" ? "Plaintext" : "Ciphertext";
    if (els.inputFormat.value === "hex") return A.hexToBlock(els.dataInput.value, modeLabel);
    return A.textToBlock(els.dataInput.value);
  }

  function parseKey() {
    return A.hexToBlock(els.keyInput.value, "Kunci AES-128");
  }

  function updateInputLabels() {
    const mode = els.mode.value;
    const fmt = els.inputFormat.value;
    els.inputLabel.textContent = mode === "encrypt" ? "Plaintext" : "Ciphertext";

    if (fmt === "hex") {
      els.inputHint.textContent = "Mode hex membutuhkan tepat 32 digit. State dipetakan secara column-major sesuai AES: s[r,c] = input[r + 4c].";
      els.dataInput.placeholder = mode === "encrypt"
        ? "Contoh plaintext hex: 4c6f636b426f78204145533132382121"
        : "Contoh ciphertext hex: gunakan hasil enkripsi Chiperbox sepanjang 16 byte";
    } else {
      els.inputHint.textContent = "Mode teks diproses sebagai byte UTF-8. Jika kurang dari 16 byte, block dipadatkan dengan 00. Jika lebih dari 16 byte, input ditolak.";
      els.dataInput.placeholder = mode === "encrypt"
        ? "Contoh plaintext teks: Box Vault 2026"
        : "Dekripsi mode teks tetap memerlukan ciphertext yang berasal dari 16 byte block.";
    }
  }

  function boxCellClass(kind, before, after, r, c) {
    const diff = before && before[r][c] !== after[r][c] ? " cell-diff" : "";
    const map = {
      base: "cell-base",
      subbytes: "cell-subbytes",
      shiftrows: "cell-shiftrows",
      mixcolumns: "cell-mixcolumns",
      key: "cell-key",
      output: "cell-output"
    };
    return `${map[kind] || map.base}${diff}`;
  }

  function renderBox(state, options = {}) {
    const kind = options.kind || "base";
    const before = options.before || null;
    const title = options.title || "";
    const caption = options.caption || "";
    let html = `<div class="box-wrap">`;
    if (title) html += `<div class="mb-2 text-xs font-black uppercase tracking-wider text-slate-300">${escapeHtml(title)}</div>`;
    html += `<table class="box-table" aria-label="${escapeHtml(title || "State Box")}"><thead><tr><th></th><th>c0</th><th>c1</th><th>c2</th><th>c3</th></tr></thead><tbody>`;
    for (let r = 0; r < 4; r++) {
      html += `<tr><th>r${r}</th>`;
      for (let c = 0; c < 4; c++) {
        html += `<td class="${boxCellClass(kind, before, state, r, c)}">${A.hx(state[r][c])}</td>`;
      }
      html += `</tr>`;
    }
    html += `</tbody></table>`;
    if (caption) html += `<p class="mt-2 text-xs leading-5 text-slate-400">${escapeHtml(caption)}</p>`;
    html += `</div>`;
    return html;
  }

  function renderOperationStep(step, index) {
    const keyBox = step.key ? renderBox(step.key, { kind: "key", title: "Round Key" }) : "";
    const beforeBox = step.before ? renderBox(step.before, { kind: "base", title: "Before" }) : "";
    const afterBox = renderBox(step.after, {
      kind: step.kind,
      before: step.before,
      title: step.before ? "After" : "State",
      caption: step.note || ""
    });

    return `
      <article class="rounded-2xl border border-white/10 bg-white/[0.03] p-4">
        <div class="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <div class="operation-chip">STEP ${index + 1}</div>
            <h4 class="mt-2 text-base font-black text-slate-100">${escapeHtml(step.name)}</h4>
          </div>
          ${step.formula ? `<div class="detail-only formula-box max-w-full sm:max-w-[26rem]">${escapeHtml(step.formula)}</div>` : ""}
        </div>
        <div class="mt-4 grid gap-4" style="grid-template-columns: repeat(auto-fit, minmax(16rem, 1fr));">
          ${beforeBox}
          ${keyBox}
          ${afterBox}
        </div>
      </article>`;
  }

  function renderSection(section, index, open = false) {
    return `
      <details id="${section.id}" class="glass rounded-[1.75rem] p-0" ${open ? "open" : ""}>
        <summary class="flex cursor-pointer items-center justify-between gap-4 p-5 sm:p-6">
          <div>
            <div class="text-xs font-black uppercase tracking-[0.18em] text-amber-200">Bagian ${index + 1}</div>
            <h3 class="mt-1 text-xl font-black">${escapeHtml(section.title)}</h3>
            <p class="mt-1 text-sm leading-6 text-slate-400">${escapeHtml(section.subtitle || "")}</p>
          </div>
          <span class="chevron rounded-full border border-white/10 px-3 py-2 text-slate-300">›</span>
        </summary>
        <div class="border-t border-white/10 p-5 sm:p-6">
          <div class="space-y-4">${section.steps.map(renderOperationStep).join("")}</div>
        </div>
      </details>`;
  }

  function renderKeyExpansion(exp) {
    const initialKeyState = A.bytesToState(exp.roundKeys[0]);
    const gRows = exp.details.filter(d => d.type === "g").map(d => `
      <tr class="border-t border-white/10">
        <td class="px-3 py-2 font-mono text-slate-100">W[${d.i}]</td>
        <td class="px-3 py-2 font-mono">${A.wordToHex(d.tempInput)}</td>
        <td class="px-3 py-2 font-mono">${A.wordToHex(d.rotWord)}</td>
        <td class="px-3 py-2 font-mono">${A.wordToHex(d.subWord)}</td>
        <td class="px-3 py-2 font-mono">${A.wordToHex(d.rcon)}</td>
        <td class="px-3 py-2 font-mono">${A.wordToHex(d.gOutput)}</td>
        <td class="px-3 py-2 font-mono text-amber-100">${A.wordToHex(d.result)}</td>
      </tr>`).join("");

    const wordCards = exp.words.map((w, i) => `
      <div class="word-card"><b>W[${i}]</b><br><span>${A.wordToHex(w)}</span></div>`).join("");

    const roundKeyCards = exp.roundKeys.map((rk, i) => `
      <details class="rounded-2xl border border-white/10 bg-white/[0.03] p-4" ${i === 0 ? "open" : ""}>
        <summary class="flex cursor-pointer items-center justify-between gap-3">
          <div class="font-black">RK${i}</div>
          <div class="font-mono text-xs text-slate-400">${A.bytesToHex(rk)}</div>
        </summary>
        <div class="mt-4">${renderBox(A.bytesToState(rk), { kind: "key", title: `Round Key ${i}` })}</div>
      </details>`).join("");

    return `
      <details id="key-expansion" class="glass rounded-[1.75rem]" open>
        <summary class="flex cursor-pointer items-center justify-between gap-4 p-5 sm:p-6">
          <div>
            <div class="text-xs font-black uppercase tracking-[0.18em] text-fuchsia-300">Key Expansion Box</div>
            <h3 class="mt-1 text-xl font-black">Pembentukan Kunci Ronde</h3>
            <p class="mt-1 text-sm leading-6 text-slate-400">Menelusuri W[0] sampai W[43], fungsi g, Rcon, dan Round Key RK0 sampai RK10.</p>
          </div>
          <span class="chevron rounded-full border border-white/10 px-3 py-2 text-slate-300">›</span>
        </summary>
        <div class="space-y-6 border-t border-white/10 p-5 sm:p-6">
          <div class="grid gap-4 lg:grid-cols-2">
            ${renderBox(initialKeyState, { kind: "key", title: "State Awal Kunci" })}
            <div class="formula-box detail-only">
              AES-128 memakai Nk=4, Nb=4, Nr=10. Total word yang dibangkitkan adalah Nb*(Nr+1)=44 word. Untuk i kelipatan Nk, temp = SubWord(RotWord(W[i-1])) XOR Rcon[i/Nk]. Selain itu, W[i] = W[i-4] XOR W[i-1].
            </div>
          </div>
          <section class="detail-only">
            <h4 class="mb-3 font-black">Detail fungsi g pada W[4], W[8], ..., W[40]</h4>
            <div class="overflow-x-auto rounded-2xl border border-white/10">
              <table class="min-w-[58rem] w-full text-left text-xs text-slate-300">
                <thead class="bg-white/[0.04] text-slate-100">
                  <tr>
                    <th class="px-3 py-2">Word</th>
                    <th class="px-3 py-2">Temp</th>
                    <th class="px-3 py-2">RotWord</th>
                    <th class="px-3 py-2">SubWord</th>
                    <th class="px-3 py-2">Rcon</th>
                    <th class="px-3 py-2">g(temp)</th>
                    <th class="px-3 py-2">Result</th>
                  </tr>
                </thead>
                <tbody>${gRows}</tbody>
              </table>
            </div>
          </section>
          <section class="detail-only">
            <h4 class="mb-3 font-black">Semua Word W[0] - W[43]</h4>
            <div class="word-grid">${wordCards}</div>
          </section>
          <section>
            <h4 class="mb-3 font-black">Round Key RK0 - RK10</h4>
            <div class="grid gap-3 lg:grid-cols-2">${roundKeyCards}</div>
          </section>
        </div>
      </details>`;
  }

  function renderSummary(trace) {
    const action = trace.mode === "encrypt" ? "Ciphertext" : "Plaintext";
    const readable = trace.mode === "decrypt" ? `<p class="mt-2 text-sm leading-6 text-slate-300"><span class="font-bold text-slate-100">Plaintext UTF-8:</span> ${escapeHtml(trace.outputText || "[tidak dapat dibaca sebagai teks biasa]")}</p>` : "";
    return `
      <div class="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div>
          <div class="details-tag">Hasil Akhir Box</div>
          <h2 class="mt-3 text-2xl font-black">${action}</h2>
          <p class="mt-2 break-all font-mono text-sm leading-6 text-amber-100">${trace.outputHex}</p>
          ${readable}
        </div>
        <button id="copyBtn" class="btn-primary shrink-0">Salin Output</button>
      </div>
      <div class="mt-5 grid gap-3 text-xs text-slate-300 sm:grid-cols-3">
        <div class="info-card"><b class="text-slate-100">Block</b><br>128-bit / 16 byte</div>
        <div class="info-card"><b class="text-slate-100">Key</b><br>128-bit / 16 byte</div>
        <div class="info-card"><b class="text-slate-100">Round</b><br>10 ronde + pre-round</div>
      </div>`;
  }

  function renderNav(trace) {
    const items = [
      { id: "key-expansion", label: "Key Expansion Box" },
      ...trace.sections.map(s => ({ id: s.id, label: s.title })),
      { id: "reference", label: "Referensi Konstanta" }
    ];
    els.roundNav.innerHTML = items.map(item => `<a class="nav-link" href="#${item.id}">${escapeHtml(item.label)}</a>`).join("");
    els.navCounter.textContent = String(items.length);
  }

  function renderAll(trace) {
    lastTrace = trace;
    els.summary.innerHTML = renderSummary(trace);
    els.summary.classList.remove("hidden");
    els.visualization.innerHTML = renderKeyExpansion(trace.keySchedule) + trace.sections.map((s, i) => renderSection(s, i, i === 0)).join("");
    renderNav(trace);
    document.body.classList.toggle("hide-detail", !detailVisible);

    const copyBtn = document.getElementById("copyBtn");
    copyBtn.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(trace.outputHex);
        showMessage("success", "Output hex berhasil masuk ke clipboard.");
      } catch (_) {
        showMessage("info", "Clipboard tidak tersedia di browser ini. Salin manual nilai hex yang tampil.");
      }
    });

    requestAnimationFrame(updateActiveNav);
  }

  function renderEmptyState() {
    els.summary.classList.add("hidden");
    els.summary.innerHTML = "";
    els.visualization.innerHTML = `
      <section class="empty-state">
        <div class="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
          <div class="max-w-3xl">
            <div class="details-tag">Box Standby</div>
            <h2 class="mt-3 text-2xl font-black text-white">Masukkan data untuk membuka simulasi Chiperbox AES-128</h2>
            <p class="mt-3 details-note">
              Isi data manual, gunakan sampel Chiperbox, atau muat vector standar AES. Setelah diproses, halaman akan menampilkan Key Expansion, perubahan State Box setiap ronde, dan output akhir dalam format heksadesimal.
            </p>
          </div>
          <div class="grid w-full max-w-md gap-3 text-sm text-slate-300">
            <div class="info-card">
              <div class="info-card-label">Sampel Hex</div>
              <div class="info-card-value font-mono text-sm">4c6f636b426f78204145533132382121</div>
            </div>
            <div class="info-card">
              <div class="info-card-label">Kunci Sampel</div>
              <div class="info-card-value font-mono text-sm">31415926535897932384626433832795</div>
            </div>
            <div class="info-card">
              <div class="info-card-label">Sampel Teks</div>
              <div class="info-card-value text-sm">Box Vault 2026</div>
            </div>
          </div>
        </div>
      </section>`;
    els.roundNav.innerHTML = `<a class="nav-link active" href="#controls">Box Input</a><a class="nav-link" href="#reference">Referensi Konstanta</a>`;
    els.navCounter.textContent = "2";
  }

  function run() {
    try {
      clearMessage();
      const input = parseInputBlock();
      const key = parseKey();
      const trace = els.mode.value === "encrypt" ? A.encryptBlockTrace(input, key) : A.decryptBlockTrace(input, key);
      renderAll(trace);
      const expected = els.mode.value === "encrypt" ? "Ciphertext" : "Plaintext";
      showMessage("success", `${expected} selesai diproses oleh Chiperbox. Output: ${trace.outputHex}`);
    } catch (err) {
      showMessage("error", err.message || String(err));
    }
  }

  function reset() {
    els.mode.value = "encrypt";
    els.inputFormat.value = "hex";
    els.dataInput.value = "";
    els.keyInput.value = "";
    lastTrace = null;
    clearMessage();
    updateInputLabels();
    renderEmptyState();
  }

  function loadVector() {
    els.mode.value = "encrypt";
    els.inputFormat.value = "hex";
    els.dataInput.value = "00112233445566778899aabbccddeeff";
    els.keyInput.value = "000102030405060708090a0b0c0d0e0f";
    updateInputLabels();
    run();
  }

  function fillExampleHex() {
    els.mode.value = "encrypt";
    els.inputFormat.value = "hex";
    els.dataInput.value = "4c6f636b426f78204145533132382121";
    els.keyInput.value = "31415926535897932384626433832795";
    updateInputLabels();
    showMessage("info", "Sampel hex Chiperbox telah dimuat. Klik 'Proses Box' untuk memulai.");
  }

  function fillExampleText() {
    els.mode.value = "encrypt";
    els.inputFormat.value = "text";
    els.dataInput.value = "Box Vault 2026";
    els.keyInput.value = "27182818284590452353602874713526";
    updateInputLabels();
    showMessage("info", "Sampel teks Chiperbox telah dimuat. Klik 'Proses Box' untuk memulai.");
  }

  function toggleDetail() {
    detailVisible = !detailVisible;
    document.body.classList.toggle("hide-detail", !detailVisible);
    els.toggleDetailBtn.textContent = detailVisible ? "Sembunyikan Detail" : "Tampilkan Detail";
  }

  function renderConstTable(title, array) {
    let html = `<details class="rounded-2xl border border-white/10 bg-white/[0.03] p-4"><summary class="flex cursor-pointer items-center justify-between gap-3"><h3 class="font-black">${escapeHtml(title)}</h3><span class="chevron rounded-full border border-white/10 px-3 py-1 text-slate-300">›</span></summary><div class="const-wrap mt-4"><table class="const-table"><thead><tr><th>x\\y</th>`;
    for (let i = 0; i < 16; i++) html += `<th>${i.toString(16)}</th>`;
    html += `</tr></thead><tbody>`;
    for (let r = 0; r < 16; r++) {
      html += `<tr><th>${r.toString(16)}</th>`;
      for (let c = 0; c < 16; c++) html += `<td class="cell-base">${A.hx(array[r * 16 + c])}</td>`;
      html += `</tr>`;
    }
    html += `</tbody></table></div></details>`;
    return html;
  }

  function renderSmallBox(title, box) {
    let html = `<details class="rounded-2xl border border-white/10 bg-white/[0.03] p-4" open><summary class="flex cursor-pointer items-center justify-between gap-3"><h3 class="font-black">${escapeHtml(title)}</h3><span class="chevron rounded-full border border-white/10 px-3 py-1 text-slate-300">›</span></summary><div class="mt-4 box-wrap"><table class="box-table"><tbody>`;
    for (const row of box) {
      html += `<tr>${row.map(v => `<td class="cell-mixcolumns">${A.hx(v)}</td>`).join("")}</tr>`;
    }
    html += `</tbody></table></div></details>`;
    return html;
  }

  function renderRcon() {
    return `<details class="rounded-2xl border border-white/10 bg-white/[0.03] p-4" open>
      <summary class="flex cursor-pointer items-center justify-between gap-3"><h3 class="font-black">Rcon AES-128</h3><span class="chevron rounded-full border border-white/10 px-3 py-1 text-slate-300">›</span></summary>
      <div class="mt-4 grid gap-2 sm:grid-cols-5 lg:grid-cols-10">
        ${A.RCON.slice(1).map((v, i) => `<div class="rounded-xl border border-white/10 bg-white/[0.03] p-3 text-center font-mono text-xs"><b>Rcon[${i + 1}]</b><br>${A.hx(v)}000000</div>`).join("")}
      </div>
    </details>`;
  }

  function renderConstants() {
    els.constantTables.innerHTML = [
      renderConstTable("S-Box Table", A.SBOX),
      renderConstTable("Inverse S-Box Table", A.INV_SBOX),
      renderRcon(),
      `<div class="grid gap-4 lg:grid-cols-2">${renderSmallBox("MixColumns Box", A.MIX_MATRIX)}${renderSmallBox("InvMixColumns Box", A.INV_MIX_MATRIX)}</div>`
    ].join("");
  }

  function updateActiveNav() {
    const links = Array.from(document.querySelectorAll(".nav-link"));
    if (!links.length) return;
    let active = links[0];
    for (const link of links) {
      const id = link.getAttribute("href").slice(1);
      const el = document.getElementById(id);
      if (!el) continue;
      const rect = el.getBoundingClientRect();
      if (rect.top <= 130) active = link;
    }
    links.forEach(l => l.classList.toggle("active", l === active));
  }

  function bindEvents() {
    els.mode.addEventListener("change", updateInputLabels);
    els.inputFormat.addEventListener("change", updateInputLabels);
    els.runBtn.addEventListener("click", run);
    els.resetBtn.addEventListener("click", reset);
    els.loadVectorBtn.addEventListener("click", loadVector);
    els.exampleHexBtn.addEventListener("click", fillExampleHex);
    els.exampleTextBtn.addEventListener("click", fillExampleText);
    els.toggleDetailBtn.addEventListener("click", toggleDetail);
    window.addEventListener("scroll", updateActiveNav, { passive: true });
  }

  bindEvents();
  updateInputLabels();
  renderConstants();
  reset();
})();
