(() => {
  "use strict";

  // ----------------------------
  // DOM
  // ----------------------------
  const el = (id) => document.getElementById(id);

  const dropzone = el("dropzone");
  const fileInput = el("fileInput");
  const dzMeta = el("dzMeta");

  const tokenInput = el("tokenInput");
  const mfaInput = el("mfaInput");
  const toggleToken = el("toggleToken");

  const btnSign = el("btnSign");
  const btnVerify = el("btnVerify");
  const btnDownload = el("btnDownload");
  const btnReset = el("btnReset");
  const btnCopyOutput = el("btnCopyOutput");

  const statusPill = el("statusPill");
  const statusLabel = el("statusLabel");

  const sessionBox = el("sessionBox");

  const apkEmpty = el("apkEmpty");
  const apkInfo = el("apkInfo");
  const apkTitle = el("apkTitle");
  const apkTags = el("apkTags");
  const apkSha = el("apkSha");
  const apkSize = el("apkSize");
  const apkPermsPreview = el("apkPermsPreview");

  const btnPerms = el("btnPerms");
  const btnPermsInline = el("btnPermsInline");

  const output = el("output");
  const debugBox = el("debugBox");

  const modalPerms = el("modalPerms");
  const permsFull = el("permsFull");
  const btnCopyPerms = el("btnCopyPerms");

  const btnOpenLogs = el("btnOpenLogs");
  const modalLogs = el("modalLogs");
  const btnRefreshLogs = el("btnRefreshLogs");
  const logsTbody = el("logsTbody");
  const systemNotice = el("systemNotice");

  // ----------------------------
  // State
  // ----------------------------
  let currentSessionId = "";
  let currentOriginalName = "";
  let currentSignedName = "";
  let currentPerms = [];
  let busy = false;
  let lastInspectSig = ""; // evita doble POST por el mismo fichero

  // ----------------------------
  // Debug + output
  // ----------------------------
  function ts() {
    return new Date().toISOString();
  }

  function dbg(msg, obj) {
    const line = `[${ts()}] ${msg}` + (obj ? ` ${safeJson(obj)}` : "");
    console.log(line);
    debugBox.textContent = (line + "\n" + debugBox.textContent).slice(0, 8000);
  }

  function safeJson(o) {
    try { return JSON.stringify(o); } catch { return String(o); }
  }

  function setOutput(text, append = false) {
    if (append) output.textContent += text;
    else output.textContent = text;
  }

  function setStatus(state, text) {
    statusPill.setAttribute("data-state", state);
    statusLabel.textContent = text;
  }

  function setBusy(v) {
    busy = v;
    if (v) setStatus("busy", "Procesando");
  }

  // ----------------------------
  // Clipboard helper
  // ----------------------------
  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      try {
        const ta = document.createElement("textarea");
        ta.value = text;
        ta.setAttribute("readonly", "");
        ta.style.position = "fixed";
        ta.style.left = "-9999px";
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
        return true;
      } catch {
        return false;
      }
    }
  }

  // ----------------------------
  // Fetch helper with better diagnostics
  // ----------------------------
  async function apiFetch(url, opts = {}, timeoutMs = 120000) {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(url, {
        credentials: "same-origin",
        cache: "no-store",
        signal: controller.signal,
        ...opts,
      });

      const ct = res.headers.get("content-type") || "";
      let bodyText = "";
      let json = null;

      if (ct.includes("application/json")) {
        json = await res.json();
      } else {
        bodyText = await res.text();
      }

      if (!res.ok) {
        const msg = json?.error || bodyText || `HTTP ${res.status}`;
        const err = new Error(msg);
        err.status = res.status;
        err.payload = json || bodyText;
        throw err;
      }

      return json ?? bodyText;
    } finally {
      clearTimeout(t);
    }
  }

  async function healthzDebug() {
    try {
      const j = await apiFetch("/healthz", { method: "GET" }, 15000);
      dbg("HEALTHZ", j);
    } catch (e) {
      dbg("HEALTHZ error", { message: e.message, status: e.status || "" });
    }
    dbg("navigator.onLine", navigator.onLine);
  }

  async function updateSystemNotice() {
    if (!systemNotice) return;
    try {
      const j = await apiFetch("/healthz", { method: "GET" }, 15000);
      const checks = j.checks || {};
      const warnings = [];
      if (!checks.secrets_exists) warnings.push("Falta secrets.json");
      if (checks.secrets_error) warnings.push(checks.secrets_error);
      if (!checks.keystore_exists) warnings.push("Falta KeyStore.jks");
      if (warnings.length) {
        systemNotice.textContent = `Atención: ${warnings.join(". ")}. Actualiza los ficheros y reinicia el servicio.`;
        systemNotice.classList.remove("hidden");
      } else {
        systemNotice.classList.add("hidden");
      }
    } catch {
      systemNotice.textContent = "Atención: no se puede validar el estado del servicio.";
      systemNotice.classList.remove("hidden");
    }
  }

  // ----------------------------
  // UI helpers
  // ----------------------------
  function bytesHuman(n) {
    const u = ["B", "KB", "MB", "GB"];
    let i = 0;
    let x = Number(n) || 0;
    while (x >= 1024 && i < u.length - 1) { x /= 1024; i++; }
    return `${x.toFixed(i === 0 ? 0 : 1)} ${u[i]}`;
  }

  function setApkInfoVisible(v) {
    apkEmpty.classList.toggle("hidden", v);
    apkInfo.classList.toggle("hidden", !v);
  }

  function resetUi() {
    currentSessionId = "";
    currentOriginalName = "";
    currentSignedName = "";
    currentPerms = [];
    lastInspectSig = "";

    dzMeta.textContent = "Ningún archivo seleccionado";
    sessionBox.textContent = "—";

    setApkInfoVisible(false);
    apkTitle.textContent = "—";
    apkTags.innerHTML = "";
    apkSha.textContent = "—";
    apkSize.textContent = "—";
    apkPermsPreview.textContent = "—";
    permsFull.textContent = "";

    btnSign.disabled = true;
    btnVerify.disabled = true;
    btnDownload.disabled = true;
    btnPerms.disabled = true;

    setStatus("idle", "Listo");
    setOutput("");
    dbg("RESET");
  }

  function enableActionsAfterInspect() {
    btnSign.disabled = false;
    btnVerify.disabled = true;
    btnDownload.disabled = true;
  }

  function enableAfterSign() {
    btnVerify.disabled = false;
    btnDownload.disabled = false; // acordado: tras firma correcta
  }

  // ----------------------------
  // Inspect
  // ----------------------------
  async function inspectFile(file) {
    if (busy) return;
    if (!file) return;

    const name = file.name || "input.apk";
    const size = file.size || 0;

    // evita doble inspección del mismo fichero si el navegador dispara dos eventos seguidos
    const sig = `${name}:${size}:${file.lastModified || 0}`;
    if (sig === lastInspectSig) {
      dbg("INSPECT skip duplicate", { name, size });
      return;
    }
    lastInspectSig = sig;

    if (!name.toLowerCase().endsWith(".apk")) {
      setStatus("bad", "Error");
      setOutput("El fichero debe ser .apk");
      return;
    }

    setBusy(true);
    setStatus("busy", "Inspeccionando");
    dbg("INSPECT request", { url: "/inspect", name, size });

    const fd = new FormData();
    fd.append("apk", file, name);

    try {
      const j = await apiFetch("/inspect", { method: "POST", body: fd }, 180000);
      dbg("INSPECT response", j);

      if (!j.ok) {
        setStatus("bad", "Error");
        setOutput(`Fallo al inspeccionar: ${j.error || "Error desconocido"}`);
        await healthzDebug();
        setBusy(false);
        return;
      }

      currentSessionId = j.sessionId;
      currentOriginalName = j.originalName || name;
      sessionBox.textContent = currentSessionId;

      dzMeta.textContent = `${currentOriginalName} (${bytesHuman(j.sizeBytes)})`;

      const info = j.apkInfo || {};
      const label = info.appLabel || currentOriginalName;
      apkTitle.textContent = label;

      apkSha.textContent = j.sha256 || "—";
      apkSize.textContent = bytesHuman(j.sizeBytes || size);

      apkTags.innerHTML = "";
      const tags = Array.isArray(info.tags) ? info.tags : [];
      for (const t of tags) {
        const div = document.createElement("div");
        div.className = "tag";
        div.innerHTML = `<span class="k">${escapeHtml(t.k || "")}:</span><span class="v">${escapeHtml(String(t.v || ""))}</span>`;
        apkTags.appendChild(div);
      }

      currentPerms = Array.isArray(info.permissions) ? info.permissions : [];
      permsFull.textContent = currentPerms.join("\n") || "(sin permisos declarados)";

      const preview = currentPerms.slice(0, 6).join(", ");
      apkPermsPreview.textContent = currentPerms.length
        ? `${preview}${currentPerms.length > 6 ? " …" : ""}`
        : "(sin permisos declarados)";

      setApkInfoVisible(true);
      btnPerms.disabled = false;

      setStatus("ok", "Inspección OK");
      setOutput(`Inspección OK\n- Archivo: ${currentOriginalName}\n- SHA-256: ${j.sha256}\n- Tamaño: ${bytesHuman(j.sizeBytes)}\n`);
      enableActionsAfterInspect();
    } catch (e) {
      dbg("INSPECT error", { message: e.message, status: e.status || "" });
      setStatus("bad", "Error");
      setOutput(`Fallo al inspeccionar: ${e.message || "Failed to fetch"}`);
      await healthzDebug();
    } finally {
      setBusy(false);
    }
  }

  // ----------------------------
  // Sign / Verify / Download
  // ----------------------------
  async function sign() {
    if (busy) return;
    if (!currentSessionId) return;

    const userToken = (tokenInput.value || "").trim();
    const mfaCode = (mfaInput.value || "").trim();
    if (!userToken || !mfaCode) {
      setStatus("warn", "MFA requerido");
      setOutput("Introduce el token y el código MFA antes de firmar.");
      return;
    }

    setBusy(true);
    setStatus("busy", "Firmando");
    setOutput("Firmando...\n");
    dbg("SIGN request", { sessionId: currentSessionId });

    try {
      const j = await apiFetch("/sign", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sessionId: currentSessionId, userToken, mfaCode }),
      }, 240000);

      dbg("SIGN response", j);

      if (!j.ok) {
        setStatus("bad", "Error");
        setOutput(`Error firmando: ${j.error || "Desconocido"}\n${j.stderr || ""}\n${j.stdout || ""}`);
        await healthzDebug();
        return;
      }

      currentSignedName = j.signedName || "";
      setStatus("ok", "Firma correcta");
      setOutput(`Firma correcta\n${(j.stdout || "").trim()}\n${(j.stderr || "").trim()}`.trim() + "\n");

      enableAfterSign();
    } catch (e) {
      dbg("SIGN error", { message: e.message, status: e.status || "" });
      setStatus("bad", "Error");
      setOutput(`Error firmando: ${e.message || "Failed to fetch"}`);
      await healthzDebug();
    } finally {
      setBusy(false);
    }
  }

  async function verify() {
    if (busy) return;
    if (!currentSessionId) return;

    setBusy(true);
    setStatus("busy", "Verificando");
    setOutput("Verificando...\n", false);
    dbg("VERIFY request", { sessionId: currentSessionId });

    try {
      const j = await apiFetch("/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sessionId: currentSessionId }),
      }, 240000);

      dbg("VERIFY response", j);

      if (!j.ok) {
        setStatus("bad", "Error");
        setOutput(`Verificación fallida: ${j.error || "Desconocido"}\n${j.stderr || ""}\n${j.stdout || ""}`);
        return;
      }

      setStatus("ok", "Verificación correcta");
      setOutput(`Verificación correcta\n${(j.stdout || "").trim()}\n${(j.stderr || "").trim()}`.trim() + "\n");
    } catch (e) {
      dbg("VERIFY error", { message: e.message, status: e.status || "" });
      setStatus("bad", "Error");
      setOutput(`Error verificando: ${e.message || "Failed to fetch"}`);
      await healthzDebug();
    } finally {
      setBusy(false);
    }
  }

  function downloadSigned() {
    if (!currentSessionId) return;
    const url = `/download/${encodeURIComponent(currentSessionId)}`;
    dbg("DOWNLOAD", { url });
    window.location.href = url;
  }

  // ----------------------------
  // Logs modal
  // ----------------------------
  function openModal(modal) { modal.classList.remove("hidden"); }
  function closeModal(modal) { modal.classList.add("hidden"); }

  async function loadLogs() {
    dbg("LOGS load");
    logsTbody.innerHTML = "";
    try {
      const j = await apiFetch("/logs/data?limit=200", { method: "GET" }, 20000);
      if (!j.ok) throw new Error("No ok");

      for (const evt of (j.events || [])) {
        const tr = document.createElement("tr");

        const dt = (evt.ts || "").replace("T", " ").replace("Z", " UTC");
        const action = evt.action || "";
        const ok = !!evt.ok;
        const fname = evt.filename || evt.signedName || "";
        const integrity = evt._integrity || "—";
        const ip = evt.ip || "";
        const userName = evt.userName || "";
        const userId = evt.userId || "";
        const userLabel = userName ? `${userName}${userId ? ` (${userId})` : ""}` : (userId || "—");

        tr.innerHTML = `
          <td class="mono">${escapeHtml(dt)}</td>
          <td>${escapeHtml(action)}</td>
          <td>${escapeHtml(userLabel)}</td>
          <td>${badge(ok ? "OK" : "KO", ok ? "ok" : "bad")}</td>
          <td class="mono">${escapeHtml(fname)}</td>
          <td>${badge(integrity, integrityClass(integrity))}</td>
          <td class="mono">${escapeHtml(ip)}</td>
        `;
        logsTbody.appendChild(tr);
      }

    } catch (e) {
      dbg("LOGS error", { message: e.message });
      const tr = document.createElement("tr");
      tr.innerHTML = `<td colspan="7">No se pueden cargar logs: ${escapeHtml(e.message || "")}</td>`;
      logsTbody.appendChild(tr);
      await healthzDebug();
    }
  }

  function integrityClass(s) {
    const v = String(s || "").toLowerCase();
    if (v === "ok") return "ok";
    if (v.includes("sin mac") || v.includes("sin clave")) return "warn";
    return "bad";
  }

  function badge(text, cls) {
    const c = cls === "ok" ? "badge-ok" : cls === "warn" ? "badge-warn" : "badge-bad";
    return `<span class="badge ${c}">${escapeHtml(text)}</span>`;
  }

  // ----------------------------
  // Events
  // ----------------------------
  // Dropzone click opens file picker
  dropzone.addEventListener("click", () => fileInput.click());
  dropzone.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") fileInput.click();
  });

  // Drag & drop
  ["dragenter", "dragover"].forEach((ev) => {
    dropzone.addEventListener(ev, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.add("dragover");
    });
  });
  ["dragleave", "drop"].forEach((ev) => {
    dropzone.addEventListener(ev, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.remove("dragover");
    });
  });
  dropzone.addEventListener("drop", (e) => {
    const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
    if (f) inspectFile(f);
  });

  // File input
  fileInput.addEventListener("change", (e) => {
    const f = e.target.files && e.target.files[0];
    if (f) inspectFile(f);
    // reset value to allow selecting the same file again without quirks
    fileInput.value = "";
  });

  // Token eye toggle
  toggleToken.addEventListener("click", () => {
    const isPw = tokenInput.getAttribute("type") === "password";
    tokenInput.setAttribute("type", isPw ? "text" : "password");
  });

  btnSign.addEventListener("click", sign);
  btnVerify.addEventListener("click", verify);
  btnDownload.addEventListener("click", downloadSigned);

  btnReset.addEventListener("click", () => {
    tokenInput.value = "";
    mfaInput.value = "";
    resetUi();
  });

  btnCopyOutput.addEventListener("click", async () => {
    const ok = await copyText(output.textContent || "");
    setStatus(ok ? "ok" : "warn", ok ? "Copiado" : "No se pudo copiar");
  });

  // Perms modal openers
  function openPerms() {
    permsFull.textContent = (currentPerms && currentPerms.length)
      ? currentPerms.join("\n")
      : "(sin permisos declarados)";
    openModal(modalPerms);
  }
  btnPerms.addEventListener("click", openPerms);
  btnPermsInline.addEventListener("click", openPerms);

  btnCopyPerms.addEventListener("click", async () => {
    const ok = await copyText(permsFull.textContent || "");
    setStatus(ok ? "ok" : "warn", ok ? "Copiado" : "No se pudo copiar");
  });

  // Logs modal
  btnOpenLogs.addEventListener("click", async () => {
    openModal(modalLogs);
    await loadLogs();
  });
  btnRefreshLogs.addEventListener("click", loadLogs);

  // Close modals on backdrop / close buttons
  document.body.addEventListener("click", (e) => {
    const t = e.target;
    if (!(t instanceof HTMLElement)) return;
    if (t.dataset && t.dataset.close === "1") {
      closeModal(modalPerms);
      closeModal(modalLogs);
    }
  });

  // Global unhandled rejection for “Failed to fetch”
  window.addEventListener("unhandledrejection", async (ev) => {
    dbg("PromiseRejection", { message: String(ev.reason && ev.reason.message ? ev.reason.message : ev.reason) });
    await healthzDebug();
  });

  // basic HTML escaping
  function escapeHtml(s) {
    return String(s || "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  // Init
  resetUi();
  updateSystemNotice();
})();
