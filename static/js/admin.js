(() => {
  "use strict";

  const el = (id) => document.getElementById(id);

  const adminToken = el("adminToken");
  const adminMfa = el("adminMfa");
  const btnAdminVerify = el("btnAdminVerify");
  const btnAdminToggle = el("btnAdminToggle");
  const adminStatus = el("adminStatus");

  const adminLocked = el("adminLocked");
  const adminContent = el("adminContent");
  const usersCard = el("usersCard");

  const newUserName = el("newUserName");
  const btnCreateUser = el("btnCreateUser");
  const btnRefreshUsers = el("btnRefreshUsers");

  const userResult = el("userResult");
  const resultToken = el("resultToken");
  const resultSecret = el("resultSecret");
  const resultQr = el("resultQr");
  const resultOtpAuth = el("resultOtpAuth");

  const usersTbody = el("usersTbody");
  const systemNotice = el("systemNotice");

  let verified = false;

  async function apiFetch(url, opts = {}, timeoutMs = 20000) {
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
      const json = ct.includes("application/json") ? await res.json() : null;

      if (!res.ok || (json && json.ok === false)) {
        const msg = json?.error || `HTTP ${res.status}`;
        throw new Error(msg);
      }
      return json;
    } finally {
      clearTimeout(t);
    }
  }

  function getAdminPayload() {
    return {
      adminToken: (adminToken.value || "").trim(),
      adminCode: (adminMfa.value || "").trim(),
    };
  }

  function setStatus(msg, ok = true) {
    adminStatus.textContent = msg;
    adminStatus.style.color = ok ? "" : "var(--bad)";
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

  function setUnlocked(on) {
    verified = on;
    adminLocked.classList.toggle("hidden", on);
    adminContent.classList.toggle("hidden", !on);
    usersCard.classList.toggle("hidden", !on);
  }

  async function verifyAdmin() {
    const payload = getAdminPayload();
    if (!payload.adminToken || !payload.adminCode) {
      setStatus("Token y MFA requeridos.", false);
      return;
    }
    try {
      await apiFetch("/api/admin/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      setStatus("Acceso correcto. Gestión desbloqueada.");
      setUnlocked(true);
      await loadUsers();
    } catch (e) {
      setStatus(`Acceso denegado: ${e.message}`, false);
      setUnlocked(false);
    }
  }

  async function loadUsers() {
    if (!verified) return;
    usersTbody.innerHTML = "";
    try {
      const payload = getAdminPayload();
      const j = await apiFetch("/api/admin/users/list", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const users = Array.isArray(j.users) ? j.users : [];
      for (const user of users) {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td>${escapeHtml(user.name || "")}</td>
          <td>${escapeHtml(user.role || "")}</td>
          <td class="mono">${escapeHtml((user.createdAt || "").replace("T", " "))}</td>
          <td class="table-actions">
            ${user.role === "admin" ? "" : `<button class="btn btn-ghost" data-user-id="${escapeHtml(user.id)}">Borrar</button>`}
          </td>
        `;
        usersTbody.appendChild(tr);
      }
    } catch (e) {
      setStatus(`No se pudo cargar usuarios: ${e.message}`, false);
    }
  }

  async function createUser() {
    if (!verified) return;
    const name = (newUserName.value || "").trim();
    if (!name) {
      setStatus("Introduce un nombre de usuario.", false);
      return;
    }
    try {
      const payload = { ...getAdminPayload(), name };
      const j = await apiFetch("/api/admin/users/create", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      userResult.classList.remove("hidden");
      resultToken.textContent = j.token || "";
      resultSecret.textContent = j.secret || "";
      resultQr.src = j.qrDataUrl || "";
      resultOtpAuth.textContent = j.otpauth || "";

      newUserName.value = "";
      await loadUsers();
    } catch (e) {
      setStatus(`No se pudo crear usuario: ${e.message}`, false);
    }
  }

  usersTbody.addEventListener("click", async (e) => {
    const target = e.target;
    if (!(target instanceof HTMLElement)) return;
    const userId = target.dataset.userId;
    if (!userId) return;
    if (!confirm("¿Borrar este usuario?")) return;
    try {
      const payload = { ...getAdminPayload(), userId };
      await apiFetch("/api/admin/users/delete", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      await loadUsers();
    } catch (err) {
      setStatus(`No se pudo borrar: ${err.message}`, false);
    }
  });

  btnAdminVerify.addEventListener("click", verifyAdmin);
  btnCreateUser.addEventListener("click", createUser);
  btnRefreshUsers.addEventListener("click", loadUsers);

  btnAdminToggle.addEventListener("click", () => {
    const isPw = adminToken.getAttribute("type") === "password";
    adminToken.setAttribute("type", isPw ? "text" : "password");
  });

  function escapeHtml(s) {
    return String(s || "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  setUnlocked(false);
  updateSystemNotice();
})();
