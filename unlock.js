// unlock.js -- shared decrypt/unlock logic for gated ARG stage pages.
// Crypto parameters must match build.py exactly (PBKDF2-HMAC-SHA256 -> AES-256-GCM).

(function () {
  const PBKDF2_ITERATIONS_FALLBACK = 250000; // used only if payload.iterations is missing
  const IV_LEN = 12; // bytes -- must match build.py

  const MIME_TYPES = {
    png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", gif: "image/gif",
    wav: "audio/wav", mp3: "audio/mpeg", ogg: "audio/ogg", mp4: "video/mp4",
  };

  function guessMime(path) {
    const clean = path.replace(/\.enc$/, "");
    const ext = clean.split(".").pop().toLowerCase();
    return MIME_TYPES[ext] || "application/octet-stream";
  }

  function normalize(answer) {
    // lowercase + strip whitespace -- must match normalize() in build.py
    return answer.trim().toLowerCase();
  }

  function b64ToBytes(b64) {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }

  async function deriveKey(password, salt, iterations) {
    const baseKey = await crypto.subtle.importKey(
      "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"]
    );
  }

  // Fetches <path>.enc (iv[12] || ciphertext+tag, written raw by build.py),
  // decrypts it with the page's already-derived key, and returns a Blob URL.
  async function decryptAsset(path) {
    const res = await fetch(path);
    const buf = new Uint8Array(await res.arrayBuffer());
    const iv = buf.slice(0, IV_LEN);
    const ciphertext = buf.slice(IV_LEN);
    const plainBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, window.ARG.key, ciphertext);
    return URL.createObjectURL(new Blob([plainBuf], { type: guessMime(path) }));
  }

  async function tryUnlock(rawAnswer, payload, errorEl) {
    try {
      const password = normalize(rawAnswer);
      const salt = b64ToBytes(payload.salt);
      const iv = b64ToBytes(payload.iv);
      const ciphertext = b64ToBytes(payload.ciphertext);
      const iterations = payload.iterations || PBKDF2_ITERATIONS_FALLBACK;

      const key = await deriveKey(password, salt, iterations);
      const plaintextBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
      const html = new TextDecoder().decode(plaintextBuf);

      // Same window survives document.open()/write()/close(), so anything
      // attached here is still reachable from the newly-written document's
      // own scripts -- lets a stage page fetch+decrypt its own binary assets
      // (images/audio) with the same key, without re-deriving from a password.
      window.ARG = { key, decryptAsset };

      // Full document replace so any <script> in the decrypted stage runs normally
      // (innerHTML would not execute embedded scripts).
      document.open();
      document.write(html);
      document.close();
      return true;
    } catch (e) {
      if (errorEl) errorEl.textContent = "Incorrect answer.";
      return false;
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    const dataEl = document.getElementById("stage-data");
    if (!dataEl) return;
    const payload = JSON.parse(dataEl.textContent);

    const form = document.getElementById("unlock-form");
    const input = document.getElementById("unlock-input");
    const errorEl = document.getElementById("unlock-error");

    // (b) URL fragment unlock, for QR codes: https://site/<hash>/#the-answer
    // location.hash is never sent to the server or written to access logs.
    if (location.hash.length > 1) {
      const fromHash = decodeURIComponent(location.hash.slice(1));
      tryUnlock(fromHash, payload, errorEl);
    }

    // (a) manual form unlock
    if (form) {
      form.addEventListener("submit", async (e) => {
        e.preventDefault();
        errorEl.textContent = "";
        await tryUnlock(input.value, payload, errorEl);
      });
    }
  });
})();
