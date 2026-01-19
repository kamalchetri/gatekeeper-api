console.log("🛡️ VIGIL Shield Active (Capture Mode)");

document.addEventListener('paste', async (e) => {
  // 1. STOP EVERYTHING IMMEDIATELY
  e.preventDefault(); 
  e.stopPropagation();
  e.stopImmediatePropagation();

  const clipboardData = e.clipboardData || window.clipboardData;
  const pastedText = clipboardData.getData('text');

  if (!pastedText) return;

  chrome.storage.sync.get(['vigil_api_key'], async (result) => {
    if (!result.vigil_api_key) {
      alert("⚠️ VIGIL Setup Required: Please enter your API Key in the extension.");
      return;
    }

    try {
      // REPLACE WITH YOUR URL
      const response = await fetch('https://gatekeeper-api-20u0.onrender.com/v1/firewall', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${result.vigil_api_key}`
        },
        body: JSON.stringify({ prompt: pastedText, source: "Chrome Extension" })
      });

      if (response.status === 403 || response.status === 401) {
        alert("🚨 Authentication Failed: Please update your API Key.");
        return; 
      }

      const data = await response.json();

      if (data.status === 'ALLOWED') {
        document.execCommand('insertText', false, pastedText);
      } else {
        // --- NEW: DISPLAY THE COACHING TIP ---
        const tip = data.coaching_tip || "No tip available.";
        alert(`🚨 VIGIL BLOCKED THIS PASTE!\n\nReason: ${data.reason}\n\n💡 COACHING TIP:\n${tip}`);
      }

    } catch (err) {
      console.error("VIGIL Connection Error:", err);
      document.execCommand('insertText', false, pastedText); 
    }
  });
}, true);
