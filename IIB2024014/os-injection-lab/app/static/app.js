"use strict";
const payload = "welcome.txt; printf 'OS_INJECTION_CONFIRMED\\n'";
const input = document.querySelector("#filename");
const message = document.querySelector("#request-message");
const runButton = document.querySelector("#run-button");
document.querySelector("#load-normal").addEventListener("click", () => {
  input.value = "welcome.txt";
  message.textContent = "Normal filename loaded. Both versions should return the same SHA-256 digest.";
  input.focus();
});
document.querySelector("#load-payload").addEventListener("click", () => {
  input.value = payload;
  message.textContent = "Payload loaded. The injected printf command only prints a harmless marker.";
  input.focus();
});
document.querySelector("#copy-input").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(input.value);
    message.textContent = "Input copied.";
  } catch {
    input.focus(); input.select();
    message.textContent = "Input selected. Press Ctrl+C (or Command+C) to copy.";
  }
});

async function request(mode, filename) {
  const response = await fetch(`/api/${mode}`, {
    method: "POST",
    headers: {"Content-Type": "application/json", "X-Lab-Request": "1"},
    body: JSON.stringify({filename}),
    signal: AbortSignal.timeout(8000),
  });
  const data = await response.json();
  if (!response.ok && response.status !== 422) throw new Error(data.error || "The request failed.");
  const status = document.querySelector(`#${mode}-status`);
  const output = document.querySelector(`#${mode}-output`);
  const injected = mode === "vulnerable" && data.stdout.includes("OS_INJECTION_CONFIRMED");
  status.textContent = `${response.status} · ${injected ? "INJECTION CONFIRMED" : data.status.toUpperCase()}`;
  status.classList.add("has-result");
  output.textContent = data.stdout || data.stderr || "(no output)";
  if (data.stdout && data.stderr) output.textContent += `\nSTDERR:\n${data.stderr}`;
  output.classList.toggle("has-marker", injected || data.status === "blocked");
  document.querySelector(`#${mode}-time`).textContent = `${data.elapsed_ms} ms`;
  document.querySelector(`#${mode}-execution`).textContent = data.execution;
  document.querySelector(`#${mode}-explanation`).textContent = data.explanation;
  return data;
}

document.querySelector("#lab-form").addEventListener("submit", async event => {
  event.preventDefault();
  const filename = input.value;
  runButton.disabled = true;
  message.textContent = "Sending the identical input to both server implementations…";
  try {
    // Sequential requests make a screen recording easy to explain.
    const vulnerable = await request("vulnerable", filename);
    const secure = await request("secure", filename);
    if (vulnerable.stdout.includes("OS_INJECTION_CONFIRMED") && secure.status === "blocked") {
      message.textContent = "Confirmed: the vulnerable route executed printf. The secured route rejected the identical payload without starting a process.";
    } else if (vulnerable.stdout === secure.stdout && secure.status === "accepted") {
      message.textContent = "Baseline verified: both versions returned the same checksum for the valid sample.";
    } else {
      message.textContent = "Comparison complete. Inspect both responses and the execution paths below.";
    }
  } catch (error) {
    message.textContent = `Request failed: ${error.message}. Check that the Docker lab is running.`;
  } finally {
    runButton.disabled = false;
  }
});
