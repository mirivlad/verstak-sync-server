document.addEventListener("change", function (event) {
  if (event.target.matches("[data-auto-submit]")) event.target.form.requestSubmit();
});

const confirmationDialog = document.getElementById("confirm-dialog");
let confirmationForm = null;
let confirmationButton = null;
document.addEventListener("click", function (event) {
  const button = event.target.closest("[data-confirm]");
  if (!button || !button.form || !confirmationDialog) return;
  event.preventDefault();
  confirmationForm = button.form;
  confirmationButton = button;
  document.getElementById("confirm-dialog-message").textContent = button.dataset.confirm;
  confirmationDialog.showModal();
});
if (confirmationDialog) {
  confirmationDialog.addEventListener("close", function () {
    if (confirmationDialog.returnValue === "confirm" && confirmationForm) {
      confirmationForm.requestSubmit(confirmationButton);
    }
    confirmationForm = null;
    confirmationButton = null;
  });
}

document.addEventListener("click", async function (event) {
  const button = event.target.closest("[data-copy-diagnostics]");
  if (!button || !navigator.clipboard) return;
  try {
    const response = await fetch(button.dataset.copyDiagnostics, { credentials: "same-origin" });
    if (!response.ok) return;
    await navigator.clipboard.writeText(await response.text());
    button.textContent = button.dataset.copiedLabel;
  } catch (_) {
    // The downloadable JSON link remains available when clipboard access is unavailable.
  }
});
