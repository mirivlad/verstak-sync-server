document.addEventListener("change", function (event) {
  if (event.target.matches("[data-auto-submit]")) event.target.form.requestSubmit();
});

let dialogOpener = null;
document.addEventListener("click", function (event) {
  const opener = event.target.closest("[data-dialog-open]");
  if (opener) {
    const dialog = document.getElementById(opener.dataset.dialogOpen);
    if (!dialog) return;
    dialogOpener = opener;
    dialog.showModal();
    return;
  }
  const closer = event.target.closest("[data-dialog-close]");
  if (closer) closer.closest("dialog")?.close();
});
document.addEventListener("close", function (event) {
  if (!event.target.matches(".management-dialog")) return;
  if (dialogOpener) dialogOpener.focus();
  dialogOpener = null;
}, true);

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

const oneTimeSecret = document.querySelector("[data-one-time-secret-url]");
if (oneTimeSecret) {
  fetch(oneTimeSecret.dataset.oneTimeSecretUrl, { method: "POST", credentials: "same-origin", headers: { "X-CSRF-Token": oneTimeSecret.dataset.csrfToken } })
    .then(async function (response) { if (!response.ok) throw new Error("one-time secret unavailable"); return response.json(); })
    .then(function (data) { oneTimeSecret.querySelector(".one-time-secret").textContent = data.password; })
    .catch(function () { oneTimeSecret.querySelector(".one-time-secret").textContent = "—"; });
}
