document.addEventListener("change", function (event) {
  if (event.target.matches("[data-auto-submit]")) event.target.form.requestSubmit();
});
document.addEventListener("click", function (event) {
  const button = event.target.closest("[data-confirm]");
  if (button && !window.confirm(button.dataset.confirm)) event.preventDefault();
});
