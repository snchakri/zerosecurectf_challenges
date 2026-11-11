(() => {
  const decodeBlob = (blob) =>
    blob
      .split(".")
      .map((value, index) => String.fromCharCode(Number(value) - (index + 5)))
      .join("");

  const params = new URLSearchParams(window.location.search);
  const view = params.get("view");
  const locked = document.getElementById("locked");
  const unlocked = document.getElementById("unlocked");
  const flag = document.getElementById("flag");

  if (view !== "release") {
    return;
  }

  locked.classList.add("hidden");
  unlocked.classList.remove("hidden");

  const pieces = [...document.querySelectorAll("[data-blob]")]
    .sort((a, b) => Number(a.dataset.order) - Number(b.dataset.order))
    .map((node) => decodeBlob(node.dataset.blob || ""));

  flag.textContent = pieces.join("");
})();
