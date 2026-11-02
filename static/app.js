"use strict";

// All mutations remain ordinary, CSRF-protected server forms.
const select = (selector, root = document) => root.querySelector(selector);
const selectAll = (selector, root = document) => [...root.querySelectorAll(selector)];
const mobileViewport = window.matchMedia("(max-width: 760px)");

function syncSidebar() {
  const sidebar = select(".sidebar");
  if (sidebar) sidebar.inert = mobileViewport.matches && !document.body.classList.contains("menu-open");
}
syncSidebar();

function closeMenu() {
  document.body.classList.remove("menu-open");
  const content = select(".workspace-content");
  if (content) content.inert = false;
  const scrim = select("[data-menu-close]");
  if (scrim) scrim.hidden = true;
  select("[data-menu]")?.setAttribute("aria-expanded", "false");
  syncSidebar();
}

select("[data-menu]")?.addEventListener("click", () => {
  const open = document.body.classList.toggle("menu-open");
  select("[data-menu-close]").hidden = !open;
  select("[data-menu]").setAttribute("aria-expanded", String(open));
  select(".workspace-content").inert = open;
  syncSidebar();
  if (open) select(".sidebar .brand").focus();
});
select("[data-menu-close]")?.addEventListener("click", closeMenu);
mobileViewport.addEventListener("change", closeMenu);
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && document.body.classList.contains("menu-open")) {
    closeMenu();
    select("[data-menu]")?.focus();
  }
});

selectAll("[data-dialog]").forEach((button) => {
  button.addEventListener("click", () => {
    closeMenu();
    document.getElementById(button.dataset.dialog)?.showModal();
  });
});
selectAll("[data-close]").forEach((button) => {
  button.addEventListener("click", () => button.closest("dialog").close());
});
selectAll("dialog").forEach((dialog) => {
  dialog.addEventListener("close", () => {
    if (mobileViewport.matches && document.activeElement?.closest(".sidebar")) select("[data-menu]")?.focus();
  });
  dialog.addEventListener("click", (event) => {
    if (event.target !== dialog) return;
    const bounds = dialog.getBoundingClientRect();
    if (event.clientX < bounds.left || event.clientX > bounds.right ||
        event.clientY < bounds.top || event.clientY > bounds.bottom) dialog.close();
  });
});
selectAll("[data-dismiss]").forEach((button) => {
  button.addEventListener("click", () => button.closest(".notice").remove());
});
selectAll("[data-password]").forEach((button) => {
  button.addEventListener("click", () => {
    const input = document.getElementById(button.dataset.password);
    const visible = input.type === "password";
    input.type = visible ? "text" : "password";
    button.setAttribute("aria-pressed", String(visible));
    button.setAttribute("aria-label", visible ? "Скрыть пароль" : "Показать пароль");
  });
});

const fileList = select("[data-file-list]");
if (fileList) {
  const entries = selectAll(".file-entry", fileList);
  const search = select("#file-search");
  const categoryNames = {folder: "Папки", document: "Документы", image: "Изображения", other: "Другие файлы"};
  let category = "";
  let descending = false;

  function filterFiles() {
    const query = search.value.trim().toLocaleLowerCase("ru");
    let visible = 0;
    entries.forEach((entry) => {
      entry.hidden = !(entry.dataset.name.toLocaleLowerCase("ru").includes(query) &&
        (!category || entry.dataset.kind === category));
      if (!entry.hidden) visible += 1;
    });
    const filtered = Boolean(query || category);
    select("[data-empty]").hidden = visible > 0;
    if (filtered) {
      select("[data-empty-title]").textContent = "Ничего не нашлось";
      select("[data-empty-description]").textContent = "Попробуйте другое название или сбросьте фильтры.";
    } else {
      select("[data-empty-title]").textContent = "Здесь начинается ваше облако";
      select("[data-empty-description]").textContent = "Загрузите первый файл или создайте папку. Всё важное будет под рукой.";
    }
    select("[data-empty-upload]").hidden = filtered;
    select("[data-result-count]").textContent = filtered ? `Найдено: ${visible} из ${entries.length}` : `Объектов: ${entries.length}`;
    select(".filter-status").hidden = !filtered;
    select("[data-filter-label]").textContent = [categoryNames[category], query ? `Поиск: «${search.value.trim()}»` : ""].filter(Boolean).join(" · ");
    selectAll("[data-category]").forEach((button) => button.setAttribute("aria-pressed", String(button.dataset.category === category)));
  }
  search.addEventListener("input", filterFiles);
  selectAll("[data-category]").forEach((button) => {
    button.addEventListener("click", () => {
      category = category === button.dataset.category ? "" : button.dataset.category;
      filterFiles();
    });
  });
  select("[data-clear-filter]").addEventListener("click", () => {
    category = "";
    search.value = "";
    filterFiles();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "/" && !event.ctrlKey && !event.metaKey && !event.altKey &&
        !event.target.closest("input, textarea, select, [contenteditable], dialog") && !select("dialog[open]")) {
      event.preventDefault();
      search.focus();
    }
  });

  function setView(view) {
    fileList.classList.toggle("is-grid", view === "grid");
    selectAll("[data-view]").forEach((button) => {
      button.classList.toggle("is-active", button.dataset.view === view);
      button.setAttribute("aria-pressed", String(button.dataset.view === view));
    });
  }
  try { setView(localStorage.getItem("cloud-file-view") === "grid" ? "grid" : "list"); } catch { /* Preferences are optional. */ }
  selectAll("[data-view]").forEach((button) => {
    button.addEventListener("click", () => {
      setView(button.dataset.view);
      try { localStorage.setItem("cloud-file-view", button.dataset.view); } catch { /* Storage can be disabled. */ }
    });
  });
  select("[data-sort]").addEventListener("click", (event) => {
    descending = !descending;
    [...entries].sort((a, b) => {
      const folderOrder = Number(b.dataset.kind === "folder") - Number(a.dataset.kind === "folder");
      return folderOrder || a.dataset.name.localeCompare(b.dataset.name, "ru", {numeric: true}) * (descending ? -1 : 1);
    }).forEach((entry) => fileList.appendChild(entry));
    event.currentTarget.setAttribute("aria-label", descending ? "Сортировка Я–А. Изменить на А–Я" : "Сортировка А–Я. Изменить на Я–А");
    event.currentTarget.querySelector("svg").style.transform = descending ? "rotate(180deg)" : "";
  });
  selectAll("[data-delete-path]").forEach((button) => {
    button.addEventListener("click", () => {
      select("[data-delete-value]").value = button.dataset.deletePath;
      select("[data-delete-label]").textContent = button.dataset.deleteName;
      select("#delete-dialog").showModal();
    });
  });
}

selectAll("[data-upload-form]").forEach((form) => {
  const input = select('input[type="file"]', form);
  const feedback = select(".upload-feedback", form);
  const submit = select("[data-upload-submit]", form);
  const maxMegabytes = Number(form.dataset.maxFile) / 1048576;
  function checkFile() {
    const file = input.files[0];
    const tooLarge = file && file.size > Number(form.dataset.maxFile);
    input.setCustomValidity(tooLarge ? `Файл слишком большой. Выберите файл до ${maxMegabytes} МБ.` : "");
    feedback.classList.toggle("is-error", Boolean(tooLarge));
    feedback.textContent = tooLarge ? `Файл слишком большой. Максимальный размер — ${maxMegabytes} МБ.` : file ? `${file.name} · ${(file.size / 1048576).toLocaleString("ru", {maximumFractionDigits: 2})} МБ` : "";
    if (form.classList.contains("dropzone")) submit.hidden = !file;
    submit.disabled = Boolean(tooLarge);
    return Boolean(file && !tooLarge);
  }
  input.addEventListener("change", checkFile);
  form.addEventListener("submit", (event) => {
    if (!checkFile()) { event.preventDefault(); return; }
    submit.disabled = true;
    submit.textContent = "Загружаем…";
    feedback.textContent = "Файл передаётся в ваше облако. Дождитесь завершения.";
  });
  if (!form.classList.contains("dropzone")) return;
  let dragDepth = 0;
  form.addEventListener("dragenter", (event) => {
    event.preventDefault();
    dragDepth += 1;
    form.classList.add("is-dragging");
  });
  form.addEventListener("dragover", (event) => event.preventDefault());
  form.addEventListener("dragleave", () => {
    dragDepth -= 1;
    if (dragDepth <= 0) form.classList.remove("is-dragging");
  });
  form.addEventListener("drop", (event) => {
    event.preventDefault();
    dragDepth = 0;
    form.classList.remove("is-dragging");
    const files = event.dataTransfer.files;
    const hasDirectory = [...event.dataTransfer.items].some((item) => item.webkitGetAsEntry?.()?.isDirectory);
    if (files.length !== 1 || hasDirectory) {
      input.value = "";
      submit.hidden = true;
      feedback.classList.add("is-error");
      feedback.textContent = "Перетащите один файл. Для папок используйте кнопку «Новая папка».";
      return;
    }
    input.files = files;
    checkFile();
  });
});

// Browsers may restore disabled controls when returning through history.
window.addEventListener("pageshow", (event) => {
  if (!event.persisted) return;
  selectAll("[data-upload-submit]").forEach((button) => {
    button.disabled = false;
    button.textContent = "Загрузить";
  });
  selectAll('[data-upload-form] input[type="file"]').forEach((input) => input.dispatchEvent(new Event("change")));
});
