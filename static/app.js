// La recherche masque les lignes dont le nom ne correspond pas au texte saisi.
const search = document.getElementById("file-search");

if (search) {
  const rows = document.querySelectorAll("tr[data-name]");
  const noResults = document.getElementById("no-results");
  document.querySelector(".file-search").hidden = false;

  search.addEventListener("input", () => {
    const query = search.value.trim().toLocaleLowerCase("ru");
    let visible = 0;

    for (const row of rows) {
      row.hidden = !row.dataset.name.toLocaleLowerCase("ru").includes(query);
      if (!row.hidden) visible += 1;
    }

    noResults.hidden = visible > 0;
  });
}

// Выделяем ссылку целиком, чтобы её было удобно скопировать.
for (const input of document.querySelectorAll(".share-url")) {
  input.addEventListener("click", () => input.select());
}
