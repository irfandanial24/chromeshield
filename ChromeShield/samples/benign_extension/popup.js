// Simple Notes - saves a note to local extension storage. Nothing risky here.

const textarea = document.getElementById("note");
const saveBtn = document.getElementById("save");

// Load any previously saved note when the popup opens.
chrome.storage.local.get("note", (data) => {
  if (data.note) {
    textarea.value = data.note;
  }
});

// Save the note when the button is clicked.
saveBtn.addEventListener("click", () => {
  chrome.storage.local.set({ note: textarea.value });
});
