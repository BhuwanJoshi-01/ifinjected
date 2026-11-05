// ifinjected project page: the copy button.
// SPDX-License-Identifier: MIT
//
// The listing itself is static HTML, generated from the messy-laptop example by
// scripts/render_site.py; tests/unit/test_site.py keeps the two in step.

"use strict";

for (const button of document.querySelectorAll("button[data-copy]")) {
    const source = document.getElementById(button.dataset.copy);
    if (!source || !navigator.clipboard) {
        button.hidden = true;
        continue;
    }
    button.addEventListener("click", async () => {
        try {
            await navigator.clipboard.writeText(source.textContent.trim());
            button.textContent = "Copied";
        } catch {
            button.textContent = "Press Ctrl+C";
            window.getSelection().selectAllChildren(source);
        }
        setTimeout(() => { button.textContent = "Copy"; }, 2000);
    });
}
