document.addEventListener("DOMContentLoaded", function () {
    // Approve buttons
    const approveBtns = document.querySelectorAll(".approve-btn");
    approveBtns.forEach(btn => {
        btn.addEventListener("click", async function (e) {
            e.preventDefault();
            const userId = this.dataset.userid;
            try {
                const resp = await fetch(`/approve_user/${userId}`, {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "X-Requested-With": "XMLHttpRequest"
                    },
                });
                const data = await resp.json();
                if (data.success) {
                    const card = document.getElementById(`pending-${userId}`);
                    if (card) {
                        // Remove button container reliably
                        const buttonContainer = card.querySelector("div");
                        if (buttonContainer) buttonContainer.remove();

                        // Add status message
                        const status = document.createElement("p");
                        status.classList.add("shared-info");
                        status.style.color = "green";
                        status.style.fontWeight = "bold";
                        status.textContent = "Approved ✅";
                        card.appendChild(status);
                    }
                } else {
                    alert(data.error || "Error occurred while approving user.");
                }
            } catch (err) {
                console.error(err);
                alert("Error occurred while approving user.");
            }
        });
    });

    // Deny buttons
    const denyBtns = document.querySelectorAll(".deny-btn");
    denyBtns.forEach(btn => {
        btn.addEventListener("click", async function (e) {
            e.preventDefault();
            if (!confirm("Are you sure you want to deny this user?")) return;
            const userId = this.dataset.userid;
            try {
                const resp = await fetch(`/deny_user/${userId}`, {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "X-Requested-With": "XMLHttpRequest"
                    },
                });
                const data = await resp.json();
                if (data.success) {
                    const card = document.getElementById(`pending-${userId}`);
                    if (card) {
                        const buttonContainer = card.querySelector("div");
                        if (buttonContainer) buttonContainer.remove();

                        const status = document.createElement("p");
                        status.classList.add("shared-info");
                        status.style.color = "red";
                        status.style.fontWeight = "bold";
                        status.textContent = "Denied ❌";
                        card.appendChild(status);
                    }
                } else {
                    alert(data.error || "Error occurred while denying user.");
                }
            } catch (err) {
                console.error(err);
                alert("Error occurred while denying user.");
            }
        });
    });
});

// Delete version buttons
const deleteBtns = document.querySelectorAll(".delete-version");
deleteBtns.forEach(button => {
    button.addEventListener("click", async () => {
        const filename = button.dataset.filename;
        const version = button.dataset.version;

        if (!confirm(`Are you sure you want to delete version ${version} of ${filename}?`)) return;

        try {
            const res = await fetch(`/delete_version/${filename}/${version}`, {
                method: 'POST'
            });
            const data = await res.json();

            if (data.success) {
                alert(`Version ${version} of ${filename} deleted`);

                // Remove the version <li> from the DOM
                const versionLi = button.closest('li');
                if (versionLi) versionLi.remove();

                // Remove the file card if no versions left
                const versionList = button.closest('.versions-list');
                if (versionList && versionList.children.length === 0) {
                    versionList.closest('.file-card').remove();
                }
            } else {
                alert(`Error: ${data.error}`);
            }
        } catch (err) {
            console.error(err);
            alert("Error deleting version.");
        }
    });
});