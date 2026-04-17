document.addEventListener("DOMContentLoaded", () => {
    // Load all users for dropdown
    window.allUsers = JSON.parse(document.getElementById("share-data").dataset.users);

    const shareTypeSelect = document.getElementById("shareType");
    const userIdSelect = document.getElementById("user_id");

    // Populate dropdown based on type (user/guest)
    if (shareTypeSelect && userIdSelect) {
        shareTypeSelect.addEventListener("change", function() {
            const type = this.value;
            userIdSelect.innerHTML = '<option value="">-- Select --</option>';

            const filtered = window.allUsers.filter(u => (type === "user" ? u.role === "user" : u.role === "guest"));

            filtered.forEach(u => {
                const opt = document.createElement("option");
                opt.value = u.id;
                opt.text = u.username;
                userIdSelect.add(opt);
            });
        });
    }

    // Attach revoke button listeners
    document.querySelectorAll(".revoke-btn").forEach(btn => {
        btn.addEventListener("click", async function () {
            const userId = this.dataset.userid;
            const filename = this.dataset.filename;
            const username = this.dataset.username;

            if (!confirm(`Revoke access from ${username}?`)) return;

            try {
                const resp = await fetch(`/share/${filename}`, {   // Same route
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "X-Requested-With": "XMLHttpRequest"
                    },
                    body: JSON.stringify({ revoke_user_id: userId })
                });

                const data = await resp.json();
                if (data.success) {
                    // Remove this user from the UI
                    this.remove();
                    alert(`Access revoked from ${data.username}`);
                } else {
                    alert("Error revoking access: " + (data.error || "Unknown error"));
                }
            } catch (err) {
                console.error(err);
                alert("Error revoking access.");
            }
        });
    });
});