document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll(".delete-btn").forEach(btn => {
        btn.addEventListener("click", async function () {
            const userId = this.dataset.userid;
            if (!confirm("Are you sure you want to delete this user?")) return;

            try {
                const resp = await fetch(`/delete_user/${userId}`, {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "X-Requested-With": "XMLHttpRequest"
                    },
                });

                const data = await resp.json();
                if (data.success) {
                    this.parentElement.remove();  // remove <li> from UI
                    alert("User deleted successfully.");
                } else {
                    alert("Error deleting user: " + (data.error || "Unknown error"));
                }
            } catch (err) {
                console.error(err);
                alert("Error deleting user.");
            }
        });
    });
});