package handler

import (
	"net/http"
	"os/exec"
)

// Vuln — намеренно уязвимый эндпоинт (command injection) для проверки DAST-гейта.
// Существует только чтобы у ZAP было что найти, в реальном сервисе такого быть не должно.
func (lh *LogHandler) Vuln(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	out, _ := exec.Command("sh", "-c", "echo "+cmd).Output()
	_, _ = w.Write(out)
}
