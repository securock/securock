package sast_test

import (
	"slices"
	"testing"
)

func TestPHPQuotedSQLEscaping(t *testing.T) {
	for _, tt := range []struct {
		name, body string
		want       []string
	}{
		{"unquoted escaped value", `$id = mysqli_real_escape_string($conn, $_POST['id']); $db->query("SELECT * FROM users WHERE id = $id");`, []string{"sast:php/sql-injection"}},
		{"single quoted interpolation", `$id = mysqli_real_escape_string($conn, $_POST['id']); $db->query("SELECT * FROM users WHERE id = '$id'");`, nil},
		{"single quoted concatenation", `$id = mysqli_real_escape_string($conn, $_POST['id']); $q = "SELECT * FROM users WHERE id = '" . $id . "'"; $db->query($q);`, nil},
		{"inline escape", `$db->query("SELECT * FROM users WHERE id = '" . mysqli_real_escape_string($conn, $_POST['id']) . "'");`, nil},
		{"legacy mysql escape", `$id = mysql_real_escape_string($_POST['id']); $db->query("SELECT * FROM users WHERE id = $id");`, []string{"sast:php/sql-injection"}},
		{"postgres escape", `$id = pg_escape_string($conn, $_POST['id']); $db->query("SELECT * FROM users WHERE id = $id");`, []string{"sast:php/sql-injection"}},
		{"mysqli method", `$id = $conn->real_escape_string($_POST['id']); $db->query("SELECT * FROM users WHERE id = $id");`, []string{"sast:php/sql-injection"}},
		{"quoted mysqli method", `$id = $conn->real_escape_string($_POST['id']); $db->query("SELECT * FROM users WHERE id = '$id'");`, nil},
		{"one unsafe substitution", `$id = mysqli_real_escape_string($conn, $_POST['id']); $db->query("SELECT * FROM users WHERE id = '$id' ORDER BY " . $_POST['sort']);`, []string{"sast:php/sql-injection"}},
		{"escaped identifier", `$id = mysqli_real_escape_string($conn, $_POST['id']); $db->query("SELECT * FROM users ORDER BY $id");`, []string{"sast:php/sql-injection"}},
		{"backtick identifier", "$id = mysqli_real_escape_string($conn, $_POST['id']); $db->query(\"SELECT `$id` FROM users\");", []string{"sast:php/sql-injection"}},
		{"reassigned escaped value", `$id = mysqli_real_escape_string($conn, $_POST['id']); $id = $_POST['other']; $db->query("SELECT * FROM users WHERE id = '$id'");`, []string{"sast:php/sql-injection"}},
		{"one unescaped branch", `$id = mysqli_real_escape_string($conn, $_POST['id']); if ($_POST['flag']) { $id = $_POST['other']; } $db->query("SELECT * FROM users WHERE id = '$id'");`, []string{"sast:php/sql-injection"}},
		{"both branches escaped", `if ($_POST['flag']) { $id = mysqli_real_escape_string($conn, $_POST['id']); } else { $id = mysqli_real_escape_string($conn, $_POST['other']); } $db->query("SELECT * FROM users WHERE id = '$id'");`, nil},
		{"query changed after construction", `$id = mysqli_real_escape_string($conn, $_POST['id']); $q = "SELECT * FROM users WHERE id = '$id'"; $q .= $_POST['tail']; $db->query($q);`, []string{"sast:php/sql-injection"}},
		{"unknown transform", `$id = mysqli_real_escape_string($conn, $_POST['id']); $q = "SELECT * FROM users WHERE id = '$id'"; $db->query(transform($q));`, []string{"sast:php/sql-injection"}},
		{"escaped query still not shell safe", `$id = mysqli_real_escape_string($conn, $_POST['id']); $q = "SELECT '$id'"; shell_exec($q);`, []string{"sast:php/command-injection"}},
		{"SQL comments stay conservative", `$id = mysqli_real_escape_string($conn, $_POST['id']); $db->query("SELECT 1 -- '$id'");`, []string{"sast:php/sql-injection"}},
		{"integer conversion", `$id = intval($_POST['id']); $db->query("SELECT * FROM users WHERE id = $id");`, nil},
		{"bound parameter", `$q = $db->prepare('SELECT * FROM users WHERE id = ?'); $q->execute([$_POST['id']]);`, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := slices.Compact(analyze(t, map[string]string{"a.php": "<?php\n" + tt.body + "\n"})); !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPHPSQLiteReceivers(t *testing.T) {
	for _, tt := range []struct {
		name, body string
		want       []string
	}{
		{"global sqlite connection", `global $sqlite_db_connection; $sqlite_db_connection->query("SELECT * FROM users WHERE id = '" . $_GET['id'] . "'");`, []string{"sast:php/sql-injection"}},
		{"SQLite3 object", `$sqlite = new SQLite3('app.db'); $sqlite->query("SELECT * FROM users WHERE id = " . $_POST['id']);`, []string{"sast:php/sql-injection"}},
		{"literal query", `$sqlite_db_connection->query("SELECT * FROM users");`, nil},
		{"integer conversion", `$id = intval($_GET['id']); $sqlite_db_connection->query("SELECT * FROM users WHERE id = $id");`, nil},
		{"bound parameter", `$q = $sqlite_db_connection->prepare('SELECT * FROM users WHERE id = :id'); $q->bindValue(':id', $_GET['id']); $q->execute();`, nil},
		{"unrelated receiver is not a database", `$cache->query($_GET['id']);`, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := slices.Compact(analyze(t, map[string]string{"a.php": "<?php\n" + tt.body + "\n"})); !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}
