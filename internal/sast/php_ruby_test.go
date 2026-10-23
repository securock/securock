package sast_test

import (
	"slices"
	"testing"
)

func TestPHP(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []string
	}{
		{"mysqli concat", `<?php
$id = $_GET['id'];
mysqli_query($conn, "SELECT * FROM t WHERE id = " . $id);`, []string{"sast:php/sql-injection"}},
		{"interpolated string", `<?php
$r = mysqli_query($conn, "SELECT * FROM t WHERE id = {$_GET['id']}");`, []string{"sast:php/sql-injection"}},
		{"pdo query vs prepared", `<?php
function a($pdo) { return $pdo->query("SELECT * FROM t WHERE n = '" . $_POST['n'] . "'"); }`, []string{"sast:php/sql-injection"}},
		{"prepared statement is safe", `<?php
function a($pdo) { $s = $pdo->prepare("SELECT * FROM t WHERE n = ?"); $s->execute([$_POST['n']]); }`, nil},
		{"intval sanitizes", `<?php
$id = intval($_GET['id']);
mysqli_query($conn, "SELECT * FROM t WHERE id = " . $id);`, nil},
		{"cast sanitizes", `<?php
$id = (int)$_GET['id'];
mysqli_query($conn, "SELECT * FROM t WHERE id = $id");`, nil},
		{"system", `<?php
system("ping -c 1 " . $_GET['host']);`, []string{"sast:php/command-injection"}},
		{"escapeshellarg sanitizes", `<?php
system("ping -c 1 " . escapeshellarg($_GET['host']));`, nil},
		{"echo xss", `<?php
echo "<h1>" . $_GET['name'] . "</h1>";`, []string{"sast:php/xss"}},
		{"htmlspecialchars sanitizes", `<?php
echo "<h1>" . htmlspecialchars($_GET['name']) . "</h1>";`, nil},
		{"include", `<?php
include $_GET['page'] . ".php";`, []string{"sast:php/path-traversal"}},
		{"file_get_contents", `<?php
$d = file_get_contents("/srv/" . $_GET['f']);`, []string{"sast:php/path-traversal"}},
		{"eval and unserialize", `<?php
eval($_POST['code']);
$o = unserialize($_COOKIE['o']);`, []string{"sast:php/code-injection", "sast:php/insecure-deserialization"}},
		{"redirect header", `<?php
header("Location: " . $_GET['next']);`, []string{"sast:php/open-redirect"}},
		{"in_array guard", `<?php
$col = $_GET['sort'];
if (!in_array($col, ['a', 'b'])) { die('bad'); }
mysqli_query($conn, "SELECT * FROM t ORDER BY " . $col);`, nil},
		{"is_numeric guard", `<?php
$id = $_GET['id'];
if (!is_numeric($id)) { exit; }
mysqli_query($conn, "SELECT * FROM t WHERE id = " . $id);`, nil},
		{"method on an untyped receiver is found by its name", `<?php
class Repo {
  private $db;
  public function find($n) { return $this->db->query("SELECT '" . $n . "'"); }
}
class Ctl {
  public function get($repo) { return $repo->find($_GET['n']); }
}`, []string{"sast:php/sql-injection"}},
		{"across a function", `<?php
function find($pdo, $n) { return $pdo->query("SELECT '" . $n . "'"); }
find($pdo, $_GET['n']);`, []string{"sast:php/sql-injection"}},
		{"laravel request", `<?php
class C { public function index($request) { return DB::select("SELECT * FROM t WHERE n = '" . $request->input('n') . "'"); } }`, []string{"sast:php/sql-injection"}},
		{"plain function parameter is not a source", `<?php
function find($pdo, $n) { return $pdo->query("SELECT '" . $n . "'"); }`, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := slices.Compact(analyze(t, map[string]string{"index.php": tt.src}))
			if !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRuby(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []string
	}{
		{"where with interpolation", `
class UsersController < ApplicationController
  def show
    User.where("name = '#{params[:name]}'").first
  end
end`, []string{"sast:rb/sql-injection"}},
		{"where with hash is safe", `
class UsersController < ApplicationController
  def show
    User.where(name: params[:name]).first
  end
end`, nil},
		{"where with placeholder array is safe", `
class UsersController < ApplicationController
  def show
    User.where(["name = ?", params[:name]]).first
  end
end`, nil},
		{"connection execute", `
class C < ApplicationController
  def x
    id = params[:id]
    ActiveRecord::Base.connection.execute("SELECT #{id}")
  end
end`, []string{"sast:rb/sql-injection"}},
		{"system with one string", `
class C < ApplicationController
  def x
    system("ls #{params[:dir]}")
  end
end`, []string{"sast:rb/command-injection"}},
		{"system with separate arguments is safe", `
class C < ApplicationController
  def x
    system("ls", params[:dir])
  end
end`, nil},
		{"backticks", `
class C < ApplicationController
  def x
    out = ` + "`ls #{params[:dir]}`" + `
  end
end`, []string{"sast:rb/command-injection"}},
		{"file read", `
class C < ApplicationController
  def x
    File.read(params[:file])
  end
end`, []string{"sast:rb/path-traversal"}},
		{"basename sanitizes", `
class C < ApplicationController
  def x
    File.read(File.basename(params[:file]))
  end
end`, nil},
		{"to_i sanitizes", `
class C < ApplicationController
  def x
    User.where("id = #{params[:id].to_i}")
  end
end`, nil},
		{"redirect", `
class C < ApplicationController
  def x
    redirect_to params[:next]
  end
end`, []string{"sast:rb/open-redirect"}},
		{"html_safe", `
class C < ApplicationController
  def x
    render html: "<p>#{params[:name]}</p>".html_safe
  end
end`, []string{"sast:rb/xss"}},
		{"eval", `
class C < ApplicationController
  def x
    eval(params[:code])
  end
end`, []string{"sast:rb/code-injection"}},
		{"include guard", `
class C < ApplicationController
  ALLOWED = %w[a b]
  def x
    col = params[:sort]
    return unless ALLOWED.include?(col)
    User.order("#{col} asc")
  end
end`, nil},
		{"helper method", `
class C < ApplicationController
  def x
    find(params[:n])
  end
  def find(n)
    User.find_by_sql("SELECT * FROM u WHERE n = '#{n}'")
  end
end`, []string{"sast:rb/sql-injection"}},
		{"deserialization", `
class C < ApplicationController
  def x
    Marshal.load(params[:data])
  end
end`, []string{"sast:rb/insecure-deserialization"}},
		{"plain method parameter is not a source", `
class Repo
  def find(n)
    User.find_by_sql("SELECT * FROM u WHERE n = '#{n}'")
  end
end`, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := slices.Compact(analyze(t, map[string]string{"app.rb": tt.src}))
			if !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}
