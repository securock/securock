package sast_test

import (
	"slices"
	"testing"
)

func TestRubyNestedRequestModels(t *testing.T) {
	for _, tt := range []struct {
		name, src string
		want      []string
	}{
		{"nested SQL input", `class C < ApplicationController
 def show
 User.where("id = '#{params[:user][:id]}'")
 end
end`, []string{"sast:rb/sql-injection"}},
		{"nested bound input", `class C < ApplicationController
 def show
 User.where(id: params[:user][:id])
 end
end`, nil},
		{"shadowed request object", `class C < ApplicationController
 def show
 params = {user: {id: '1'}}
 User.where("id = '#{params[:user][:id]}'")
 end
end`, nil},
		{"unknown constructor and unrelated new", `class OtherController < ApplicationController
 def new
  'safe'
 end
end
class C < ApplicationController
 def download
  path = params[:name]
  file = params[:type].constantize.new(path)
  send_file file, disposition: "attachment"
 end
end`, []string{"sast:rb/code-injection", "sast:rb/path-traversal"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := slices.Compact(analyze(t, map[string]string{"app.rb": tt.src}))
			if !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}
