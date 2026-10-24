package sast_test

import (
	"slices"
	"testing"
)

func TestPythonXPathLiteralContexts(t *testing.T) {
	for _, tt := range []struct {
		name, body string
		want       []string
	}{
		{"single quote guard", "if \"'\" in value:\n        return\n    tree.xpath(f\"/users/user[@id='{value}']\")", nil},
		{"double quote guard", "if '\"' in value:\n        return\n    tree.xpath('/users/user[@id=\"' + value + '\"]')", nil},
		{"single quote replacement", `tree.xpath(f"/users/user[@id='{value.replace(chr(39), '')}']")`, []string{"sast:py/xpath-injection"}},
		{"literal quote replacement", `tree.xpath(f"/users/user[@id='{value.replace('\'', '&apos;')}']")`, nil},
		{"guard does not protect raw xpath", "if \"'\" in value:\n        return\n    tree.xpath(value)", []string{"sast:py/xpath-injection"}},
		{"xpath comment is not a string literal", "if \"'\" in value:\n        return\n    tree.xpath(\"(: ' :) /users/user[@id=\" + value + ']')", []string{"sast:py/xpath-injection"}},
		{"guard does not protect opposite quotes", "if \"'\" in value:\n        return\n    tree.xpath('/users/user[@id=\"' + value + '\"]')", []string{"sast:py/xpath-injection"}},
		{"reassignment invalidates guard", "if \"'\" in value:\n        return\n    value = request.args['other']\n    tree.xpath(f\"/users/user[@id='{value}']\")", []string{"sast:py/xpath-injection"}},
		{"guard on transformed value does not validate original", "if \"'\" in value.replace(\"'\", ''):\n        return\n    tree.xpath(f\"/users/user[@id='{value}']\")", []string{"sast:py/xpath-injection"}},
		{"partial replacement", `tree.xpath(f"/users/user[@id='{value.replace('\'', '', 1)}']")`, []string{"sast:py/xpath-injection"}},
		{"safe local query", "if \"'\" in value:\n        return\n    query = \"/users/user[@id='\" + value + \"']\"\n    tree.xpath(query)", nil},
		{"safe query reused inside another quote", "if \"'\" in value:\n        return\n    query = \"/users/user[@id='\" + value + \"']\"\n    tree.xpath('/users/user[@id=\"' + query + '\"]')", []string{"sast:py/xpath-injection"}},
		{"unknown transformation", "if \"'\" in value:\n        return\n    query = f\"/users/user[@id='{value}']\"\n    tree.xpath(transform(query))", []string{"sast:py/xpath-injection"}},
		{"replacement can destroy query quoting", "if \"'\" in value:\n        return\n    query = f\"/users/user[@id='{value}']\"\n    tree.xpath(query.replace(\"'\", ''))", []string{"sast:py/xpath-injection"}},
		{"other injection classes remain", "if \"'\" in value:\n        return\n    query = f\"/users/user[@id='{value}']\"\n    db.execute(query)", []string{"sast:py/sql-injection"}},
		{"one unsafe branch", "if flag:\n        if \"'\" in value:\n            return\n        query = f\"/users/user[@id='{value}']\"\n    else:\n        query = value\n    tree.xpath(query)", []string{"sast:py/xpath-injection"}},
		{"format conversion stays conservative", "if \"'\" in value:\n        return\n    tree.xpath(f\"/users/user[@id='{value!r}']\")", []string{"sast:py/xpath-injection"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			src := "from flask import request\ndef route(tree, db, flag):\n    value = request.args['id']\n    " + tt.body + "\n"
			if got := analyze(t, map[string]string{"app.py": src}); !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}
