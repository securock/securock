package sast_test

import "testing"

// These labels describe the actual source/rule pairs, including safe uses of
// the same APIs. Upstream challenge titles alone are not vulnerability labels.
// Each revision and every scanned file are pinned; upstream code is never run.

func TestDVNA(t *testing.T) {
	runApplicationBenchmark(t, "SECUROCK_DVNA", "9ba473add536f66ac9007966acb2a775dd31277a", []applicationProject{{
		inputs: []applicationInput{
			{"core/appHandler.js", "0fc237589d5a9e73450d089f97124fb943d68222f70df0e973a8b9acfe2ebb6b"},
			{"core/authHandler.js", "ceb187b1c60a30f46fc6bc89d8b0181a9d0b3fcad9b49e60fc13ed013be7bc5c"},
		},
		cases: []applicationCase{
			{"core/appHandler.js", "sast:js/sql-injection", 11, 13, true, true, false},
			{"core/appHandler.js", "sast:js/command-injection", 39, 44, true, true, false},
			{"core/appHandler.js", "sast:js/open-redirect", 188, 188, true, true, false},
			{"core/appHandler.js", "sast:js/code-injection", 197, 197, true, true, false},
			{"core/appHandler.js", "sast:js/insecure-deserialization", 218, 218, true, true, false},
			{"core/appHandler.js", "sast:js/xxe", 235, 235, true, true, false},
			{"core/authHandler.js", "sast:js/weak-crypto", 49, 49, true, true, false},
			{"core/authHandler.js", "sast:js/weak-crypto", 78, 78, true, true, false},
			{"core/appHandler.js", "sast:js/sql-injection", 59, 65, false, false, false},
			{"core/appHandler.js", "sast:js/sql-injection", 85, 89, false, false, false},
			{"core/appHandler.js", "sast:js/open-redirect", 122, 122, false, false, false},
			{"core/authHandler.js", "sast:js/open-redirect", 10, 16, false, false, false},
		},
	}})
}

func TestRailsGoat(t *testing.T) {
	runApplicationBenchmark(t, "SECUROCK_RAILSGOAT", "f5951f13089d85c979de09e7da3c8c0fb982f94a", []applicationProject{{
		inputs: []applicationInput{
			{"app/controllers/users_controller.rb", "2fd2eaf6580ec5917643b3ddcd4dc4ac0558604d4ee0a6415175422786505d52"},
			{"app/controllers/benefit_forms_controller.rb", "9d5807504795b89fbd5a52c3986d4ffab324bb4eda1cabe1a9bd21a576385cc8"},
			{"app/controllers/dashboard_controller.rb", "0e55894f81c7894ade6da34d316b66c70fede4573e7c2c228937bc2878c8c9f9"},
			{"app/controllers/api/v1/mobile_controller.rb", "7d508d8be13f7d4f467d6d91129a4e558161c0aa6dc59d6af3ba7c52c540692d"},
			{"app/controllers/password_resets_controller.rb", "349ef94a497850a580f762bb52f428fe0952489de523043b9279f3ea11e062f1"},
			{"app/controllers/sessions_controller.rb", "4e4bf095f3440718e1fe91c2a08baa925d7b4da7cc763a2d70e2c7aab133a4cd"},
			{"app/controllers/messages_controller.rb", "887e96da72f3182bccbed022c461892731f518eaef72b1de434a49d3acc6baa1"},
		},
		cases: []applicationCase{
			{"app/controllers/users_controller.rb", "sast:rb/sql-injection", 29, 29, true, true, false},
			{"app/controllers/users_controller.rb", "sast:rb/mass-assignment", 50, 50, true, true, false},
			{"app/controllers/benefit_forms_controller.rb", "sast:rb/code-injection", 12, 12, true, true, false},
			{"app/controllers/benefit_forms_controller.rb", "sast:rb/path-traversal", 13, 13, true, true, false},
			{"app/controllers/dashboard_controller.rb", "sast:rb/code-injection", 16, 16, true, true, false},
			{"app/controllers/api/v1/mobile_controller.rb", "sast:rb/code-injection", 10, 10, true, true, false},
			{"app/controllers/api/v1/mobile_controller.rb", "sast:rb/code-injection", 17, 17, true, true, false},
			{"app/controllers/password_resets_controller.rb", "sast:rb/insecure-deserialization", 6, 6, true, true, false},
			{"app/controllers/password_resets_controller.rb", "sast:rb/xss", 36, 36, true, true, false},
			{"app/controllers/password_resets_controller.rb", "sast:rb/weak-crypto", 48, 48, true, true, false},
			{"app/controllers/password_resets_controller.rb", "sast:rb/weak-crypto", 57, 57, true, true, false},
			{"app/controllers/sessions_controller.rb", "sast:rb/open-redirect", 26, 26, true, true, false},
			{"app/controllers/messages_controller.rb", "sast:rb/sql-injection", 11, 11, false, false, false},
			{"app/controllers/messages_controller.rb", "sast:rb/sql-injection", 15, 15, false, false, false},
			{"app/controllers/sessions_controller.rb", "sast:rb/open-redirect", 36, 36, false, false, false},
			{"app/controllers/benefit_forms_controller.rb", "sast:rb/open-redirect", 21, 21, false, false, false},
		},
	}})
}

func TestDVWAExtended(t *testing.T) {
	inputs := []applicationInput{
		{"vulnerabilities/xss_r/source/low.php", "fb3c6fd9937697d4473cb9a2a9267df44b7e8620b16a4189189e76455d351833"},
		{"vulnerabilities/xss_r/source/medium.php", "b2b44ca0f6dd017a5a81a3461668072e15b4481b0c5eebf6da42abcbc94830ad"},
		{"vulnerabilities/xss_r/source/high.php", "1df9d34ce72f26e3f9cdf4878a23094e194dbabda0d2091547702a51f2851612"},
		{"vulnerabilities/xss_r/source/impossible.php", "6cff3122f97aec856e57134f497cb79079929d7efa1aca3eb75748ea3cc28dd3"},
		{"vulnerabilities/sqli_blind/source/low.php", "28e34b5f7f4dd2ae1a38b1fae4c1bf67aaf3b98791c4a6c7560e322d1079f73a"},
		{"vulnerabilities/sqli_blind/source/medium.php", "6d2e04fab2e805f39629f6a8cc77e42671ebd13c0cba1bf3c00a9baa920efa4d"},
		{"vulnerabilities/sqli_blind/source/high.php", "35165a2b85a80880b566a4605d2b23af5eefa5fff12e5b13961789dc4fafdc82"},
		{"vulnerabilities/sqli_blind/source/impossible.php", "ccd72dcc781d921f3acbc02da2609018f2d604921a51e74d6b097624ddc18f83"},
	}
	// The SQLite queries use a global receiver with no type declaration in these
	// isolated fragments, so they are found through the modeled receiver names.
	cases := []applicationCase{
		{"vulnerabilities/xss_r/source/low.php", "sast:php/xss", 8, 8, true, true, false},
		{"vulnerabilities/xss_r/source/medium.php", "sast:php/xss", 11, 11, true, true, false},
		{"vulnerabilities/xss_r/source/high.php", "sast:php/xss", 11, 11, true, true, false},
		{"vulnerabilities/xss_r/source/impossible.php", "sast:php/xss", 12, 12, false, false, false},
		{"vulnerabilities/sqli_blind/source/low.php", "sast:php/sql-injection", 13, 13, true, true, false},
		{"vulnerabilities/sqli_blind/source/low.php", "sast:php/sql-injection", 34, 34, true, true, false},
		{"vulnerabilities/sqli_blind/source/medium.php", "sast:php/sql-injection", 15, 15, true, true, false},
		{"vulnerabilities/sqli_blind/source/medium.php", "sast:php/sql-injection", 36, 36, true, true, false},
		{"vulnerabilities/sqli_blind/source/high.php", "sast:php/sql-injection", 13, 13, true, true, false},
		{"vulnerabilities/sqli_blind/source/high.php", "sast:php/sql-injection", 35, 35, true, true, false},
		{"vulnerabilities/sqli_blind/source/impossible.php", "sast:php/sql-injection", 17, 19, false, false, false},
		{"vulnerabilities/sqli_blind/source/impossible.php", "sast:php/sql-injection", 26, 28, false, false, false},
	}
	projects, err := singleFileApplications(inputs, cases)
	if err != nil {
		t.Fatal(err)
	}
	runApplicationBenchmark(t, "SECUROCK_DVWA", "a1978a2fed195acd093010af6395f86a281537ca", projects)
}
