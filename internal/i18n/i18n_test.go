package i18n

import (
	"regexp"
	"testing"
)

var verb = regexp.MustCompile(`%[-+# 0-9.]*[a-zA-Z]`)

// Every text exists in all languages with the same format verbs, so a
// translation can never break formatting.
func TestCatalogIsCompleteAndConsistent(t *testing.T) {
	for key, m := range catalog {
		want := verb.FindAllString(m.en, -1)
		for lang, text := range map[string]string{"en": m.en, "ru": m.ru, "fr": m.fr} {
			if text == "" {
				t.Errorf("%s: missing %s", key, lang)
				continue
			}
			got := verb.FindAllString(text, -1)
			if len(got) != len(want) {
				t.Errorf("%s/%s: verbs %v, want %v", key, lang, got, want)
				continue
			}
			for i := range got {
				if got[i] != want[i] {
					t.Errorf("%s/%s: verbs %v, want %v", key, lang, got, want)
					break
				}
			}
		}
	}
}

func TestNormalize(t *testing.T) {
	for in, want := range map[string]string{"2": "ru", "FR": "fr", "ru_RU.UTF-8": "ru", "en-US": "en", "de": "", "russian": "", "": ""} {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFallback(t *testing.T) {
	if T("de", "yes") != "yes" || T("ru", "yes") != "да" || T("fr", "missing-key") != "missing-key" {
		t.Fatal("fallback broken")
	}
}
