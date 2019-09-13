#!/bin/sh

find . -not -path "./node_modules/*" -name "*.md" | xargs ./node_modules/.bin/cspell || exit 1
find . -not -path "./node_modules/*" -name "*.md" -and -not -path "*/target/*" -name "*.md" | xargs ./node_modules/.bin/markdownlint --config .markdownlintrc || exit 1
