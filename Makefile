# Feb-02-2026 
all: build

build:
	mvn clean install

test:
	mvn test

.PHONY: docs
docs:
	./scripts/mkdocs.sh

.PHONY: deptree
deptree:
	mvn dependency:tree
