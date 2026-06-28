# Feb-02-2026

.PHONY: all build build_gradle build_maven test clean docs doc deptree gradle-clean

all: build

build:
	mvn clean install
	gradle clean build publishToMavenLocal

build_maven:
	mvn clean install

# run make gradle-clean in case of weidness about gradle
# e.g.
# make gradle-clean
# make build-gradle
build_gradle: 
	gradle clean build publishToMavenLocal

test:
	mvn clean test
	gradle clean test

docs:
	./scripts/mkdocs.sh

doc: docs

deptree:
	mvn dependency:tree
	gradle dependencies --configuration runtimeClasspath

# stop Gradle daemon and clear caches (use when seeing build errors or 
# cache corruption)
gradle-clean:
	@echo "Stopping Gradle daemon and clearing caches..."
	gradle --stop
	/bin/rm -rf ~/.gradle/caches/
	@echo "Gradle fixed. 'make build_gradle' to rebuild should work now."
