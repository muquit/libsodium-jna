# Feb-02-2026
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

.PHONY: docs
docs:
	./scripts/mkdocs.sh

.PHONY: deptree
deptree:
	mvn dependency:tree
	gradle dependencies --configuration runtimeClasspath

.PHONY: gradle-clean
# stop Gradle daemon and clear caches (use when seeing build errors or 
# cache corruption)
gradle-clean:
	@echo "Stopping Gradle daemon and clearing caches..."
	gradle --stop
	/bin/rm -rf ~/.gradle/caches/
	@echo "Gradle fixed. 'make build_gradle' to rebuild should work now."
