SHELL := /bin/bash
.PHONY: all check lint test integration install uninstall demo list lab lab-audit lab-stop clean

all: check

check: lint test

lint:
	shellcheck -S warning nginx2root.sh install.sh tests/run.sh tests/integration.sh lab/run.sh lab/stop.sh lab/audit.sh lab/entrypoint.sh

test:
	bash tests/run.sh

integration:
	bash tests/integration.sh

lab:
	bash lab/run.sh

lab-audit:
	bash lab/audit.sh

lab-stop:
	bash lab/stop.sh

install:
	./install.sh

uninstall:
	./install.sh --uninstall

demo:
	./nginx2root.sh --dump tests/fixtures/insecure.conf --nginx-version 1.25.2 --no-live --no-color

list:
	./nginx2root.sh --list-checks

clean:
	rm -f /tmp/nginx-T.txt
	rm -rf lab/results
