runtests:
	-[ -d /tmp/opt ] && find /tmp/opt -type d -exec chmod 755 {} +
	rm -rf /tmp/opt
	tox tests | cat
