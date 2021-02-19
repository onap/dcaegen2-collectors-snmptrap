runtests:
	. ~/bin/set_proxies; tox tests | cat
	coverage html
