ERLANG_PATH = $(shell erl -eval 'io:format("~s", [lists:concat([code:root_dir(), "/erts-", erlang:system_info(version), "/include"])])' -s init stop -noshell)
OpenSSL_PATH = /usr/local/Cellar/openssl/1.0.2l/include

all:
	# compile nif
	gcc -I"$(ERLANG_PATH)" -I"$(OpenSSL_PATH)" \
			-lcrypto -fPIC -bundle -flat_namespace \
			-undefined suppress -m64 -arch x86_64 \
			-o priv/rsagen.so c_src/rsagen.c

clean:
	rm  -r "priv/nif.so"
